// SPDX-License-Identifier: MPL-2.0

// Package testkms supplies a loopback TLS implementation of the KMS wire contract.
package testkms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	egoscale "github.com/exoscale/egoscale/v3"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

const (
	// KeyID is the fake's primary key.
	KeyID = "11111111-1111-4111-8111-111111111111"
	// OtherID is a distinct usable key.
	OtherID = "22222222-2222-4222-8222-222222222222"
	// DisabledID is a key provisioned in the disabled state.
	DisabledID    = "33333333-3333-4333-8333-333333333333"
	fixtureKey    = "fixture-key"
	fixtureSecret = "fixture-only"
	// Zone is the logical hostname used by the fake.
	Zone = "ch-gva-2"
	// ReplicaZone is the second logical hostname routed to the same fake.
	ReplicaZone = "ch-dk-2"
)

// Hook can inject an HTTP failure before the fake processes an operation.
type Hook func(http.ResponseWriter, *http.Request, string) bool

// Start runs a KMS fake on loopback and returns client settings for the test.
func Start(t *testing.T, hook Hook) kmsapi.Config {
	t.Helper()
	cfg, _ := start(t, hook)
	return cfg
}

// StartEndpoint runs the same fake and returns its explicit HTTPS endpoint.
func StartEndpoint(t *testing.T, hook Hook) (kmsapi.Config, string) {
	t.Helper()
	cfg, srv := start(t, hook)
	return cfg, srv.URL + "/v2"
}

// StartWithRotation runs a fake whose active key can be rotated through its HTTPS route.
func StartWithRotation(t *testing.T) (kmsapi.Config, func()) {
	t.Helper()
	cfg, srv := start(t, nil)
	return cfg, func() {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v2/kms-key/"+cfg.KeyID+"/rotate", nil)
		if err != nil || egoscale.SignHTTPRequest(req, fixtureKey, fixtureSecret, time.Now().Add(time.Minute)) != nil {
			t.Fatal("prepare fake rotation request")
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal("send fake rotation request")
		}
		defer resp.Body.Close() // No response data used.
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("fake rotation HTTP %d", resp.StatusCode)
		}
	}
}

func start(t *testing.T, hook Hook) (kmsapi.Config, *httptest.Server) {
	t.Helper()
	fake := server{hook: hook, versions: make(map[string]uint32)}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(fake.handle))
	cert, certPEM := makeCert(t)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	caFile := filepath.Join(t.TempDir(), fmt.Sprintf("fake-%d.pem", port))
	if err := os.WriteFile(caFile, certPEM, 0600); err != nil {
		t.Fatal("write fake CA certificate")
	}
	cfg := kmsapi.Config{Zone: Zone, KeyID: KeyID, CAFile: caFile, Timeout: 3 * time.Second}
	return Connect(cfg), srv
}

// Connect sets synthetic credentials and dials the port encoded in the fake CA
// filename. The upstream plugin helper starts the child with a minimal environment.
func Connect(cfg kmsapi.Config) kmsapi.Config {
	cfg.APIKey = fixtureKey
	cfg.APISecret = fixtureSecret
	cfg.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		base := filepath.Base(cfg.CAFile)
		port, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(base, "fake-"), ".pem"))
		if err != nil || port <= 0 || port > 65535 || address != "api-"+cfg.Zone+".exoscale.com:443" {
			return nil, fmt.Errorf("unexpected fake KMS destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	return cfg
}

func makeCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate fake TLS key")
	}
	root := &x509.Certificate{
		SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"api-" + Zone + ".exoscale.com", "api-" + ReplicaZone + ".exoscale.com"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, root, root, pub, priv)
	if err != nil {
		t.Fatal("issue fake TLS certificate")
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type message struct {
	Plaintext  []byte `json:"plaintext,omitempty"`
	Ciphertext []byte `json:"ciphertext,omitempty"`
	KeySpec    string `json:"key-spec,omitempty"`
}

type server struct {
	hook     Hook
	mu       sync.Mutex
	versions map[string]uint32
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.Split(r.URL.Path, "/")
	if len(path) < 4 || path[1] != "v2" || path[2] != "kms-key" {
		problem(w, http.StatusBadRequest, "Invalid Request")
		return
	}
	id, op := path[3], "get"
	switch {
	case len(path) == 4 && r.Method == http.MethodGet:
	case len(path) == 5 && r.Method == http.MethodPost:
		op = path[4]
	default:
		problem(w, http.StatusBadRequest, "Invalid Request")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	defer clear(body)
	if err != nil || len(body) > 64<<10 {
		problem(w, http.StatusBadRequest, "Invalid Request")
		return
	}
	if !validSignature(r, body) {
		problem(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	if s.hook != nil && s.hook(w, r, op) {
		return
	}
	if id == DisabledID && op != "get" {
		problem(w, http.StatusBadRequest, "Key is Disabled")
		return
	}
	if id != KeyID && id != OtherID && id != DisabledID {
		problem(w, http.StatusBadRequest, "Key Not Found")
		return
	}
	if op == "get" {
		status := "enabled"
		if id == DisabledID {
			status = "disabled"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		}{id, status}) // The only write error is a disconnected test client.
		return
	}
	s.mu.Lock()
	if op == "rotate" {
		s.versions[id]++
	}
	version := s.versions[id]
	s.mu.Unlock()
	if op == "rotate" {
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, `{"rotation":{}}`); err != nil {
			return // The client disconnected.
		}
		return
	}
	var in message
	if json.Unmarshal(body, &in) != nil {
		clear(in.Plaintext)
		problem(w, http.StatusBadRequest, "Invalid Request")
		return
	}
	out, err := crypt(id, version, op, in)
	if err != nil {
		problem(w, http.StatusBadRequest, "Invalid Request")
		return
	}
	defer clear(out.Plaintext)
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		return // The client disconnected.
	}
}

func validSignature(r *http.Request, body []byte) bool {
	actual := r.Header.Get("Authorization")
	_, suffix, ok := strings.Cut(actual, ",expires=")
	value, _, complete := strings.Cut(suffix, ",")
	seconds, err := strconv.ParseInt(value, 10, 64)
	now := time.Now()
	exp := time.Unix(seconds, 0)
	if !ok || !complete || err != nil || exp.Before(now) || exp.After(now.Add(10*time.Minute)) {
		return false
	}
	check := r.Clone(r.Context())
	check.Body = io.NopCloser(bytes.NewReader(body))
	return egoscale.SignHTTPRequest(check, fixtureKey, fixtureSecret, exp) == nil &&
		hmac.Equal([]byte(actual), []byte(check.Header.Get("Authorization")))
}

func problem(w http.ResponseWriter, status int, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
	}{"about:blank", title, status}); err != nil {
		return // The client disconnected.
	}
}

func crypt(id string, version uint32, op string, in message) (message, error) {
	defer clear(in.Plaintext)
	if op == "decrypt" {
		if len(in.Ciphertext) <= 4 || binary.BigEndian.Uint32(in.Ciphertext) > version {
			return message{}, fmt.Errorf("unknown key version")
		}
		version = binary.BigEndian.Uint32(in.Ciphertext)
	}
	k := sha256.Sum256([]byte(fmt.Sprintf("test-only/%s/%d", id, version)))
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return message{}, err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return message{}, err
	}
	prefix := binary.BigEndian.AppendUint32(nil, version)
	switch {
	case op == "encrypt" && len(in.Plaintext) > 0:
		return message{Ciphertext: gcm.Seal(prefix, nil, in.Plaintext, nil)}, nil
	case op == "decrypt":
		raw, err := gcm.Open(nil, nil, in.Ciphertext[4:], nil)
		return message{Plaintext: raw}, err
	case op == "generate-data-key" && in.KeySpec == "AES-256":
		raw := make([]byte, kmsapi.KeySize)
		if _, err := rand.Read(raw); err != nil {
			return message{}, err
		}
		return message{Plaintext: raw, Ciphertext: gcm.Seal(prefix, nil, raw, nil)}, nil
	default:
		return message{}, fmt.Errorf("invalid KMS operation request")
	}
}
