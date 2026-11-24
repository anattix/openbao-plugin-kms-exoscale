// SPDX-License-Identifier: MPL-2.0

// Package testkms supplies a loopback TLS implementation of the KMS wire contract.
package testkms

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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
	// ProxyHost is a non-resolving DNS name in the fake TLS certificate.
	ProxyHost = "kms-proxy.invalid"
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

// StartWithRotation runs a fake with an explicit HTTPS endpoint and a rotatable key.
func StartWithRotation(t *testing.T) (kmsapi.Config, string, func()) {
	t.Helper()
	cfg, srv := start(t, nil)
	cfg.KeyID = createRotationFixture(t, cfg, srv, false)
	return cfg, srv.URL + "/v2", func() { rotateFixtureKey(t, cfg, srv) }
}

func createRotationFixture(t *testing.T, cfg kmsapi.Config, srv *httptest.Server, multiZone bool) string {
	t.Helper()
	body := strings.NewReader(fmt.Sprintf(`{"name":"rotation-fixture","usage":"encrypt-decrypt","multi-zone":%t}`, multiZone))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v2/kms-key", body)
	if err != nil || egoscale.SignHTTPRequest(req, cfg.APIKey, cfg.APISecret, time.Now().Add(time.Minute)) != nil {
		t.Fatal("prepare fake key creation")
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal("send fake key creation")
	}
	defer resp.Body.Close() // The fake is local and closes at test cleanup.
	var meta keyMetadata
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&meta) != nil || !kmsapi.ValidKeyID(meta.ID) || meta.ID == cfg.KeyID {
		t.Fatal("create a separate fake rotation key")
	}
	return meta.ID
}

func rotateFixtureKey(t *testing.T, cfg kmsapi.Config, srv *httptest.Server) {
	t.Helper()
	rotationFixturePost(t, cfg, srv, "rotate", nil)
}

func replicateRotationFixture(t *testing.T, cfg kmsapi.Config, srv *httptest.Server) {
	t.Helper()
	rotationFixturePost(t, cfg, srv, "replicate", strings.NewReader(`{"zone":"`+ReplicaZone+`"}`))
}

func rotationFixturePost(t *testing.T, cfg kmsapi.Config, srv *httptest.Server, operation string, body io.Reader) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/v2/kms-key/"+cfg.KeyID+"/"+operation, body)
	if err != nil || egoscale.SignHTTPRequest(req, cfg.APIKey, cfg.APISecret, time.Now().Add(time.Minute)) != nil {
		t.Fatalf("prepare fake %s request", operation)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("send fake %s request", operation)
	}
	if err := resp.Body.Close(); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fake %s did not return HTTP 200 (status %d)", operation, resp.StatusCode)
	}
}

func start(t *testing.T, hook Hook) (kmsapi.Config, *httptest.Server) {
	t.Helper()
	return startWithResponseHook(t, hook, nil)
}

// StartWithOverheadSkew runs a fake whose ciphertexts stay valid but are extra
// bytes longer than the measured overhead, so that length assertions must fail.
func StartWithOverheadSkew(t *testing.T, extra int) (kmsapi.Config, string) {
	t.Helper()
	cfg, srv := startFake(t, nil, nil, extra)
	return cfg, srv.URL + "/v2"
}

func startWithResponseHook(t *testing.T, hook Hook, responseHook func(http.Handler, http.ResponseWriter, *http.Request)) (kmsapi.Config, *httptest.Server) {
	t.Helper()
	return startFake(t, hook, responseHook, 0)
}

func startFake(t *testing.T, hook Hook, responseHook func(http.Handler, http.ResponseWriter, *http.Request), extra int) (kmsapi.Config, *httptest.Server) {
	t.Helper()
	fake := server{hook: hook, extraPadding: extra, keys: map[string]*fakeKey{
		KeyID:      {status: "enabled", multiZone: true, version: 1, replica: ReplicaZone},
		OtherID:    {status: "enabled", version: 1},
		DisabledID: {status: "disabled", version: 1},
	}}
	handler := http.HandlerFunc(fake.handle)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if responseHook == nil {
			handler.ServeHTTP(w, r)
			return
		}
		responseHook(handler, w, r)
	}))
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
		SerialNumber: big.NewInt(1), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"api-" + Zone + ".exoscale.com", "api-" + ReplicaZone + ".exoscale.com", ProxyHost},
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

type server struct {
	hook Hook
	mu   sync.Mutex
	keys map[string]*fakeKey
	// extraPadding skews every ciphertext length; only negative tests set it.
	extraPadding int
}

func (s *server) handle(w http.ResponseWriter, r *http.Request) {
	path := strings.Split(r.URL.Path, "/")
	if len(path) < 3 || path[1] != "v2" || path[2] != "kms-key" {
		plainError(w, 400)
		return
	}
	id, op := "", ""
	switch {
	case len(path) == 3 && r.Method == http.MethodPost:
		op = "create"
	case len(path) == 3 && r.Method == http.MethodGet:
		op = "list"
	case len(path) == 4 && r.Method == http.MethodGet:
		id, op = path[3], "get"
	case len(path) == 5 && r.Method == http.MethodPost && path[4] != "":
		id, op = path[3], path[4]
	case len(path) == 5 && r.Method == http.MethodGet && path[4] == "list-key-rotations":
		id, op = path[3], path[4]
	default:
		plainError(w, 400)
		return
	}
	const limit = 2 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	defer clear(body)
	if err != nil || len(body) > limit {
		plainError(w, 400)
		return
	}
	if !validSignature(r, body, fixtureKey, fixtureSecret) {
		message := "Invalid key or request signature"
		if strings.Contains(r.Header.Get("Authorization"), "credential="+fixtureKey+",") {
			message = "Invalid request signature"
		}
		w.Header().Set("Content-Type", refusalJSON)
		wireJSON(w, http.StatusForbidden, struct {
			Message string `json:"message"`
		}{message})
		return
	}
	if s.hook != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		if s.hook(w, r, op) {
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "" && (op == "create" || op == "list") {
		s.collection(w, op, body)
		return
	}
	if !kmsapi.ValidKeyID(id) {
		type fieldError struct {
			Message string   `json:"message"`
			Path    string   `json:"path"`
			In      []string `json:"in"`
		}
		w.Header().Set("Content-Type", refusalJSON)
		wireJSON(w, 400, struct {
			Message string       `json:"message"`
			Errors  []fieldError `json:"errors"`
		}{"Invalid value `not-a-uuid` at 'id': should be a UUID", []fieldError{{"should be a UUID", "id", []string{"id"}}}})
		return
	}
	key := s.keys[id]
	atReplica := r.Host == "api-"+ReplicaZone+".exoscale.com"
	if key == nil || (atReplica && key.replica != ReplicaZone) {
		problem(w, 400, "#/kms-key/not-found", "Key not found", "requested key not found")
		return
	}
	switch op {
	case "encrypt", "decrypt", "generate-data-key", "re-encrypt":
		s.crypt(w, id, op, key, body)
	default:
		s.lifecycle(w, id, op, key, body, atReplica)
	}
}

func validSignature(r *http.Request, body []byte, key, secret string) bool {
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
	return egoscale.SignHTTPRequest(check, key, secret, exp) == nil &&
		hmac.Equal([]byte(actual), []byte(check.Header.Get("Authorization")))
}
