// SPDX-License-Identifier: MPL-2.0

package kmsapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"
)

const maxResponse = 64 << 10

var errInvalidResponse = errors.New("invalid Exoscale KMS response")

// Client sends authenticated KMS requests to a single zone.
type Client struct {
	http                 *http.Client
	base, apiKey, secret string
	contextName          []byte
}

// StatusError reports the HTTP status without echoing the remote body.
type StatusError struct {
	Operation   string
	Code        int
	ProblemType string
}

// Error reports only the operation, HTTP status and an approved problem type.
func (e *StatusError) Error() string {
	return fmt.Sprintf("Exoscale KMS %s: HTTP %d (%s)", e.Operation, e.Code, SafeProblemType(e.ProblemType))
}

// New constructs a client with system TLS trust and an optional additional CA.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !ValidZone(cfg.Zone) || !apiKeyPattern.MatchString(cfg.APIKey) || cfg.APISecret == "" {
		return nil, errors.New("valid Exoscale zone, API key and secret are required")
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 10*time.Second {
		return nil, errors.New("invalid Exoscale KMS timeout")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.New("cannot load the system CA pool")
		}
		pem, err := readFile(ctx, cfg.CAFile, 1<<20)
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("cannot load additional CA certificates")
		}
		tlsConfig.RootCAs = roots
	}
	dial := cfg.DialContext
	if dial == nil {
		dial = (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext
	}
	transport := &http.Transport{
		DialContext:       dial,
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   30 * time.Second,
	}
	return &Client{
		http: &http.Client{
			Transport:     transport,
			Timeout:       cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		base:        "https://api-" + cfg.Zone + ".exoscale.com/v2/kms-key/",
		apiKey:      cfg.APIKey,
		secret:      cfg.APISecret,
		contextName: []byte(cfg.EncryptionContext),
	}, nil
}

type request struct {
	Plaintext         []byte `json:"plaintext,omitempty"`
	Ciphertext        []byte `json:"ciphertext,omitempty"`
	KeySpec           string `json:"key-spec,omitempty"`
	EncryptionContext []byte `json:"encryption-context,omitempty"`
}

type response struct {
	Plaintext  []byte `json:"plaintext"`
	Ciphertext []byte `json:"ciphertext"`
	Algorithm  string `json:"encryption-algorithm"`
}

// Encrypt wraps bytes for the raw API and OpenTofu IAM conformance tests.
// Neither production command calls it.
func (c *Client) Encrypt(ctx context.Context, id string, plaintext []byte) ([]byte, error) {
	out, err := c.crypto(ctx, id, "encrypt", request{Plaintext: plaintext})
	if err != nil {
		return nil, err
	}
	defer clear(out.Plaintext)
	if !validCiphertext(out.Ciphertext) {
		return nil, fmt.Errorf("encrypt: %w", errInvalidResponse)
	}
	return out.Ciphertext, nil
}

// Decrypt unwraps an opaque KMS ciphertext using id.
func (c *Client) Decrypt(ctx context.Context, id string, ciphertext []byte) ([]byte, error) {
	if !validCiphertext(ciphertext) {
		return nil, errors.New("invalid KMS ciphertext length")
	}
	out, err := c.crypto(ctx, id, "decrypt", request{Ciphertext: ciphertext})
	if err != nil {
		return nil, err
	}
	if len(out.Plaintext) == 0 {
		return nil, fmt.Errorf("decrypt: %w", errInvalidResponse)
	}
	return out.Plaintext, nil
}

// GenerateDataKey creates a fresh 32-byte data key and its KMS-wrapped form.
func (c *Client) GenerateDataKey(ctx context.Context, id string) (plaintext, ciphertext []byte, err error) {
	out, err := c.crypto(ctx, id, "generate-data-key", request{KeySpec: "AES-256"})
	if err != nil {
		return nil, nil, err
	}
	if len(out.Plaintext) != KeySize || !validCiphertext(out.Ciphertext) {
		clear(out.Plaintext)
		return nil, nil, fmt.Errorf("generate-data-key: %w", errInvalidResponse)
	}
	return out.Plaintext, out.Ciphertext, nil
}

func validCiphertext(data []byte) bool {
	return len(data) > 0 && len(data) <= MaxWrappedKey
}

func (c *Client) crypto(ctx context.Context, id, operation string, in request) (response, error) {
	var out response
	in.EncryptionContext = c.contextName
	body, err := json.Marshal(in)
	if err != nil {
		return out, errors.New("cannot encode KMS request")
	}
	defer clear(body)
	if err = c.post(ctx, id, operation, body, &out); err != nil {
		clear(out.Plaintext)
		return response{}, err
	}
	// The OpenAPI excerpt omits this field; the vendor Go client defines it.
	if out.Algorithm != "" && out.Algorithm != "AES_256" {
		clear(out.Plaintext)
		return response{}, fmt.Errorf("%s: %w", operation, errInvalidResponse)
	}
	return out, nil
}

func (c *Client) post(ctx context.Context, id, operation string, body []byte, out *response) error {
	if !ValidKeyID(id) {
		return errors.New("invalid KMS key UUID")
	}
	data, retry, err := c.attempt(ctx, id, operation, body)
	// A repeated data-plane operation can produce a fresh result but does not
	// mutate the wrapping key. Lifecycle operations always get one attempt.
	if err != nil && retry && retryable(operation) {
		timer := time.NewTimer(100 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return fmt.Errorf("Exoscale KMS %s: %w", operation, ctx.Err())
		case <-timer.C:
		}
		data, _, err = c.attempt(ctx, id, operation, body)
	}
	if err != nil {
		return err
	}
	defer clear(data)
	if json.Unmarshal(data, out) != nil {
		return fmt.Errorf("%s: %w", operation, errInvalidResponse)
	}
	return nil
}

func (c *Client) attempt(ctx context.Context, id, operation string, body []byte) ([]byte, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+id+"/"+operation, bytes.NewReader(body))
	if err != nil {
		return nil, false, errors.New("cannot create KMS request")
	}
	// A body without GetBody cannot be transparently replayed by net/http.
	req.GetBody = nil
	if len(body) != 0 {
		// The transport can finish reading and close asynchronously. It owns
		// this copy, while the caller can clear or retry using the original.
		raw := bytes.Clone(body)
		req.Body = &requestBody{raw: raw, reader: bytes.NewReader(raw)}
	}
	req.Header.Set("Content-Type", "application/json")
	sign(req, body, c.apiKey, c.secret, time.Now().Add(10*time.Minute))
	resp, err := c.http.Do(req)
	if err != nil {
		return classifyTransport(ctx, operation, err)
	}
	defer resp.Body.Close() // Response body is read below; Close adds no result data.
	if resp.StatusCode != http.StatusOK {
		return nil, transientStatus(resp.StatusCode), &StatusError{Operation: operation, Code: resp.StatusCode, ProblemType: problemDetails(resp.Body)}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil || len(data) > maxResponse {
		clear(data)
		if err != nil {
			// A body cut short is what a dropped connection looks like.
			return classifyTransport(ctx, operation, err)
		}
		return nil, false, fmt.Errorf("%s: %w", operation, errInvalidResponse)
	}
	return data, false, nil
}

func problemDetails(body io.Reader) string {
	const maxProblem = 4 << 10
	raw, err := io.ReadAll(io.LimitReader(body, maxProblem+1))
	defer clear(raw)
	var problem struct {
		Type string `json:"type"`
	}
	if err != nil || len(raw) > maxProblem || json.Unmarshal(raw, &problem) != nil {
		return SafeProblemType("")
	}
	return SafeProblemType(problem.Type)
}

// SafeProblemType returns a known KMS problem URI or a neutral label.
func SafeProblemType(problemType string) string {
	switch problemType {
	case "#/crypto/invalid-ciphertext", "#/kms-key/key-disabled",
		"#/kms-key/multi-zone/key-is-not-multi-zone", "#/kms-key/not-found",
		"#/http-problem-types/request-invalid-parameters",
		"#/kms-key/manual-rotation-limit",
		"#/kms-key/multi-zone/operation-not-allowed-on-a-replica":
		return problemType
	default:
		return "unclassified"
	}
}

func classifyTransport(ctx context.Context, operation string, cause error) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, fmt.Errorf("Exoscale KMS %s: %w", operation, err)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return nil, true, fmt.Errorf("Exoscale KMS %s: attempt timeout: %w", operation, context.DeadlineExceeded)
	}
	var dns *net.DNSError
	var verification *tls.CertificateVerificationError
	var netErr *net.OpError
	diagnostic, retry := "transport failed", false
	switch {
	case errors.As(cause, &dns):
		diagnostic, retry = "dns lookup failed", dns.IsTemporary || dns.IsTimeout
	case errors.As(cause, &verification):
		diagnostic = "tls verification failed"
	case errors.Is(cause, syscall.ECONNREFUSED):
		diagnostic, retry = "connection refused", true
	case errors.Is(cause, io.ErrUnexpectedEOF):
		diagnostic, retry = "truncated response", true
	case errors.As(cause, &netErr), errors.Is(cause, io.EOF), errors.Is(cause, syscall.ECONNRESET):
		retry = true
	}
	// Keep peer-controlled transport text out of the error chain.
	return nil, retry, fmt.Errorf("Exoscale KMS %s: %s", operation, diagnostic)
}

func retryable(operation string) bool {
	switch operation {
	case "encrypt", "decrypt", "generate-data-key":
		return true
	default:
		return false
	}
}

func transientStatus(status int) bool {
	switch status {
	case 408, 429, 500, 502, 503, 504:
		return true
	default:
		return false
	}
}

type requestBody struct {
	mu     sync.Mutex
	raw    []byte
	reader *bytes.Reader
}

func (b *requestBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reader.Read(p)
}

func (b *requestBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.raw)
	b.raw = nil
	b.reader.Reset(nil)
	return nil
}
