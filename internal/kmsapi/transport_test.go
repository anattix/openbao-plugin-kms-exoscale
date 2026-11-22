// SPDX-License-Identifier: MPL-2.0

package kmsapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

func TestTransportDiagnostics(t *testing.T) {
	server := testkms.Start(t, func(w http.ResponseWriter, r *http.Request, _ string) bool {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
		return true
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, diagnostic string
		adjust           func(*kmsapi.Config)
	}{
		{"closed loopback port", "connection refused", func(c *kmsapi.Config) {
			c.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, closed)
			}
		}},
		{"untrusted TLS", "tls verification failed", func(c *kmsapi.Config) { c.CAFile = "" }},
		{"unresolvable hostname", "dns lookup failed", func(c *kmsapi.Config) {
			c.DialContext = func(context.Context, string, string) (net.Conn, error) {
				return nil, &net.DNSError{Err: "untrusted peer text", Name: "fixture.invalid", IsNotFound: true}
			}
		}},
		{"attempt timed out", "attempt timeout: context deadline exceeded", func(c *kmsapi.Config) {
			c.Timeout = 100 * time.Millisecond
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := server
			tc.adjust(&cfg)
			c, err := kmsapi.New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Encrypt(t.Context(), cfg.KeyID, make([]byte, kmsapi.KeySize))
			if err == nil || err.Error() != "Exoscale KMS encrypt: "+tc.diagnostic {
				t.Fatalf("unexpected transport diagnostic: %v", err)
			}
		})
	}
}

func TestFakeRejectsUnknownDisabledAndBadSignature(t *testing.T) {
	for _, tc := range []struct {
		name, id  string
		badSecret bool
		want      int
		reason    string
	}{
		{"unknown", "44444444-4444-4444-8444-444444444444", false, http.StatusBadRequest, "#/kms-key/not-found"},
		{"disabled", testkms.DisabledID, false, http.StatusBadRequest, "#/kms-key/key-disabled"},
		{"wrong signature", testkms.KeyID, true, http.StatusForbidden, "unclassified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testkms.Start(t, nil)
			if tc.badSecret {
				cfg.APISecret += "-invalid"
			}
			c, err := kmsapi.New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Encrypt(t.Context(), tc.id, make([]byte, kmsapi.KeySize))
			var status *kmsapi.StatusError
			if !errors.As(err, &status) || status.Code != tc.want || status.ProblemType != tc.reason {
				t.Fatalf("unexpected safe status: %v", err)
			}
		})
	}
}

func TestLifecycleCallIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	cfg := testkms.Start(t, func(w http.ResponseWriter, _ *http.Request, op string) bool {
		if op == "rotate" {
			calls.Add(1)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	})
	c, err := kmsapi.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = kmsapi.ProbeLifecycle(t.Context(), c, cfg.KeyID, "rotate")
	if err == nil || !strings.HasSuffix(err.Error(), "HTTP 503 (unclassified)") || calls.Load() != 1 {
		t.Fatal("rotate must report failure after one attempt")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	for _, code := range []int{http.StatusFound, http.StatusSeeOther} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			var requests atomic.Int32
			cfg := testkms.Start(t, func(w http.ResponseWriter, _ *http.Request, op string) bool {
				if op == "generate-data-key" {
					requests.Add(1)
					w.Header().Set("Location", "/v2/kms-key/"+testkms.KeyID)
					w.WriteHeader(code)
					return true
				}
				requests.Add(1)
				return false
			})
			c, err := kmsapi.New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			plain, _, err := c.GenerateDataKey(t.Context(), cfg.KeyID)
			clear(plain)
			var status *kmsapi.StatusError
			if !errors.As(err, &status) || status.Code != code || requests.Load() != 1 {
				t.Fatal("provider followed a redirect instead of returning its HTTP status")
			}
		})
	}
}

func TestReplyGuards(t *testing.T) {
	for _, tc := range []struct {
		name      string
		algorithm string
		wrapped   int
	}{
		{"wrapped key above local limit", "AES_256", kmsapi.MaxWrappedKey + 1},
		{"unexpected response algorithm", "RSAES_OAEP_SHA_256", 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testkms.Start(t, func(w http.ResponseWriter, _ *http.Request, _ string) bool {
				_ = json.NewEncoder(w).Encode(struct {
					Plaintext  []byte `json:"plaintext"`
					Ciphertext []byte `json:"ciphertext"`
					Algorithm  string `json:"encryption-algorithm"`
				}{make([]byte, kmsapi.KeySize), make([]byte, tc.wrapped), tc.algorithm}) // Synthetic test data.
				return true
			})
			c, err := kmsapi.New(t.Context(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			plain, wrapped, err := c.GenerateDataKey(t.Context(), cfg.KeyID)
			clear(plain)
			if err == nil || plain != nil || wrapped != nil {
				t.Fatal("invalid generate-data-key answer yielded key material")
			}
		})
	}
}

func TestRemoteProblemTypeAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"known type", `{"type":"#/crypto/invalid-ciphertext","title":"untrusted marker","detail":"untrusted marker"}`, "#/crypto/invalid-ciphertext"},
		{"not found", `{"type":"#/kms-key/not-found","detail":"untrusted marker"}`, "#/kms-key/not-found"},
		{"manual rotation limit", `{"type":"#/kms-key/manual-rotation-limit","detail":"untrusted marker"}`, "#/kms-key/manual-rotation-limit"},
		{"replica operation", `{"type":"#/kms-key/multi-zone/operation-not-allowed-on-a-replica","title":"untrusted marker"}`, "#/kms-key/multi-zone/operation-not-allowed-on-a-replica"},
		{"invalid parameters", `{"type":"#/http-problem-types/request-invalid-parameters","detail":"untrusted marker"}`, "#/http-problem-types/request-invalid-parameters"},
		{"truncated type", `{"type":"#/http-problem-types/request-invalid-paramete"}`, "unclassified"},
		{"extra suffix", `{"type":"#/kms-key/not-found/untrusted"}`, "unclassified"},
		{"unknown type despite known title", `{"type":"untrusted marker","title":"Key is disabled","detail":"untrusted marker"}`, "unclassified"},
		{"non problem body", "untrusted marker", "unclassified"},
		{"oversized error", strings.Repeat("untrusted marker", 1024), "unclassified"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testkms.Start(t, func(w http.ResponseWriter, _ *http.Request, _ string) bool {
				http.Error(w, tc.body, http.StatusBadRequest)
				return true
			})
			c, err := kmsapi.New(t.Context(), cfg)
			if err != nil {
				t.Fatal("configure problem diagnostic test")
			}
			got, _, err := c.GenerateDataKey(t.Context(), cfg.KeyID)
			defer clear(got)
			var status *kmsapi.StatusError
			if !errors.As(err, &status) || status.ProblemType != tc.want ||
				err.Error() != "Exoscale KMS generate-data-key: HTTP 400 ("+tc.want+")" || len(got) != 0 {
				t.Fatal("error must contain only the HTTP status and approved type or neutral label")
			}
		})
	}
}
