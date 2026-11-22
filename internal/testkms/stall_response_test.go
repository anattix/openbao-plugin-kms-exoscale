// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
)

func stallAfterHeaders(t *testing.T, w http.ResponseWriter, r *http.Request, status int) {
	t.Helper()
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		t.Error("drain fake request before stalling response")
		return
	}
	// The service frames every measured answer as chunked, without Content-Length.
	w.WriteHeader(status)
	if err := http.NewResponseController(w).Flush(); err != nil {
		t.Error("flush fake response headers")
		return
	}
	select {
	case <-r.Context().Done():
	case <-time.After(3 * time.Second):
		t.Error("fake response was not canceled")
	}
}

// TestStalledResponseFraming checks the wire framing used by the KMS fixtures.
func TestStalledResponseFraming(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				stallAfterHeaders(t, w, r, status)
			}))
			t.Cleanup(server.Close)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal("prepare loopback request")
			}
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal("read loopback response headers")
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Error("close loopback response")
				}
			}()
			if resp.StatusCode != status || resp.ContentLength != -1 || !slices.Equal(resp.TransferEncoding, []string{"chunked"}) {
				t.Fatal("stalled response must send its status and chunked framing without Content-Length")
			}
		})
	}
}

// TestPayloadBoundUsesOnlyMeasuredSizes checks the probe's measured payloads.
func TestPayloadBoundUsesOnlyMeasuredSizes(t *testing.T) {
	var mu sync.Mutex
	var sizes []int
	cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		if probeOperation(r) == "encrypt" {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error("read fake payload probe")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer clear(raw)
			var in struct{ Plaintext []byte }
			if err := json.Unmarshal(raw, &in); err != nil {
				t.Error("decode fake payload probe")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer clear(in.Plaintext)
			if size := len(in.Plaintext); size >= 262144 {
				mu.Lock()
				sizes = append(sizes, size)
				mu.Unlock()
			}
			r.Body = io.NopCloser(bytes.NewReader(raw))
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
	conformance.Data(t, testProbeClient(t, cfg.APIKey, cfg.APISecret, srv), KeyID)
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(sizes, []int{262144, 393216, 524288, 786432}) {
		t.Fatalf("payload-bound sizes = %v", sizes)
	}
}
