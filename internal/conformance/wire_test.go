// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplayableProbe(t *testing.T) {
	for _, tc := range []struct {
		name, method, path string
		want               bool
	}{
		{"list", "GET", "", true},
		{"metadata", "GET", "/id", true},
		{"encrypt", "POST", "/id/encrypt", true},
		{"decrypt", "POST", "/id/decrypt", true},
		{"generate_data_key", "POST", "/id/generate-data-key", true},
		{"reencrypt", "POST", "/id/re-encrypt", true},
		{"create", "POST", "", false},
		{"rotate", "POST", "/id/rotate", false},
		{"disable", "POST", "/id/disable", false},
		{"enable", "POST", "/id/enable", false},
		{"schedule_deletion", "POST", "/id/schedule-deletion", false},
		{"cancel_deletion", "POST", "/id/cancel-deletion", false},
		{"replicate", "POST", "/id/replicate", false},
		{"unknown_post", "POST", "/id/unknown", false},
		{"unknown_method", "PUT", "/id/encrypt", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := replayableProbe(tc.method, tc.path); got != tc.want {
				t.Fatalf("replayableProbe = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestProbeResponseAttempts(t *testing.T) {
	for _, tc := range []struct {
		name, method, path string
		status, attempts   int
		stall              bool
	}{
		{"read", "GET", "/id", 200, 2, true},
		{"encrypt", "POST", "/id/encrypt", 200, 2, true},
		{"decrypt", "POST", "/id/decrypt", 200, 2, true},
		{"generate_data_key", "POST", "/id/generate-data-key", 400, 2, true},
		{"reencrypt", "POST", "/id/re-encrypt", 200, 2, true},
		{"state_change", "POST", "/id/rotate", 200, 1, true},
		{"complete_success", "GET", "/id", 200, 1, false},
		{"complete_refusal", "POST", "/id/encrypt", 400, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				first := calls.Add(1) == 1
				w.Header().Set("Content-Length", "2")
				w.WriteHeader(tc.status)
				if first && tc.stall {
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Error("flush fake response")
						return
					}
					<-r.Context().Done()
					return
				}
				if _, err := w.Write([]byte("{}")); err != nil {
					t.Error("write fake response")
				}
			}))
			defer server.Close()
			httpClient := server.Client()
			httpClient.Timeout = 250 * time.Millisecond
			c := Client{HTTP: httpClient, Endpoint: server.URL}
			got, err := c.probe(t.Context(), tc.method, tc.path, nil)
			if n := int(calls.Load()); n != tc.attempts {
				t.Fatalf("physical requests = %d, want %d (error %v)", n, tc.attempts, err)
			}
			if tc.stall && tc.attempts == 1 {
				if !responseMissing(err) || got.code != tc.status {
					t.Fatal("mutation probe did not report its incomplete answer")
				}
			} else if err != nil || got.code != tc.status || string(got.raw) != "{}" {
				t.Fatal("probe did not return the complete fake answer")
			}
		})
	}
}

type neverConnected struct {
	calls int
}

func (tr *neverConnected) RoundTrip(r *http.Request) (*http.Response, error) {
	tr.calls++
	if err := r.Body.Close(); err != nil {
		return nil, err
	}
	return nil, context.DeadlineExceeded
}

func TestMutationSecondReadbackPreventsReplay(t *testing.T) {
	tr := &neverConnected{}
	c := Client{HTTP: &http.Client{Transport: tr}, Endpoint: "https://example.invalid"}
	readbacks := 0
	applied := reply{Status: "enabled"}
	got, err := c.attemptMutation(t.Context(), "/id/enable", []byte("{}"), func(context.Context) (*reply, bool) {
		readbacks++
		if readbacks == 1 {
			return nil, true
		}
		return &applied, false
	})
	if tr.calls != 1 || readbacks != 2 || err != nil || got.readback != &applied {
		t.Fatalf("second readback must prevent replay: attempts=%d readbacks=%d error=%v", tr.calls, readbacks, err)
	}
}
