// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestStatusLineIsIncompleteNotUnanswered checks the classification used by the retry counter.
func TestStatusLineIsIncompleteNotUnanswered(t *testing.T) {
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error("hijack fake response")
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Error("close fake response")
			}
		}()
		if _, err := buf.WriteString("HTTP/1.1 200 OK\r\n"); err != nil || buf.Flush() != nil {
			t.Error("write status line")
			return
		}
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	defer close(done)
	httpClient := server.Client()
	httpClient.Timeout = 250 * time.Millisecond
	u := &Unanswered{t: t}
	c := Client{HTTP: httpClient, Endpoint: server.URL, Unanswered: u}
	if _, err := c.call(t.Context(), http.MethodGet, "/id", nil); !errors.Is(err, errIncomplete) || errors.Is(err, errUnanswered) {
		t.Fatalf("status line alone must be reported as incomplete, got %v", err)
	}
	if n := u.count.Load(); n != 1 {
		t.Fatalf("interruptions counted = %d, want 1", n)
	}
}

// TestMutationReplayRespectsAllowance checks that the shared limit blocks a replay before connection.
func TestMutationReplayRespectsAllowance(t *testing.T) {
	tr := &neverConnected{}
	u := &Unanswered{t: t}
	u.count.Store(unansweredLimit)
	c := Client{HTTP: &http.Client{Transport: tr}, Endpoint: "https://example.invalid", Unanswered: u}
	_, err := c.attemptMutation(t.Context(), "/id/enable", nil, func(context.Context) (*reply, bool) { return nil, true })
	if tr.calls != 1 || err == nil {
		t.Fatalf("mutation replayed beyond the allowance: attempts=%d error=%v", tr.calls, err)
	}
}
