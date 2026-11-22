// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestCleanupBounds checks that final cleanup reads back before choosing
// another action and limits each schedule plan and recovery transition.
func TestCleanupBounds(t *testing.T) {
	answeredPlans := []string{"read"}
	for day := minimumDeletionDelay; day <= maximumDeletionDelay; day++ {
		answeredPlans = append(answeredPlans, fmt.Sprintf("schedule-%d", day), "read")
	}
	for _, tc := range []struct {
		name, status string
		want         []string
	}{
		{"answered_plan_never_resent", "enabled", answeredPlans},
		{"enable_capped_at_two", "disabled", []string{"read", "enable", "read", "enable", "read"}},
		{"cancel_capped_at_two", "pending-deletion", []string{"read", "cancel-deletion", "read", "cancel-deletion", "read"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var calls []string
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				calls = append(calls, cleanupBoundsReply(t, w, r, tc.status))
				i := len(calls) - 1
				if i >= len(tc.want) || calls[i] != tc.want[i] {
					cancel()
				}
			}))
			defer server.Close()
			c := Client{HTTP: server.Client(), Endpoint: server.URL}
			if got := c.scheduleCleanup(ctx, "key"); got != 0 {
				t.Fatalf("cleanup reported %d days for a key that never showed a schedule", got)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(calls, tc.want) {
				t.Fatalf("cleanup sequence = %v, want %v", calls, tc.want)
			}
		})
	}
}

func cleanupBoundsReply(t *testing.T, w http.ResponseWriter, r *http.Request, status string) string {
	t.Helper()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/kms-key/key":
		if err := json.NewEncoder(w).Encode(reply{ID: "key", Status: status}); err != nil {
			t.Error("write fake key metadata")
		}
		return "read"
	case r.Method == http.MethodPost && r.URL.Path == "/kms-key/key/schedule-deletion":
		var plan struct {
			Days int `json:"delay-days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&plan); err != nil {
			t.Error("decode fake schedule request")
			w.WriteHeader(http.StatusBadRequest)
			return "invalid schedule"
		}
		// The reply completes, but the effect never appears in a readback.
		if _, err := w.Write([]byte(`{}`)); err != nil {
			t.Error("write fake schedule answer")
		}
		return fmt.Sprintf("schedule-%d", plan.Days)
	case r.Method == http.MethodPost && r.URL.Path == "/kms-key/key/enable":
		w.WriteHeader(http.StatusServiceUnavailable)
		return "enable"
	case r.Method == http.MethodPost && r.URL.Path == "/kms-key/key/cancel-deletion":
		w.WriteHeader(http.StatusServiceUnavailable)
		return "cancel-deletion"
	default:
		t.Error("unexpected cleanup request")
		w.WriteHeader(http.StatusBadRequest)
		return "unexpected request"
	}
}
