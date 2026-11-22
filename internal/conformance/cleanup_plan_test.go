// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"
)

// TestCleanupScheduleRange checks bounded cleanup with a fresh read before each plan.
func TestCleanupScheduleRange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		applyLast bool
		want      int
	}{
		{name: "last plan is accepted", applyLast: true, want: 30},
		{name: "all plans are refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var requests []int
			after := reply{ID: "key", Status: "enabled"}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodGet {
					requests = append(requests, 0)
					if err := json.NewEncoder(w).Encode(after); err != nil {
						t.Error("write fake key metadata")
					}
					return
				}
				var plan struct {
					Days int `json:"delay-days"`
				}
				if r.URL.Path != "/kms-key/key/schedule-deletion" || json.NewDecoder(r.Body).Decode(&plan) != nil {
					t.Error("unexpected cleanup request")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				requests = append(requests, plan.Days)
				if tc.applyLast && plan.Days == 30 {
					deleteAt := time.Now().Add(30 * 24 * time.Hour)
					after.Status, after.DeleteAt = "pending-deletion", &deleteAt
					return
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			c := Client{HTTP: server.Client(), Endpoint: server.URL}
			if got := c.scheduleCleanup(ctx, "key"); got != tc.want {
				t.Errorf("verified schedule = %d days, want %d", got, tc.want)
			}
			mu.Lock()
			defer mu.Unlock()
			want := []int{0}
			for day := 7; day <= 30; day++ {
				want = append(want, day, 0)
			}
			if !slices.Equal(requests, want) {
				t.Fatalf("cleanup attempt and readback sequence = %v, want %v", requests, want)
			}
		})
	}
}
