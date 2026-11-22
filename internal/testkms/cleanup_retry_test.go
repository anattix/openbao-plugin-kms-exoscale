// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
)

// TestCleanupAfterFailedSchedule verifies distinct cleanup plans and the readbacks between them.
func TestCleanupAfterFailedSchedule(t *testing.T) {
	if mode := os.Getenv("EXOSCALEKMS_TEST_CLEANUP"); mode != "" {
		runFailedSchedule(t, mode)
		return
	}
	for _, mode := range []string{"unanswered", "incomplete", "refused", "cleanup_refused", "applied_before_refusal"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestCleanupAfterFailedSchedule$")
			cmd.Env = append(os.Environ(), "EXOSCALEKMS_TEST_CLEANUP="+mode)
			out, err := cmd.CombinedOutput()
			want := "KMS disposable_cleanup status=pending-deletion delay_days=8"
			if mode == "applied_before_refusal" {
				want = "KMS disposable_cleanup status=pending-deletion delay_days=7"
			} else if mode == "cleanup_refused" {
				want = "KMS disposable_cleanup status=pending-deletion delay_days=9"
			}
			firstPlan := bytes.Index(out, []byte("KMS disposable single_zone=true enabled=true first_cleanup_plan_days=7"))
			verified := bytes.Index(out, []byte(want))
			if firstPlan < 0 || (verified >= 0 && firstPlan >= verified) {
				t.Fatal("initial cleanup plan must be labeled and logged before the verified schedule")
			}
			if verified < 0 {
				t.Fatalf("cleanup did not report %q", want)
			}
			if err == nil || !bytes.Contains(out, []byte("--- FAIL: TestCleanupAfterFailedSchedule/pending_deletion")) {
				t.Fatal("the injected failure did not fail the lifecycle probe")
			}
			if bytes.Contains(out, []byte("cleanup request trace did not match")) {
				t.Fatal("cleanup request trace did not match the bounded readback policy")
			}
		})
	}
}

func runFailedSchedule(t *testing.T, mode string) {
	t.Helper()
	var trace probeTrace
	want := 2
	switch mode {
	case "applied_before_refusal":
		want = 1
	case "cleanup_refused":
		want = 3
	}
	t.Cleanup(func() {
		trace.mu.Lock()
		defer trace.mu.Unlock()
		scheduled, readBack := 0, false
		for _, call := range trace.calls {
			switch call {
			case "read-key":
				readBack = true
			case "schedule-seven", "schedule-eight", "schedule-nine":
				plans := []string{"schedule-seven", "schedule-eight", "schedule-nine"}
				if !readBack || scheduled >= len(plans) || call != plans[scheduled] {
					t.Error("cleanup request trace did not match: missing readback or replayed schedule")
				}
				scheduled++
				readBack = false
			}
		}
		if scheduled != want || !readBack {
			t.Error("cleanup request trace did not match: wrong attempt count or final readback missing")
		}
	})
	cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		op := probeOperation(r)
		if strings.Contains(r.URL.Path, "/"+KeyID+"/") && strings.HasPrefix(op, "schedule-") {
			t.Error("cleanup request trace did not match: configured key reached deletion route")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := trace.record(op)
		if op == "schedule-eight" && mode == "cleanup_refused" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if op == "schedule-seven" && n == 1 {
			switch mode {
			case "unanswered":
				closeUnanswered(t, w)
			case "incomplete":
				stallAfterHeaders(t, w, r, http.StatusOK)
			case "applied_before_refusal":
				next.ServeHTTP(httptest.NewRecorder(), r)
				w.WriteHeader(http.StatusServiceUnavailable)
			default:
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		next.ServeHTTP(w, r)
	})
	c := testProbeClient(t, cfg.APIKey, cfg.APISecret, srv)
	c.HTTP.Timeout = 300 * time.Millisecond
	conformance.Disposable(t, c, KeyID, ReplicaZone)
}

// A status line with no headers is an incomplete answer, even before
// net/http can parse the response and return an HTTP status code.
func TestStatusLineWithoutHeadersIsReplayed(t *testing.T) {
	var trace probeTrace
	resumed := make(chan struct{})
	cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		if probeOperation(r) != "encrypt" {
			next.ServeHTTP(w, r)
			return
		}
		switch trace.record("encrypt") {
		case 2:
			close(resumed)
			next.ServeHTTP(w, r)
			return
		case 1:
		default:
			next.ServeHTTP(w, r)
			return
		}
		conn, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error("hijack loopback request")
			return
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Error("close started loopback reply")
			}
		}()
		if _, err := buf.WriteString("HTTP/1.1 200 OK\r\n"); err != nil || buf.Flush() != nil {
			t.Error("send first response line")
			return
		}
		select {
		case <-resumed:
		case <-t.Context().Done():
		}
	})
	c := testProbeClient(t, cfg.APIKey, cfg.APISecret, srv)
	c.HTTP.Timeout = 300 * time.Millisecond
	conformance.Replica(t, c, c, KeyID)
	select {
	case <-resumed:
	default:
		t.Fatal("status line alone did not cause a replay")
	}
}
