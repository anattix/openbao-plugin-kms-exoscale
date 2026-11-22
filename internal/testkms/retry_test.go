// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
)

type probeTrace struct {
	mu    sync.Mutex
	calls []string
}

func (trace *probeTrace) record(op string) int {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.calls = append(trace.calls, op)
	count := 0
	for _, call := range trace.calls {
		if call == op {
			count++
		}
	}
	return count
}

func (trace *probeTrace) between(op, readback string) bool {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	start := slices.Index(trace.calls, op)
	if start == -1 {
		return false
	}
	end := slices.Index(trace.calls[start+1:], op)
	return end != -1 && slices.Contains(trace.calls[start+1:start+1+end], readback)
}

func closeUnanswered(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		t.Error("hijack loopback request")
		return
	}
	if err := conn.Close(); err != nil {
		t.Error("close loopback request")
	}
}

// truncateAfterHeaders ends an incomplete HTTP/1.1 response without a
// timer. Budget fixtures can then count interruptions independently of the
// time needed to serve valid responses.
func truncateAfterHeaders(t *testing.T, w http.ResponseWriter, r *http.Request, status int) {
	t.Helper()
	if _, err := io.Copy(io.Discard, r.Body); err != nil {
		t.Error("drain loopback request before truncating response")
		return
	}
	w.WriteHeader(status)
	if err := http.NewResponseController(w).Flush(); err != nil {
		t.Error("flush loopback response headers")
		return
	}
	closeUnanswered(t, w)
}

func testProbeClient(t *testing.T, cfgKey, cfgSecret string, srv *httptest.Server) conformance.Client {
	t.Helper()
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	t.Cleanup(transport.CloseIdleConnections)
	return conformance.Client{
		HTTP:     &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Endpoint: srv.URL + "/v2", APIKey: cfgKey, Secret: cfgSecret, Unanswered: conformance.TrackUnanswered(t),
	}
}

func probeOperation(r *http.Request) string {
	path := strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/kms-key"), "/")
	if len(path) == 1 {
		if r.Method == http.MethodGet {
			return "list"
		}
		return "create"
	}
	if r.Method == http.MethodGet {
		return "read-key"
	}
	if path[2] != "schedule-deletion" {
		return path[2]
	}
	var body struct {
		Days int `json:"delay-days"`
	}
	raw, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(raw, &body)
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err == nil && body.Days == 6 {
		return "schedule-six"
	}
	if err == nil && body.Days == 8 {
		return "schedule-eight"
	}
	if err == nil && body.Days == 9 {
		return "schedule-nine"
	}
	return "schedule-seven"
}

type dropBeforeConnection struct {
	next      http.RoundTripper
	trace     *probeTrace
	operation string
	missed    bool
}

func (d *dropBeforeConnection) RoundTrip(r *http.Request) (*http.Response, error) {
	if !d.missed && probeOperation(r) == d.operation {
		d.missed = true
		d.trace.record(d.operation)
		if r.Body != nil {
			if err := r.Body.Close(); err != nil {
				return nil, err
			}
		}
		return nil, context.DeadlineExceeded
	}
	return d.next.RoundTrip(r)
}

func TestMutationReadback(t *testing.T) {
	for _, tc := range []struct {
		operation, observe string
		canApply           bool
	}{
		{"create", "list", true},
		{"rotate", "read-key", true},
		{"disable", "read-key", true},
		{"enable", "read-key", true},
		{"schedule-six", "read-key", false},
		{"schedule-seven", "read-key", true},
		{"cancel-deletion", "read-key", true},
		{"replicate", "read-key", false},
	} {
		for _, applied := range []bool{false, true} {
			if applied && !tc.canApply {
				continue
			}
			mode := "missed"
			if applied {
				mode = "applied"
			}
			t.Run(tc.operation+"/"+mode, func(t *testing.T) {
				var trace probeTrace
				cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
					op := probeOperation(r)
					n := trace.record(op)
					if !applied || op != tc.operation || n != 1 {
						next.ServeHTTP(w, r)
						return
					}
					next.ServeHTTP(httptest.NewRecorder(), r)
					closeUnanswered(t, w)
				})
				c := testProbeClient(t, cfg.APIKey, cfg.APISecret, srv)
				if !applied {
					c.HTTP.Transport = &dropBeforeConnection{next: c.HTTP.Transport, trace: &trace, operation: tc.operation}
				}
				t.Cleanup(func() {
					trace.mu.Lock()
					calls := slices.Clone(trace.calls)
					trace.mu.Unlock()
					count := 0
					for _, op := range calls {
						if op == tc.operation {
							count++
						}
					}
					want := 2
					// A successful cancellation intentionally starts a new deletion
					// plan during cleanup, even when the first schedule was applied.
					if tc.operation == "schedule-seven" || tc.operation == "enable" {
						want++
					}
					if applied {
						want--
					}
					if count != want {
						t.Errorf("mutation attempts=%d, want %d", count, want)
					}
					if !applied && !trace.between(tc.operation, tc.observe) {
						t.Error("no state readback between unanswered mutation and replay")
					}
				})
				if tc.operation == "rotate" {
					(conformance.RotationProbe{Origin: c, ConfiguredKey: KeyID}).Run(t)
				} else {
					conformance.Disposable(t, c, KeyID, ReplicaZone)
				}
			})
		}
	}
}

// TestRotationReadbackAfterReplication requires the current origin snapshot
// before an unanswered rotate can be reconciled and resent.
func TestRotationReadbackAfterReplication(t *testing.T) {
	var trace probeTrace
	originHost := "api-" + Zone + ".exoscale.com"
	cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		if r.Host == originHost {
			trace.record(probeOperation(r))
		}
		next.ServeHTTP(w, r)
	})
	origin, replica := routedProbeClients(t, cfg, srv)
	client := *origin.HTTP
	client.Transport = &dropBeforeConnection{next: client.Transport, trace: &trace, operation: "rotate"}
	origin.HTTP = &client
	probe := conformance.RotationProbe{Origin: origin, Replica: replica, ConfiguredKey: KeyID, ReplicaZone: ReplicaZone}
	t.Run("rotation", probe.Run)

	between := trace.between("rotate", "read-key")
	trace.mu.Lock()
	defer trace.mu.Unlock()
	attempts := 0
	for _, op := range trace.calls {
		if op == "rotate" {
			attempts++
		}
	}
	if !between || attempts != 2 {
		t.Errorf("no origin state readback followed by one bounded resend (attempts=%d)", attempts)
	}
}

func TestUnansweredProbeBudget(t *testing.T) {
	if scenario := os.Getenv("EXOSCALEKMS_TEST_UNANSWERED"); scenario != "" {
		runUnansweredScenario(t, scenario)
		return
	}
	for _, tc := range []struct {
		scenario   string
		unanswered int
		incomplete int
		wantError  string
	}{
		{"recover", 1, 0, ""},
		{"at_limit", 4, 0, ""},
		{"over_limit", 3, 2, "KMS unanswered budget exceeded: count=5 limit=4"},
		{"no_answer_twice", 2, 0, "KMS request unanswered"},
		{"answered", 0, 0, "expected HTTP 200 with JSON (got HTTP 503)"},
		{"incomplete_twice", 0, 2, "KMS response incomplete (HTTP 200)"},
		{"incomplete_200", 0, 1, ""},
		{"incomplete_400", 0, 1, ""},
		{"incomplete_rotation_applied", 0, 1, ""},
		{"incomplete_rotation_unchanged", 0, 1, "unchanged readback cannot rule out a late effect"},
		{"ambiguous_mutation", 1, 0, "effect could not be determined"},
		{"connected_mutation", 1, 0, "unchanged readback cannot rule out a late effect"},
		{"answered_mutation", 0, 0, "expected HTTP 200 with JSON (got HTTP 503)"},
		{"lost_create", 1, 0, "effect could not be determined"},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestUnansweredProbeBudget$")
			cmd.Env = append(os.Environ(), "EXOSCALEKMS_TEST_UNANSWERED="+tc.scenario)
			out, err := cmd.CombinedOutput()
			var failed *exec.ExitError
			if (tc.wantError == "" && err != nil) || (tc.wantError != "" && (!errors.As(err, &failed) || !bytes.Contains(out, []byte(tc.wantError)))) {
				t.Fatalf("unexpected local subprocess result for %s: %s", tc.scenario, out)
			}
			if n := bytes.Count(out, []byte("KMS unanswered_requests count=")); n != tc.unanswered {
				t.Fatalf("stable unanswered lines=%d, want %d", n, tc.unanswered)
			}
			if n := bytes.Count(out, []byte("KMS incomplete_responses count=")); n != tc.incomplete {
				t.Fatalf("stable incomplete lines=%d, want %d", n, tc.incomplete)
			}
			if tc.scenario == "over_limit" &&
				(!bytes.Contains(out, []byte("KMS incomplete_responses count=4 limit=4")) ||
					!bytes.Contains(out, []byte("KMS unanswered_requests count=5 limit=4"))) {
				t.Fatal("unanswered and incomplete responses must share a counter")
			}
			if strings.HasPrefix(tc.scenario, "incomplete_rotation") &&
				bytes.Contains(out, []byte("rotation readback count differs")) {
				t.Fatal("incomplete rotation did not read back its effect")
			}
			if tc.scenario == "lost_create" && !bytes.Contains(out, []byte("KMS disposable_cleanup status=pending-deletion delay_days=7")) {
				t.Fatal("cleanup did not recover and schedule the lost create")
			}
			if bytes.Contains(out, []byte("unexpected replay count")) {
				t.Fatal("physical request count differs from the retry policy")
			}
		})
	}
}

func runUnansweredScenario(t *testing.T, scenario string) {
	t.Helper()
	var trace probeTrace
	var replayCount int
	cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		op := probeOperation(r)
		n := trace.record(op)
		switch {
		case scenario == "lost_create" && op == "create":
			next.ServeHTTP(httptest.NewRecorder(), r)
			closeUnanswered(t, w)
		case scenario == "lost_create" && op == "list" && n == 2:
			w.WriteHeader(http.StatusServiceUnavailable)
		case scenario == "answered_mutation" && op == "rotate":
			w.WriteHeader(http.StatusServiceUnavailable)
		case (scenario == "ambiguous_mutation" || scenario == "connected_mutation") && op == "rotate":
			closeUnanswered(t, w)
		case scenario == "ambiguous_mutation" && op == "read-key" && n > 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case scenario == "answered" && op == "encrypt":
			w.WriteHeader(http.StatusServiceUnavailable)
		case scenario == "incomplete_twice" && op == "encrypt",
			scenario == "incomplete_200" && op == "encrypt" && n == 1:
			truncateAfterHeaders(t, w, r, http.StatusOK)
		case scenario == "incomplete_400" && op == "generate-data-key" && n == 6:
			truncateAfterHeaders(t, w, r, http.StatusBadRequest)
		case scenario == "over_limit" && op == "encrypt" && (n == 3 || n == 7):
			truncateAfterHeaders(t, w, r, http.StatusOK)
		case strings.HasPrefix(scenario, "incomplete_rotation") && op == "rotate" && n == 1:
			if scenario == "incomplete_rotation_applied" {
				next.ServeHTTP(httptest.NewRecorder(), r)
			}
			truncateAfterHeaders(t, w, r, http.StatusOK)
		case op == "encrypt" && ((scenario == "recover" && n == 1) ||
			(scenario == "no_answer_twice" && n <= 2) ||
			(scenario == "at_limit" && n <= 7 && n%2 == 1) ||
			(scenario == "over_limit" && n <= 9 && n%2 == 1)):
			if scenario == "recover" {
				// Let the client's own deadline expire without an HTTP answer.
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error("drain loopback request")
				}
				select {
				case <-r.Context().Done():
				case <-time.After(3 * time.Second):
				}
			} else {
				closeUnanswered(t, w)
			}
		default:
			next.ServeHTTP(w, r)
		}
	})
	c := testProbeClient(t, cfg.APIKey, cfg.APISecret, srv)
	switch scenario {
	case "answered":
		replayCount = 1
	case "no_answer_twice", "incomplete_twice":
		replayCount = 2
	case "over_limit":
		replayCount = 9 // Encrypt attempts only, including the fifth interruption.
	}
	if replayCount != 0 {
		t.Cleanup(func() {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			encrypts := 0
			for _, op := range trace.calls {
				if op == "encrypt" {
					encrypts++
				}
			}
			if encrypts != replayCount {
				t.Error("unexpected replay count")
			}
		})
	}
	switch scenario {
	case "incomplete_400":
		conformance.Data(t, c, KeyID)
		return
	case "incomplete_rotation_applied", "incomplete_rotation_unchanged":
		checkOneMutation(t, &trace, "rotate")
		t.Cleanup(func() {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			start := slices.Index(trace.calls, "rotate") + 1
			if len(trace.calls) < start+2 || trace.calls[start] != "read-key" ||
				(scenario == "incomplete_rotation_unchanged" && trace.calls[start+1] != "read-key") {
				t.Error("rotation readback count differs")
			}
		})
		(conformance.RotationProbe{Origin: c, ConfiguredKey: KeyID}).Run(t)
		return
	case "ambiguous_mutation", "answered_mutation", "connected_mutation":
		checkOneMutation(t, &trace, "rotate")
		(conformance.RotationProbe{Origin: c, ConfiguredKey: KeyID}).Run(t)
		return
	case "lost_create":
		checkOneMutation(t, &trace, "create")
		conformance.Disposable(t, c, KeyID, ReplicaZone)
		return
	}
	for range 3 {
		conformance.Replica(t, c, c, KeyID)
	}
}

func checkOneMutation(t *testing.T, trace *probeTrace, operation string) {
	t.Helper()
	t.Cleanup(func() {
		trace.mu.Lock()
		defer trace.mu.Unlock()
		first := slices.Index(trace.calls, operation)
		if first < 0 || slices.Contains(trace.calls[first+1:], operation) {
			t.Error("unexpected replay count")
		}
	})
}
