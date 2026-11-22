// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

// TestDisposableRotationContract checks every lifecycle write at both zone
// endpoints and the retained, usable version-11 key after the limit refusal.
func TestDisposableRotationContract(t *testing.T) {
	for _, tc := range []struct {
		name                                                                                              string
		zone                                                                                              string
		rotateOrigin, rotateReplica, scheduleReplica, replicate, reencrypt, limitEncrypts, originDecrypts int
	}{
		{"single_zone", "", 11, 0, 0, 0, 1, 3, 5},
		{"multi_zone", ReplicaZone, 1, 1, 1, 1, 1, 2, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type operation struct{ host, op string }
			var mu sync.Mutex
			counts := make(map[operation]int)
			created := ""
			cfg, srv := start(t, func(_ http.ResponseWriter, r *http.Request, op string) bool {
				if r.Method != http.MethodPost || op == "create" {
					return false
				}
				pre := "/v2/kms-key/"
				id, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, pre), "/")
				if !kmsapi.ValidKeyID(id) || strings.EqualFold(id, KeyID) {
					t.Error("probe sent an operation to the configured or invalid key")
				}
				mu.Lock()
				defer mu.Unlock()
				if created != "" && id != created {
					t.Error("rotation probe used more than one disposable key")
				}
				created = id
				counts[operation{r.Host, op}]++
				return false
			})
			origin, replica := routedProbeClients(t, cfg, srv)
			t.Run("rotation", func(t *testing.T) {
				(conformance.RotationProbe{Origin: origin, Replica: replica, ConfiguredKey: KeyID,
					ReplicaZone: tc.zone, CheckLimit: tc.zone == ""}).Run(t)
			})
			mu.Lock()
			defer mu.Unlock()
			originHost, replicaHost := "api-"+Zone+".exoscale.com", "api-"+ReplicaZone+".exoscale.com"
			for _, step := range []struct {
				at   operation
				want int
			}{
				{operation{originHost, "rotate"}, tc.rotateOrigin},
				{operation{replicaHost, "rotate"}, tc.rotateReplica},
				{operation{replicaHost, "schedule-deletion"}, tc.scheduleReplica},
				{operation{originHost, "replicate"}, tc.replicate},
				{operation{originHost, "schedule-deletion"}, 1},
				{operation{originHost, "cancel-deletion"}, 0},
				{operation{originHost, "re-encrypt"}, tc.reencrypt},
				{operation{originHost, "encrypt"}, tc.limitEncrypts},
				{operation{originHost, "decrypt"}, tc.originDecrypts},
				{operation{replicaHost, "decrypt"}, 2 * tc.replicate},
				{operation{replicaHost, "encrypt"}, tc.replicate},
			} {
				if got := counts[step.at]; got != step.want {
					t.Errorf("%s %s calls = %d, want %d", step.at.host, step.at.op, got, step.want)
				}
			}
		})
	}
}

// TestRotationSchedulesDeletionAfterFailure exercises cleanup after a fatal
// assertion on a key already created by the rotation probe.
func TestRotationSchedulesDeletionAfterFailure(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_ROTATION_CLEANUP_CHILD"
	if os.Getenv(child) == "1" {
		cfg, srv := start(t, nil)
		origin, replica := routedProbeClients(t, cfg, srv)
		(conformance.RotationProbe{Origin: origin, Replica: replica, ConfiguredKey: KeyID, ReplicaZone: ReplicaZone,
			BeforeSeal: func(t *testing.T, _ string, _ int) func(*testing.T, int) {
				t.Fatal("synthetic pre-rotation assertion failed")
				return nil
			}}).Run(t)
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestRotationSchedulesDeletionAfterFailure$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatal("the synthetic rotation failure must fail the probe")
	}
	for _, message := range []string{"synthetic pre-rotation assertion failed", "disposable_cleanup status=pending-deletion", "disposable_replica_cleanup status=pending-deletion encrypt=400"} {
		if !bytes.Contains(out, []byte(message)) {
			t.Errorf("expected cleanup evidence %q", message)
		}
	}
}

// TestRotationLimitLengthRejectsSkew requires the independent length check on
// the first ciphertext emitted after the manual limit has been reached.
func TestRotationLimitLengthRejectsSkew(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_LIMIT_LENGTH_CHILD"
	if os.Getenv(child) == "1" {
		var rotations int
		var mu sync.Mutex
		cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			op := probeOperation(r)
			if op == "rotate" {
				rotations++
			}
			if op == "encrypt" && rotations == 11 {
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r)
				var out struct{ Ciphertext []byte }
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Ciphertext) == 0 {
					t.Error("fake did not produce a post-limit ciphertext")
					return
				}
				payload := base64.StdEncoding.EncodeToString(append(out.Ciphertext, 0))
				wireJSON(w, http.StatusOK, struct{ Ciphertext string }{payload})
				return
			}
			next.ServeHTTP(w, r)
		})
		(conformance.RotationProbe{Origin: testProbeClient(t, cfg.APIKey, cfg.APISecret, srv), ConfiguredKey: KeyID, CheckLimit: true}).Run(t)
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestRotationLimitLengthRejectsSkew$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
		!bytes.Contains(out, []byte("rotation_limit_fresh: ciphertext overhead at material version 11 with 32 plaintext bytes: got 193, want 192")) {
		t.Fatal("post-limit probe did not independently reject the wrong length")
	}
}

// TestRotationRequiresExactRefusals supplies each refusal with the correct
// HTTP status and either an incorrect type with the measured title, or the
// measured type with an incorrect title, with no state change.
func TestRotationRequiresExactRefusals(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_ROTATION_REFUSAL_CHILD"
	if value := os.Getenv(child); value != "" {
		scenario, field, _ := strings.Cut(value, ":")
		answer := func(w http.ResponseWriter, typ, title string) {
			if field == "title" {
				title = "Unexpected title"
			} else {
				typ = "#/test/unexpected"
			}
			problem(w, http.StatusBadRequest, typ, title, "")
		}
		var mu sync.Mutex
		count := 0
		cfg, srv := start(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
			mu.Lock()
			defer mu.Unlock()
			atReplica := r.Host == "api-"+ReplicaZone+".exoscale.com"
			if atReplica && op == "encrypt" && scenario == "replica-cleanup" {
				answer(w, "#/kms-key/key-disabled", "Key is disabled")
				return true
			}
			if atReplica && op == scenario {
				answer(w, "#/kms-key/multi-zone/operation-not-allowed-on-a-replica", "Operation not allowed on replica")
				return true
			}
			if scenario == "manual-limit" && op == "rotate" {
				count++
				if count == 11 {
					answer(w, "#/kms-key/manual-rotation-limit", "Maximum rotation limit exceeded")
					return true
				}
			}
			return false
		})
		origin, replica := routedProbeClients(t, cfg, srv)
		probe := conformance.RotationProbe{Origin: origin, Replica: replica, ConfiguredKey: KeyID}
		if scenario == "manual-limit" {
			probe.CheckLimit = true
		} else {
			probe.ReplicaZone = ReplicaZone
		}
		probe.Run(t)
		return
	}
	for _, scenario := range []string{"manual-limit", "rotate", "schedule-deletion",
		"manual-limit:title", "rotate:title", "schedule-deletion:title", "replica-cleanup:title"} {
		t.Run(scenario, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestRotationRequiresExactRefusals$")
			cmd.Env = append(os.Environ(), child+"="+scenario)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
				!bytes.Contains(out, []byte("KMS problem type or title differs from the measurement")) {
				t.Fatal("rotation suite accepted a refusal with the wrong problem type or title")
			}
		})
	}
}
