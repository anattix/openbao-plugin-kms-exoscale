// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
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

// rotationFaults maps a misreported rotation fact to the assertion that must
// reject it. Each fault touches only the key created by the probe.
var rotationFaults = map[string]string{
	"count_skipped":       "manual rotation did not increment material version and manual count once",
	"automatic_history":   "manual rotation missing from rotation history",
	"replica_unreadable":  "disposable replica did not become readable",
	"replica_stale":       "replica did not report the rotated material version and manual count",
	"limit_state":         "manual rotation limit changed the key state or counts",
	"replica_delete_type": "KMS problem type or title differs from the measurement",
	"created_version":     "new rotation key must have material version 1 and no manual rotations",
	"created_zone_mode":   "created key has unexpected zone mode, state or usage",
	"created_count":       "new rotation key must have material version 1 and no manual rotations",
	"replica_not_pending": "replica did not report pending deletion",
}

// TestRotationAssertionsRejectFaults runs the rotation probe against a fake
// that misreports one fact at a time. Each run must fail at the assertion that
// covers that fact, and the created key must still be scheduled for deletion.
func TestRotationAssertionsRejectFaults(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_ROTATION_FAULT_CHILD"
	if fault := os.Getenv(child); fault != "" {
		runRotationFault(t, fault)
		return
	}
	for fault, want := range rotationFaults {
		t.Run(fault, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestRotationAssertionsRejectFaults$")
			cmd.Env = append(os.Environ(), child+"="+fault)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte(want)) {
				t.Fatalf("rotation probe accepted fault %s", fault)
			}
			if !bytes.Contains(out, []byte("disposable_cleanup status=pending-deletion")) {
				t.Fatalf("fault %s left the created key without a deletion plan", fault)
			}
		})
	}
}

func runRotationFault(t *testing.T, fault string) {
	var mu sync.Mutex
	limitRefused, rotated, deleted := false, false, false
	cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		id, op, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v2/kms-key/"), "/")
		owned := kmsapi.ValidKeyID(id) && !strings.EqualFold(id, KeyID)
		read := r.Method == http.MethodGet && op == ""
		atReplica := r.Host == "api-"+ReplicaZone+".exoscale.com"
		if fault == "replica_delete_type" && owned && atReplica && op == "encrypt" {
			// Only the post-deletion probe encrypts at the replica.
			problem(w, http.StatusBadRequest, "#/kms-key/not-found", "Key not found", "requested key not found")
			return
		}
		if fault == "replica_unreadable" && owned && read && atReplica {
			problem(w, http.StatusBadRequest, "#/kms-key/not-found", "Key not found", "requested key not found")
			return
		}
		if owned && op == "rotate" {
			rotated = true
		}
		if owned && op == "schedule-deletion" && !atReplica {
			deleted = true
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		body := rec.Body.Bytes()
		if fault == "created_zone_mode" && probeOperation(r) == "create" && rec.Code == http.StatusOK {
			body = bytes.Replace(body, []byte(`"multi-zone":true`), []byte(`"multi-zone":false`), 1)
		}
		if owned && rec.Code == http.StatusOK {
			switch {
			case fault == "count_skipped" && read && !atReplica:
				body = bytes.Replace(body, []byte(`"manual-count":1}`), []byte(`"manual-count":2}`), 1)
			case fault == "created_version" && read && !atReplica && !rotated:
				body = bytes.Replace(body, []byte(`"version":1`), []byte(`"version":2`), 1)
			case fault == "created_count" && read && !atReplica && !rotated:
				// Misreport only the readbacks of the new key before any rotation.
				body = bytes.Replace(body, []byte(`"manual-count":0}`), []byte(`"manual-count":3}`), 1)
			case fault == "replica_not_pending" && read && atReplica && deleted:
				body = bytes.Replace(body, []byte(`"status":"pending-deletion"`), []byte(`"status":"enabled"`), 1)
			case fault == "automatic_history" && op == "list-key-rotations":
				body = bytes.ReplaceAll(body, []byte(`"automatic":false`), []byte(`"automatic":true`))
			case fault == "replica_stale" && read && atReplica:
				body = bytes.Replace(body, []byte(`"manual-count":1}`), []byte(`"manual-count":0}`), 1)
			case fault == "limit_state" && read && !atReplica && limitRefused:
				// Misreport only the readback that follows the refused rotation.
				limitRefused = false
				body = bytes.Replace(body, []byte(`"status":"enabled"`), []byte(`"status":"disabled"`), 1)
			}
		}
		if fault == "limit_state" && owned && op == "rotate" && rec.Code == http.StatusBadRequest {
			limitRefused = true
		}
		for name, values := range rec.Header() {
			w.Header()[name] = values
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(body) // The loopback test client reports a short write.
	})
	origin, replica := routedProbeClients(t, cfg, srv)
	probe := conformance.RotationProbe{Origin: origin, Replica: replica, ConfiguredKey: KeyID}
	switch fault {
	case "replica_unreadable", "replica_stale", "replica_delete_type", "replica_not_pending", "created_zone_mode":
		probe.ReplicaZone = ReplicaZone
	case "limit_state":
		probe.CheckLimit = true
	}
	t.Run("rotation", probe.Run)
}

// TestReplicaRefusalsNeedOnlyMeasuredFields supplies the measured HTTP
// status, type and title for each replica refusal, including after deletion.
func TestReplicaRefusalsNeedOnlyMeasuredFields(t *testing.T) {
	cfg, srv := start(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
		if r.Host != "api-"+ReplicaZone+".exoscale.com" || strings.Contains(r.URL.Path, "/"+KeyID+"/") {
			return false
		}
		var response struct {
			Type  string `json:"type"`
			Title string `json:"title"`
		}
		switch op {
		case "rotate", "schedule-deletion":
			response.Type = "#/kms-key/multi-zone/operation-not-allowed-on-a-replica"
			response.Title = "Operation not allowed on replica"
		case "encrypt":
			response.Type = "#/kms-key/key-disabled"
			response.Title = "Key is disabled"
		default:
			return false
		}
		wireJSON(w, http.StatusBadRequest, response)
		return true
	})
	origin, replica := routedProbeClients(t, cfg, srv)
	t.Run("rotation", (conformance.RotationProbe{Origin: origin, Replica: replica, ConfiguredKey: KeyID, ReplicaZone: ReplicaZone}).Run)
}
