// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
)

// TestRefusedLifecycleStillSchedulesDeletion checks that final cleanup recovers from lifecycle refusals.
func TestRefusedLifecycleStillSchedulesDeletion(t *testing.T) {
	if mode := os.Getenv("EXOSCALEKMS_TEST_LIFECYCLE_REFUSAL"); mode != "" {
		var mu sync.Mutex
		seen := map[string]int{}
		cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
			op := probeOperation(r)
			if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/"+KeyID+"/") && op != "encrypt" && op != "decrypt" && op != "re-encrypt" {
				t.Log("lifecycle request reached the configured key")
			}
			mu.Lock()
			seen[op]++
			n := seen[op]
			mu.Unlock()
			refuse := (mode == "enable" && op == "enable" && n == 1) ||
				(mode == "cleanup_schedule" && (op == "schedule-seven" || op == "schedule-eight") && n == 1)
			if refuse {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
		conformance.Disposable(t, testProbeClient(t, cfg.APIKey, cfg.APISecret, srv), KeyID, ReplicaZone)
		return
	}
	for _, mode := range []string{"enable", "cleanup_schedule"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestRefusedLifecycleStillSchedulesDeletion$")
			cmd.Env = append(os.Environ(), "EXOSCALEKMS_TEST_LIFECYCLE_REFUSAL="+mode)
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatal("expected the lifecycle probe to fail after the injected refusal")
			}
			wantFailure := "enabled_again"
			if mode == "cleanup_schedule" {
				wantFailure = "pending_deletion"
			}
			if !bytes.Contains(out, []byte("--- FAIL: TestRefusedLifecycleStillSchedulesDeletion/"+wantFailure)) {
				t.Fatal("the expected lifecycle subtest did not fail")
			}
			if bytes.Contains(out, []byte("lifecycle request reached the configured key")) {
				t.Fatal("configured key reached a lifecycle route")
			}
			if !bytes.Contains(out, []byte("KMS disposable_cleanup status=pending-deletion")) {
				t.Fatal("disposable key was left without a deletion schedule after one refused lifecycle request")
			}
		})
	}
}
