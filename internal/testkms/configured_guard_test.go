// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
)

// A listing that shows the configured key under the run's generated name
// must never let reconciliation or cleanup send a lifecycle request to it.
func TestConfiguredKeyNeverReconciledAsDisposable(t *testing.T) {
	if os.Getenv("EXOSCALEKMS_TEST_CONFIGURED_GUARD") == "1" {
		var mu sync.Mutex
		name := ""
		cfg, srv := startWithResponseHook(t, nil, func(next http.Handler, w http.ResponseWriter, r *http.Request) {
			op := probeOperation(r)
			if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/"+KeyID+"/") && op != "encrypt" && op != "decrypt" {
				t.Log("lifecycle request reached the configured key")
			}
			switch op {
			case "create":
				var in struct{ Name string }
				if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
					t.Error("decode fake create request")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				mu.Lock()
				name = in.Name
				mu.Unlock()
				closeUnanswered(t, w)
				return
			case "list":
				mu.Lock()
				n := name
				mu.Unlock()
				if n != "" {
					w.Header().Set("Content-Type", "application/json")
					type entry struct{ ID, Name, Status string }
					list := struct {
						Keys []entry `json:"kms-keys"`
					}{Keys: []entry{{KeyID, n, "enabled"}}}
					if err := json.NewEncoder(w).Encode(list); err != nil {
						t.Error("write fake key listing")
					}
					return
				}
			}
			next.ServeHTTP(w, r)
		})
		conformance.Disposable(t, testProbeClient(t, cfg.APIKey, cfg.APISecret, srv), KeyID, ReplicaZone)
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestConfiguredKeyNeverReconciledAsDisposable$")
	cmd.Env = append(os.Environ(), "EXOSCALEKMS_TEST_CONFIGURED_GUARD=1")
	out, err := cmd.CombinedOutput()
	if err == nil || bytes.Contains(out, []byte("lifecycle request reached the configured key")) {
		t.Fatal("the configured key was treated as a disposable key")
	}
	if !bytes.Contains(out, []byte("could not reconcile a disposable create")) {
		t.Fatal("an unresolvable create must be reported for the operator")
	}
}
