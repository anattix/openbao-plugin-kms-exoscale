// SPDX-License-Identifier: MPL-2.0

package kmsapi_test

import (
	"bytes"
	"net/http"
	"os"
	"os/exec"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

func TestSealRoleProbe(t *testing.T) {
	switch os.Getenv("EXOSCALEKMS_TEST_SEAL_ROLE") {
	case "restricted", "broad":
		broad := os.Getenv("EXOSCALEKMS_TEST_SEAL_ROLE") == "broad"
		cfg := testkms.Start(t, func(w http.ResponseWriter, _ *http.Request, op string) bool {
			if !broad && op == "generate-data-key" {
				w.WriteHeader(http.StatusForbidden)
				return true
			}
			return false
		})
		checkSealRole(t, t.Context(), liveClient(t, t.Context(), cfg), cfg)
		return
	}
	for _, role := range []string{"restricted", "broad"} {
		t.Run(role, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestSealRoleProbe$")
			cmd.Env = append(os.Environ(), "EXOSCALEKMS_TEST_SEAL_ROLE="+role)
			data, err := cmd.CombinedOutput()
			if role == "restricted" && err != nil {
				t.Fatalf("restricted seal role did not pass the probe: %v\n%s", err, data)
			}
			if role == "broad" && (err == nil || !bytes.Contains(data, []byte("seal role must deny generate-data-key with HTTP 403"))) {
				t.Fatalf("probe did not reject the over-broad role: %v\n%s", err, data)
			}
		})
	}
}
