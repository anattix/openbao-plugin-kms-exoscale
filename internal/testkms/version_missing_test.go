// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/conformance"
)

// TestLengthAssertionsRequireMaterialVersion requires the data probes to fail,
// not skip, when key metadata carries no material version.
func TestLengthAssertionsRequireMaterialVersion(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_VERSION_MISSING_CHILD"
	if os.Getenv(child) == "1" {
		cfg, srv := startFake(t, func(w http.ResponseWriter, r *http.Request, op string) bool {
			if op != "get" || !strings.HasSuffix(r.URL.Path, "/"+KeyID) {
				return false
			}
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte(`{"material":{}}`)); err != nil {
				t.Error("write synthetic key metadata")
			}
			return true
		}, nil, 2)
		conformance.Data(t, testProbeClient(t, cfg.APIKey, cfg.APISecret, srv), KeyID)
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run", "^TestLengthAssertionsRequireMaterialVersion$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("KMS material version missing or invalid (0)")) {
		t.Fatal("data probes passed without a material version")
	}
}
