// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
)

// TestReplicateRefusesConfiguredKey requires the rotation probe to refuse a
// replication request for the configured UUID before anything is sent, like
// every other lifecycle write of the probe.
func TestReplicateRefusesConfiguredKey(t *testing.T) {
	const child = "EXOSCALEKMS_TEST_REPLICATE_GUARD_CHILD"
	if os.Getenv(child) == "1" {
		var posts atomic.Int32
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				posts.Add(1)
			}
			w.WriteHeader(http.StatusBadRequest)
		}))
		t.Cleanup(srv.Close)
		t.Cleanup(func() { t.Logf("replicate_posts=%d", posts.Load()) })
		const configured = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
		c := Client{HTTP: srv.Client(), Endpoint: srv.URL + "/v2", APIKey: "EXOtest", Secret: "test"}
		RotationProbe{Origin: c, Replica: c, ConfiguredKey: configured, ReplicaZone: "ch-dk-2"}.replicate(t, configured, reply{})
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.v", "-test.run", "^TestReplicateRefusesConfiguredKey$")
	cmd.Env = append(os.Environ(), child+"=1")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
		!bytes.Contains(out, []byte("replication refused for configured or invalid key")) ||
		!bytes.Contains(out, []byte("replicate_posts=0")) {
		t.Fatal("rotation probe sent or attempted replication of the configured key")
	}
}
