// SPDX-License-Identifier: MPL-2.0

package kmsapi_test

import (
	"os"
	"os/exec"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

// TestMain keeps the offline fakes independent of an inherited proxy.
func TestMain(m *testing.M) {
	testkms.ClearProxyEnvironment()
	os.Exit(m.Run())
}

// TestOfflineSuiteIgnoresAmbientProxy runs a fake-backed test in a child
// process that inherits an unreachable proxy.
func TestOfflineSuiteIgnoresAmbientProxy(t *testing.T) {
	if os.Getenv("EXOSCALEKMS_LIVE") == "1" {
		t.Skip("live runs keep the proxy environment")
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestLifecycleCallIsNotRetried$", "-test.count=1", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "HTTPS_PROXY=http://127.0.0.1:1",
		"https_proxy=http://127.0.0.1:1", "NO_PROXY=", "no_proxy=")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fake-backed test failed under an inherited proxy: %v\n%s", err, output)
	}
}
