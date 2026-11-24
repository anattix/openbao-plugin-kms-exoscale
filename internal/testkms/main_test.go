// SPDX-License-Identifier: MPL-2.0

package testkms

import (
	"os"
	"testing"
)

// TestMain keeps the offline fakes independent of an inherited proxy.
func TestMain(m *testing.M) {
	ClearProxyEnvironment()
	os.Exit(m.Run())
}

// TestClearProxyEnvironment checks both startup modes without running live tests.
func TestClearProxyEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name string
		live string
		keep bool
	}{
		{name: "offline"},
		{name: "live", live: "1", keep: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("EXOSCALEKMS_LIVE", tc.live)
			names := []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"}
			const value = "synthetic proxy setting"
			for _, name := range names {
				t.Setenv(name, value)
			}
			ClearProxyEnvironment()
			for _, name := range names {
				got, present := os.LookupEnv(name)
				if present != tc.keep || (present && got != value) {
					t.Errorf("unexpected disposition of %s in %s mode", name, tc.name)
				}
			}
		})
	}
}
