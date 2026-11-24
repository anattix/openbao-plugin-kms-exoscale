// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

// TestMain keeps the offline fakes independent of an inherited proxy.
func TestMain(m *testing.M) {
	testkms.ClearProxyEnvironment()
	os.Exit(m.Run())
}
