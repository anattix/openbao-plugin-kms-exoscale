// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestPluginRecoversStalledAttempt(t *testing.T) {
	for _, stalled := range []string{"get", "encrypt", "decrypt"} {
		t.Run(stalled, func(t *testing.T) {
			var attempts atomic.Int32
			cfg, endpoint := fakeEndpoint(t, func(_ http.ResponseWriter, r *http.Request, op string) bool {
				if op != stalled || attempts.Add(1) != 1 {
					return false
				}
				<-r.Context().Done() // The first attempt never answers.
				return true
			})
			remote := pluginClient(t, "TestServer")
			start := time.Now()
			err := configureRemote(t.Context(), remote, cfg.KeyID, endpoint)
			if err != nil {
				t.Fatal("configure after one stalled attempt:", err)
			}
			payload := []byte("test fixture")
			blob, err := remote.Encrypt(t.Context(), payload)
			if err != nil {
				t.Fatal("encrypt after one stalled attempt:", err)
			}
			got, err := remote.Decrypt(t.Context(), blob)
			defer clear(got)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("decrypt after one stalled attempt did not recover the fixture:", err)
			}
			if attempts.Load() != 2 || time.Since(start) > callTimeout {
				t.Fatal("plugin did not recover from one stalled attempt within the budget")
			}
		})
	}
}
