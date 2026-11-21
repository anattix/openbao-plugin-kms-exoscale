// SPDX-License-Identifier: MPL-2.0

package kmsapi

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	egoscale "github.com/exoscale/egoscale/v3"
)

func TestSignMatchesVendor(t *testing.T) {
	for _, tc := range []struct{ name, method, path, body string }{
		{"encrypt", "POST", "/v2/kms-key/id/encrypt", `{"plaintext":"AQID"}`},
		{"decrypt", "POST", "/v2/kms-key/id/decrypt", `{"ciphertext":"AQID"}`},
		{"generate", "POST", "/v2/kms-key/id/generate-data-key", `{"key-spec":"AES-256"}`},
		{"escaping and query order", "GET", "/v2/path%2Fx?z=last&empty=&a=%2B%20&dup=q&dup=w", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			req, err := http.NewRequest(tc.method, "https://api-ch-gva-2.exoscale.com"+tc.path, bytes.NewReader(body))
			if err != nil {
				t.Fatal("create test request")
			}
			vendor := req.Clone(t.Context())
			exp := time.Unix(1800000000, 0)
			if err := egoscale.SignHTTPRequest(vendor, "fixture-key", "fixture-only", exp); err != nil {
				t.Fatal("vendor signer failed")
			}
			sign(req, body, "fixture-key", "fixture-only", exp)
			if req.Header.Get("Authorization") != vendor.Header.Get("Authorization") {
				t.Fatal("Authorization differs from the vendor signer")
			}
		})
	}
}
