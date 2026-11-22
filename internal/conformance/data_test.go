// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"net/http"
	"testing"
)

// TestPayloadBoundObservation checks that response content is reduced to fixed fields.
func TestPayloadBoundObservation(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body, want string
		hasContentType                bool
	}{
		{"empty refusal", "", "", "absent body_bytes=0 body_server_error=false", false},
		{"known body", "", "server error", "absent body_bytes=12 body_server_error=true", false},
		{"empty content type header", "", "server error", "other body_bytes=12 body_server_error=true", true},
		{"problem response", refusalJSON, "private detail", "problem_json body_bytes=14 body_server_error=false", true},
		{"unrecognized content type", "private type", "private detail", "other body_bytes=14 body_server_error=false", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := "KMS payload_bound accepts=524288 refuses=786432 status=500 content_type=" + tc.want + " exact_bound=unmeasured"
			if payloadBoundObservation(result{code: 500, contentType: tc.contentType, hasContentType: tc.hasContentType, raw: []byte(tc.body)}) != want {
				t.Fatal("payload-bound observation did not match the fixed fields")
			}
		})
	}
}

// TestMatchesPayloadBoundRefusal checks every field of the complete refusal.
func TestMatchesPayloadBoundRefusal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response result
		want     bool
	}{
		{"measured response", result{code: http.StatusInternalServerError, raw: []byte("server error")}, true},
		{"wrong status", result{code: http.StatusBadGateway, raw: []byte("server error")}, false},
		{"present empty header", result{code: http.StatusInternalServerError, hasContentType: true, raw: []byte("server error")}, false},
		{"empty body", result{code: http.StatusInternalServerError}, false},
		{"wrong body of same length", result{code: http.StatusInternalServerError, raw: []byte("other errors")}, false},
		{"trailing newline", result{code: http.StatusInternalServerError, raw: []byte("server error\n")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchesPayloadBoundRefusal(tc.response); got != tc.want {
				t.Fatalf("matchesPayloadBoundRefusal = %t, want %t", got, tc.want)
			}
		})
	}
}
