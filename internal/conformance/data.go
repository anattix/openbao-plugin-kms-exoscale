// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net/http"
	"testing"
	"time"
)

const payloadRefusalBody = "server error"

// Data exercises the shared non-mutating protocol assertions on a configured key.
func Data(t *testing.T, c Client, id string) {
	t.Helper()
	version := metadata(t, c, id).Material.Version
	plain := make([]byte, 32)
	wrapped := enc(t, c, id, plain, nil)
	t.Run("encryption_context", func(t *testing.T) { contextCases(t, c, id, plain, wrapped) })
	t.Run("generate_data_key", func(t *testing.T) { generateCases(t, c, id, version) })
	t.Run("ciphertext_shape", func(t *testing.T) { shape(t, c, id, version) })
	t.Run("payload_bound", func(t *testing.T) {
		wrapped := enc(t, c, id, make([]byte, 262144), nil)
		checkCiphertextLength(t, version, 262144, len(wrapped))
		for _, size := range []int{393216, 524288} {
			enc(t, c, id, make([]byte, size), nil)
		}
		refused := post(t, c, id, "encrypt", request{Plaintext: make([]byte, 786432)})
		t.Log(payloadBoundObservation(refused))
		if !matchesPayloadBoundRefusal(refused) {
			t.Fatal("payload refusal differs from measured HTTP 500 without Content-Type and with a 12-byte server error body")
		}
	})
	t.Run("same_key_reencrypt", func(t *testing.T) {
		out := reencrypt(t, c, id, id, wrapped)
		dec(t, c, id, out, nil, plain)
		checkCiphertextLength(t, version, len(plain), len(out))
		if bytes.Equal(out, wrapped) {
			t.Fatal("re-encrypt must return fresh ciphertext")
		}
		t.Logf("KMS same_key_reencrypt roundtrip=true wrapped_bytes=%d", len(out))
	})
	t.Run("remote_refusals", func(t *testing.T) { remoteRefusals(t, c, id, wrapped) })
}

func matchesPayloadBoundRefusal(refused result) bool {
	return refused.code == http.StatusInternalServerError &&
		!refused.hasContentType && bytes.Equal(refused.raw, []byte(payloadRefusalBody))
}

func payloadBoundObservation(refused result) string {
	contentType := "other"
	switch {
	case !refused.hasContentType:
		contentType = "absent"
	case refused.contentType == refusalJSON:
		contentType = "problem_json"
	}
	return fmt.Sprintf("KMS payload_bound accepts=524288 refuses=786432 status=%d content_type=%s body_bytes=%d body_server_error=%t exact_bound=unmeasured",
		refused.code, contentType, len(refused.raw), bytes.Equal(refused.raw, []byte(payloadRefusalBody)))
}

func contextCases(t *testing.T, c Client, id string, plain, wrapped []byte) {
	a, b := []byte("test-context-a"), []byte("test-context-b")
	bound := enc(t, c, id, plain, a)
	t.Run("same", func(t *testing.T) {
		dec(t, c, id, bound, a, plain)
		t.Log("KMS context_same status=200 identical=true")
	})
	for _, tc := range []struct {
		name          string
		blob, context []byte
		encoding      string
	}{
		{"absent", bound, nil, "problem"}, {"different", bound, b, "problem"}, {"added", wrapped, a, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusal(t, post(t, c, id, "decrypt", request{Ciphertext: tc.blob, Context: tc.context}),
				expectation{400, invalidCiphertext, "Invalid ciphertext", tc.encoding})
			t.Logf("KMS context_%s status=400 type=%s", tc.name, invalidCiphertext)
		})
	}
}

func generateCases(t *testing.T, c Client, id string, version int) {
	for _, tc := range []struct {
		name    string
		spec    string
		count   *int
		length  int
		failure expectation
	}{
		{name: "aes_256", spec: "AES-256", length: 32},
		{name: "one_byte", count: count(1), length: 1},
		{name: "64_bytes", count: count(64), length: 64},
		{name: "1024_bytes", count: count(1024), length: 1024},
		{name: "both", spec: "AES-256", count: count(16), failure: expectation{400, invalidArgument, "Invalid argument", "problem"}},
		{name: "neither", failure: expectation{400, invalidArgument, "Invalid argument", "problem"}},
		{name: "too_small", count: count(0), failure: expectation{400, invalidArgument, "Invalid Request", "problem"}},
		{name: "too_large", count: count(1025), failure: expectation{400, invalidArgument, "Invalid Request", "problem"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got := post(t, c, id, "generate-data-key", request{KeySpec: tc.spec, BytesCount: tc.count})
			elapsed := time.Since(start)
			if tc.failure.code != 0 {
				refusal(t, got, tc.failure)
				t.Logf("KMS generate_%s status=%d", tc.name, got.code)
				return
			}
			out := success(t, got)
			if len(out.Plaintext) != tc.length {
				t.Fatal("unexpected generated plaintext length")
			}
			checkCiphertextLength(t, version, tc.length, len(out.Ciphertext))
			dec(t, c, id, out.Ciphertext, nil, out.Plaintext)
			t.Logf("KMS generate_%s plaintext_bytes=%d wrapped_bytes=%d elapsed_ms=%d", tc.name, len(out.Plaintext), len(out.Ciphertext), elapsed.Milliseconds())
		})
	}
}

func count(value int) *int { return &value }

func shape(t *testing.T, c Client, id string, version int) {
	var overhead int
	for _, size := range []int{1, 16, 32, 4096, 65536} {
		wrapped := enc(t, c, id, make([]byte, size), nil)
		checkCiphertextLengthAs(t, "ciphertext_shape", version, size, len(wrapped))
		overhead = len(wrapped) - size
	}
	a := enc(t, c, id, make([]byte, 32), nil)
	minPrefix := len(a)
	for range 3 {
		b := enc(t, c, id, make([]byte, 32), nil)
		if bytes.Equal(a, b) {
			t.Fatal("repeated encryption reused a ciphertext")
		}
		for i := range min(len(a), len(b)) {
			if a[i] != b[i] {
				minPrefix = min(minPrefix, i)
				break
			}
		}
	}
	if minPrefix != 9 {
		t.Fatalf("expected minimum ciphertext prefix of 9 bytes, got %d", minPrefix)
	}
	t.Logf("KMS ciphertext_shape material_version=%d overhead=%d prefix=%d", version, overhead, minPrefix)
}

func reencrypt(t *testing.T, c Client, source, dest string, wrapped []byte) []byte {
	t.Helper()
	var in reencryptRequest
	in.Source.Key, in.Source.Ciphertext, in.Destination.Key = source, wrapped, dest
	return success(t, send(t, c, http.MethodPost, "/"+source+"/re-encrypt", in)).Ciphertext
}

func remoteRefusals(t *testing.T, c Client, id string, wrapped []byte) {
	var unknown [16]byte
	if _, err := rand.Read(unknown[:]); err != nil {
		t.Fatal("generate unknown key UUID")
	}
	unknown[6], unknown[8] = unknown[6]&15|64, unknown[8]&63|128
	unknownID := fmt.Sprintf("%x-%x-%x-%x-%x", unknown[:4], unknown[4:6], unknown[6:8], unknown[8:10], unknown[10:])
	flipped := bytes.Clone(wrapped)
	flipped[len(flipped)-1] ^= 1
	random := make([]byte, len(wrapped))
	if _, err := rand.Read(random); err != nil {
		t.Fatal("generate ciphertext-shaped fixture")
	}
	invalid := expectation{400, invalidCiphertext, "Invalid ciphertext", "problem"}
	notFound := expectation{400, unknownKey, "Key not found", "problem"}
	malformed := expectation{code: 400, encoding: "malformed ID"}
	wrongSecret := c
	wrongSecret.Secret += "-conformance-invalid"
	for _, tc := range []struct {
		name, key string
		client    Client
		wrapped   []byte
		want      expectation
	}{
		{"unknown_key", unknownID, c, wrapped, notFound},
		{"malformed_key_id", "not-a-uuid", c, wrapped, malformed},
		{"tampered_ciphertext", id, c, flipped, invalid},
		{"random_ciphertext", id, c, random, invalid},
		{"refused_credential", id, wrongSecret, wrapped, expectation{code: 403}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := post(t, tc.client, tc.key, "decrypt", request{Ciphertext: tc.wrapped})
			refusal(t, got, tc.want)
			t.Logf("KMS %s status=%d", tc.name, got.code)
		})
	}
	t.Run("non_base64_ciphertext", func(t *testing.T) {
		got := sendRaw(t, c, http.MethodPost, "/"+id+"/decrypt", []byte(`{"ciphertext":"not base64 !"}`))
		refusal(t, got, expectation{400, invalidArgument, "Invalid Request", "problem"})
		t.Log("KMS non_base64_ciphertext status=400")
	})
	t.Run("unknown_key_metadata", func(t *testing.T) {
		refusal(t, sendRaw(t, c, http.MethodGet, "/"+unknownID, nil), notFound)
	})
	t.Run("unknown_key_encrypt", func(t *testing.T) {
		refusal(t, post(t, c, unknownID, "encrypt", request{Plaintext: make([]byte, 32)}), notFound)
	})
	t.Run("malformed_key_metadata", func(t *testing.T) {
		refusal(t, sendRaw(t, c, http.MethodGet, "/not-a-uuid", nil), malformed)
	})
	t.Run("refused_signature_metadata_and_encrypt", func(t *testing.T) {
		want := expectation{code: 403, encoding: "signature"}
		refusal(t, sendRaw(t, wrongSecret, http.MethodGet, "/"+id, nil), want)
		refusal(t, post(t, wrongSecret, id, "encrypt", request{Plaintext: make([]byte, 32)}), want)
	})
	t.Run("unknown_api_key_metadata", func(t *testing.T) {
		var keyNonce [12]byte
		if _, err := rand.Read(keyNonce[:]); err != nil {
			t.Fatal("generate unknown API key")
		}
		unknownCredential := wrongSecret
		unknownCredential.APIKey = fmt.Sprintf("EXO%x", keyNonce)
		refusal(t, sendRaw(t, unknownCredential, http.MethodGet, "/"+id, nil), expectation{code: 403, encoding: "api key"})
	})
}

// Rate checks the measured 32-request paced sample, independently of service quotas.
func Rate(t *testing.T, c Client, id string) {
	t.Helper()
	plain := make([]byte, 32)
	wrapped := enc(t, c, id, plain, nil)
	start := time.Now()
	pacer := time.NewTicker(125 * time.Millisecond)
	defer pacer.Stop()
	for range 32 {
		select {
		case <-pacer.C:
			dec(t, c, id, wrapped, nil, plain)
		case <-t.Context().Done():
			t.Fatal("paced sample canceled")
		}
	}
	t.Logf("KMS paced_requests requests=32 elapsed_ms=%d http_429=0", time.Since(start).Milliseconds())
}
