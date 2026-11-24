// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

type createRequest struct {
	Name      string `json:"name"`
	Usage     string `json:"usage"`
	MultiZone bool   `json:"multi-zone"`
}

type replicateRequest struct {
	Zone string `json:"zone"`
}

func replicationBody(t *testing.T, zone string) []byte {
	t.Helper()
	body, err := json.Marshal(replicateRequest{zone})
	if err != nil {
		t.Fatal("encode replication request")
	}
	return body
}

// Replica probes interoperability in both directions using an already provisioned replica.
func Replica(t *testing.T, origin, replica Client, id string) {
	t.Helper()
	plain := make([]byte, 32)
	fromOrigin := enc(t, origin, id, plain, nil)
	dec(t, replica, id, fromOrigin, nil, plain)
	fromReplica := enc(t, replica, id, plain, nil)
	dec(t, origin, id, fromReplica, nil, plain)
	if !MeasuredCiphertextLength(EndpointZone(origin.Endpoint), len(plain), len(fromOrigin)) {
		t.Error("origin ciphertext length is outside the measured sizes")
	}
	if !MeasuredCiphertextLength(EndpointZone(replica.Endpoint), len(plain), len(fromReplica)) {
		t.Error("replica ciphertext length is outside the measured sizes")
	}
	t.Log("KMS replica same_uuid=true both_directions=true")
}

func checkRotationReplica(t *testing.T, replica Client, id string, wrapped, plain []byte, start time.Time) {
	t.Helper()
	body, err := json.Marshal(request{Ciphertext: wrapped})
	if err != nil {
		t.Fatal("encode replica decrypt probe")
	}
	defer clear(body)
	for attempt := 1; attempt <= 20; attempt++ {
		select {
		case <-t.Context().Done():
			t.Fatal("replica probe canceled")
		case <-time.After(200 * time.Millisecond):
		}
		got, err := replica.probe(t.Context(), http.MethodPost, "/"+id+"/decrypt", body)
		if err == nil && got.code == 200 {
			decResult(t, got, plain)
			clear(got.raw)
			t.Logf("KMS post_rotation_replica attempts=%d elapsed_ms=%d", attempt, time.Since(start).Milliseconds())
			return
		}
		clear(got.raw)
		if err != nil || got.code != 400 {
			t.Fatalf("replica decrypt failed (HTTP %d)", got.code)
		}
	}
	t.Fatal("replica did not decrypt post-rotation ciphertext within 20 attempts")
}

func decResult(t *testing.T, got result, plain []byte) {
	t.Helper()
	out := success(t, got)
	if string(out.Plaintext) != string(plain) {
		t.Fatal("replica decrypted different bytes")
	}
}

// Disposable probes state transitions on a newly created single-zone key.
func Disposable(t *testing.T, c Client, configured, replicateZone string) {
	t.Helper()
	owned, c := createDisposable(t, c, configured, false, nil)
	wrapped := disposableData(t, c, configured, owned, replicateZone)
	disposableStates(t, c, configured, owned, wrapped)
}

func createDisposable(t *testing.T, c Client, configured string, multiZone bool, afterSchedule func(context.Context, string)) (string, Client) {
	t.Helper()
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("generate disposable key name")
	}
	name := fmt.Sprintf("kms-conformance-%x", nonce[:])
	c.blocked = make(map[string]bool)
	raw, err := json.Marshal(createRequest{Name: name, Usage: "encrypt-decrypt", MultiZone: multiZone})
	if err != nil {
		t.Fatal("encode disposable create request")
	}
	owned := ""
	triedCreate := false
	t.Cleanup(func() {
		if multiZone {
			cleanupOwned(t, c, configured, name, owned, triedCreate, c.scheduleMultiZoneCleanup, afterSchedule)
			return
		}
		cleanupDisposable(t, c, configured, name, owned, triedCreate)
	})
	t.Logf("KMS disposable_name=%s", name)
	if matches, ok := c.namedKeys(t.Context(), name, configured); !ok || len(matches) != 0 {
		t.Fatal("could not establish an unused disposable key name")
	}
	triedCreate = true
	got, err := c.mutate(t.Context(), "", raw, createObserver(c, name, configured))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got.raw)
	created := success(t, got)
	if !canMutateDisposable(configured, created.ID) || created.Name != name {
		t.Fatal("create did not return the new disposable key identity")
	}
	owned = created.ID
	if created.MultiZone == nil || *created.MultiZone != multiZone || created.Status != "enabled" || created.Usage != "encrypt-decrypt" {
		t.Fatal("created key has unexpected zone mode, state or usage")
	}
	if !multiZone {
		t.Log("KMS disposable single_zone=true enabled=true first_cleanup_plan_days=7")
	}
	return owned, c
}

func disposableData(t *testing.T, c Client, configured, owned, replicateZone string) []byte {
	t.Helper()
	plain := make([]byte, 32)
	original := enc(t, c, configured, plain, nil)
	wrapped := enc(t, c, owned, plain, nil)
	t.Run("single_zone_replication", func(t *testing.T) {
		got := disposablePost(t, c, configured, owned, "replicate", replicationBody(t, replicateZone), 0)
		refusal(t, got, expectation{400, singleZone, "Replication allowed on multi-zone keys only", ""})
		t.Logf("KMS single_zone_replication status=400 type=%s", singleZone)
	})
	t.Run("different_key_reencrypt", func(t *testing.T) {
		out := reencrypt(t, c, configured, owned, original)
		checkCiphertextLength(t, EndpointZone(c.Endpoint), metadata(t, c, owned).Material.Version, len(plain), len(out))
		dec(t, c, owned, out, nil, plain)
		t.Log("KMS different_key_reencrypt status=200 roundtrip=true")
	})
	t.Run("ciphertext_of_another_key", func(t *testing.T) {
		got := post(t, c, owned, "decrypt", request{Ciphertext: original})
		refusal(t, got, expectation{code: 400})
		var problem struct{ Detail string }
		if json.Unmarshal(got.raw, &problem) != nil || !strings.Contains(problem.Detail, "ERN identifiers do not match") {
			t.Fatal("wrong-key response did not identify an ERN mismatch")
		}
		t.Log("KMS ciphertext_of_another_key status=400 ern_mismatch=true")
	})
	return wrapped
}

func metadata(t *testing.T, c Client, id string) reply {
	t.Helper()
	return success(t, sendRaw(t, c, http.MethodGet, "/"+id, nil))
}

func disposableStates(t *testing.T, c Client, configured, id string, wrapped []byte) {
	t.Helper()
	if !t.Run("disabled", func(t *testing.T) {
		success(t, disposablePost(t, c, configured, id, "disable", nil, 0))
		checkDisabled(t, c, id, "disabled", wrapped)
		t.Log("KMS disabled encrypt=400 decrypt=400 generate=400")
	}) {
		return
	}
	if !t.Run("enabled_again", func(t *testing.T) {
		if metadata(t, c, id).Status != "disabled" {
			success(t, disposablePost(t, c, configured, id, "disable", nil, 0))
		}
		enable(t, c, configured, id, wrapped)
		t.Log("KMS enabled_again decrypt=200")
	}) {
		return
	}
	if !t.Run("pending_deletion", func(t *testing.T) {
		refusal(t, disposablePost(t, c, configured, id, "schedule-deletion", []byte(`{"delay-days":6}`), 6), expectation{code: 400})
		out := success(t, disposablePost(t, c, configured, id, "schedule-deletion", []byte(`{"delay-days":7}`), 7))
		if out.DeleteAt == nil {
			t.Fatal("accepted deletion did not return a date")
		}
		checkDisabled(t, c, id, "pending-deletion", wrapped)
		t.Log("KMS pending_deletion six_days=400 seven_days=200 encrypt=400 decrypt=400 generate=400")
	}) {
		return
	}
	t.Run("cancel_deletion", func(t *testing.T) {
		if metadata(t, c, id).Status != "pending-deletion" {
			success(t, disposablePost(t, c, configured, id, "schedule-deletion", []byte(`{"delay-days":7}`), 7))
		}
		success(t, disposablePost(t, c, configured, id, "cancel-deletion", nil, 0))
		checkDisabled(t, c, id, "disabled", wrapped)
		enable(t, c, configured, id, wrapped)
		t.Log("KMS cancel_deletion state=disabled decrypt_before_enable=400 decrypt_after_enable=200")
	})
}

func checkDisabled(t *testing.T, c Client, id, state string, wrapped []byte) {
	t.Helper()
	if metadata(t, c, id).Status != state {
		t.Fatal("key state differs from expected state")
	}
	for _, tc := range []struct {
		op string
		in request
	}{
		{"encrypt", request{Plaintext: make([]byte, 32)}}, {"decrypt", request{Ciphertext: wrapped}},
		{"generate-data-key", request{KeySpec: "AES-256"}},
	} {
		refusal(t, post(t, c, id, tc.op, tc.in), expectation{400, disabledKey, "Key is disabled", ""})
	}
}

func enable(t *testing.T, c Client, configured, id string, wrapped []byte) {
	t.Helper()
	success(t, disposablePost(t, c, configured, id, "enable", nil, 0))
	if metadata(t, c, id).Status != "enabled" {
		t.Fatal("enable did not restore enabled state")
	}
	dec(t, c, id, wrapped, nil, make([]byte, 32))
}
