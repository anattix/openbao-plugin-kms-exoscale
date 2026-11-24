// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

const (
	manualLimit        = "#/kms-key/manual-rotation-limit"
	replicaOnlyRefusal = "#/kms-key/multi-zone/operation-not-allowed-on-a-replica"
)

// RotationProbe exercises manual rotation on a key it creates and owns.
type RotationProbe struct {
	Origin, Replica            Client
	ConfiguredKey, ReplicaZone string
	CheckLimit                 bool
	// BeforeSeal captures a plugin blob and returns the check to run after rotation.
	BeforeSeal func(t *testing.T, key string, version int) (afterSeal func(t *testing.T, version int))
}

// Run creates a disposable key at the origin. The optional replica is
// provisioned and used only for the measured multi-zone lifecycle.
func (p RotationProbe) Run(t *testing.T) {
	t.Helper()
	multiZone := p.ReplicaZone != ""
	var id string
	var replicated bool
	// Check propagation only after origin cleanup verifies the deletion plan.
	afterSchedule := func(ctx context.Context, candidate string) {
		if replicated && candidate == id {
			p.checkReplicaDeletion(ctx, t, id)
		}
	}
	id, p.Origin = createDisposable(t, p.Origin, p.ConfiguredKey, multiZone, afterSchedule)
	before := metadata(t, p.Origin, id)
	if before.Material.Version != 1 || before.Rotation.ManualCount != 0 {
		t.Fatal("new rotation key must have material version 1 and no manual rotations")
	}
	if multiZone {
		p.replicate(t, id, before)
		replicated = true
		// Replication changes the origin revision and replica list.
		before = metadata(t, p.Origin, id)
	}
	var afterSeal func(*testing.T, int)
	if p.BeforeSeal != nil {
		afterSeal = p.BeforeSeal(t, id, before.Material.Version)
	}
	plain := make([]byte, 32)
	old := enc(t, p.Origin, id, plain, nil)
	if multiZone && !t.Run("replica_refusals", func(t *testing.T) {
		checkRotationReplica(t, p.Replica, id, old, plain, time.Now())
		p.replicaRefusals(t, id)
	}) {
		return
	}
	after := p.rotateAndProbe(t, id, before, plain, old)
	if afterSeal != nil {
		t.Run("plugin_blobs_after_rotation", func(t *testing.T) { afterSeal(t, after.Material.Version) })
	}
	if p.CheckLimit && !multiZone && !t.Failed() {
		t.Run("manual_rotation_limit", func(t *testing.T) { p.checkManualLimit(t, id, old, plain, after) })
	}
}

func (p RotationProbe) rotateAndProbe(t *testing.T, id string, before reply, plain, old []byte) reply {
	t.Helper()
	after := p.rotateOnce(t, id, before)
	start := time.Now()
	fresh := enc(t, p.Origin, id, plain, nil)
	if p.ReplicaZone != "" {
		t.Run("post_rotation_replica", func(t *testing.T) {
			checkRotationReplica(t, p.Replica, id, fresh, plain, start)
			if !waitForReplica(t.Context(), p.Replica, id, func(meta reply) bool {
				return meta.Status == "enabled" && meta.Material == after.Material && meta.Rotation == after.Rotation
			}) {
				t.Fatal("replica did not report the rotated material version and manual count")
			}
		})
	}
	dec(t, p.Origin, id, old, nil, plain)
	dec(t, p.Origin, id, fresh, nil, plain)
	rewrapped := reencrypt(t, p.Origin, id, id, old)
	dec(t, p.Origin, id, rewrapped, nil, plain)
	checkCiphertextLengthAs(t, "rotation_old", EndpointZone(p.Origin.Endpoint), before.Material.Version, len(plain), len(old))
	checkCiphertextLengthAs(t, "rotation_fresh", EndpointZone(p.Origin.Endpoint), after.Material.Version, len(plain), len(fresh))
	checkCiphertextLengthAs(t, "rotation_rewrapped", EndpointZone(p.Origin.Endpoint), after.Material.Version, len(plain), len(rewrapped))
	history := success(t, sendRaw(t, p.Origin, http.MethodGet, "/"+id+"/list-key-rotations", nil))
	for _, rotation := range history.Rotations {
		if rotation.Version == after.Material.Version && !rotation.Automatic {
			t.Log("KMS rotation version_delta=1 manual_delta=1 old_decrypt=true new_decrypt=true old_reencrypt=true")
			return after
		}
	}
	t.Fatal("manual rotation missing from rotation history")
	return after
}

func (p RotationProbe) rotateOnce(t *testing.T, id string, before reply) reply {
	t.Helper()
	if !canMutateDisposable(p.ConfiguredKey, id) {
		t.Fatal("rotation refused for configured or invalid key")
	}
	success(t, mutateKey(t, p.Origin, id, "rotate", nil, 0, before))
	after := metadata(t, p.Origin, id)
	if after.Material.Version != before.Material.Version+1 || after.Rotation.ManualCount != before.Rotation.ManualCount+1 {
		t.Fatal("manual rotation did not increment material version and manual count once")
	}
	return after
}

func (p RotationProbe) checkManualLimit(t *testing.T, id string, old, plain []byte, after reply) {
	t.Helper()
	for count := after.Rotation.ManualCount; count < 10; count++ {
		after = p.rotateOnce(t, id, after)
	}
	if !canMutateDisposable(p.ConfiguredKey, id) {
		t.Fatal("limit probe refused for configured or invalid key")
	}
	got := sendRaw(t, p.Origin, http.MethodPost, "/"+id+"/rotate", nil)
	refusal(t, got, expectation{400, manualLimit, "Maximum rotation limit exceeded", ""})
	current := metadata(t, p.Origin, id)
	if current.Status != "enabled" || current.Material.Version != 11 || current.Rotation.ManualCount != 10 {
		t.Fatal("manual rotation limit changed the key state or counts")
	}
	dec(t, p.Origin, id, old, nil, plain)
	fresh := enc(t, p.Origin, id, plain, nil)
	checkCiphertextLengthAs(t, "rotation_limit_fresh", EndpointZone(p.Origin.Endpoint), current.Material.Version, len(plain), len(fresh))
	dec(t, p.Origin, id, fresh, nil, plain)
	t.Log("KMS manual_rotation_limit HTTP=400 manual_count=10 material_version=11")
}

func (p RotationProbe) replicate(t *testing.T, id string, before reply) {
	t.Helper()
	if !canMutateDisposable(p.ConfiguredKey, id) {
		t.Fatal("replication refused for configured or invalid key")
	}
	// Submit once. After a missing reply, destination readback can confirm
	// replication. A missing readback cannot establish it is safe to replay.
	got, err := p.Origin.call(t.Context(), http.MethodPost, "/"+id+"/replicate", replicationBody(t, p.ReplicaZone))
	defer clear(got.raw)
	if (err == nil && got.code != http.StatusOK) || (err != nil && !responseMissing(err)) {
		t.Fatal("replication did not return HTTP 200")
	}
	if !waitForReplica(t.Context(), p.Replica, id, func(meta reply) bool {
		return meta.Status == "enabled" && meta.Material == before.Material && meta.Rotation == before.Rotation
	}) {
		t.Fatal("disposable replica did not become readable")
	}
}

func (p RotationProbe) replicaRefusals(t *testing.T, id string) {
	t.Helper()
	if !canMutateDisposable(p.ConfiguredKey, id) {
		t.Fatal("replica mutation refused for configured or invalid key")
	}
	const title = "Operation not allowed on replica"
	t.Run("rotate", func(t *testing.T) {
		replicaRefusal(t, sendRaw(t, p.Replica, http.MethodPost, "/"+id+"/rotate", nil), replicaOnlyRefusal, title)
	})
	t.Run("schedule_deletion", func(t *testing.T) {
		replicaRefusal(t, sendRaw(t, p.Replica, http.MethodPost, "/"+id+"/schedule-deletion", []byte(`{"delay-days":7}`)), replicaOnlyRefusal, title)
	})
}

// replicaRefusal checks only what the disposable multi-zone measurement
// recorded for a replica refusal: HTTP 400, the problem type and the title.
func replicaRefusal(t *testing.T, got result, typ, title string) {
	t.Helper()
	if got.code != http.StatusBadRequest {
		t.Fatalf("expected HTTP %d, got HTTP %d", http.StatusBadRequest, got.code)
	}
	var problem struct{ Type, Title string }
	if json.Unmarshal(got.raw, &problem) != nil || problem.Type != typ || problem.Title != title {
		t.Fatal("KMS problem type or title differs from the measurement")
	}
}

func waitForReplica(ctx context.Context, replica Client, id string, ready func(reply) bool) bool {
	for attempt := range 20 {
		if attempt != 0 {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(200 * time.Millisecond):
			}
		}
		if meta, ok := replica.readKey(ctx, id); ok && ready(meta) {
			return true
		}
	}
	return false
}

func (p RotationProbe) checkReplicaDeletion(ctx context.Context, t *testing.T, id string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !waitForReplica(ctx, p.Replica, id, func(meta reply) bool { return meta.Status == "pending-deletion" }) {
		t.Error("replica did not report pending deletion")
		return
	}
	body, err := json.Marshal(request{Plaintext: make([]byte, 32)})
	if err != nil {
		t.Fatal("encode replica cleanup probe")
	}
	defer clear(body)
	got, err := p.Replica.probe(ctx, http.MethodPost, "/"+id+"/encrypt", body)
	defer clear(got.raw)
	if err != nil {
		t.Fatal("could not read replica encryption refusal")
	}
	replicaRefusal(t, got, disabledKey, "Key is disabled")
	t.Log("KMS disposable_replica_cleanup status=pending-deletion encrypt=400")
}
