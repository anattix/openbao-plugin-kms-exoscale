// SPDX-License-Identifier: MPL-2.0

package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

type observeMutation func(context.Context) (applied *reply, unchanged bool)

// A readback is evidence for one of two outcomes. Anything else leaves the
// operation ambiguous and forbids replay.
func (c Client) mutate(ctx context.Context, path string, body []byte, observe observeMutation) (got result, err error) {
	key := mutationKey(path, body)
	if c.blocked[key] {
		return result{}, errors.New("KMS mutation already failed; identical replay refused")
	}
	if c.blocked != nil {
		defer func() {
			if err != nil || (got.readback == nil && got.code != http.StatusOK) {
				c.blocked[key] = true
			}
		}()
	}
	return c.attemptMutation(ctx, path, body, observe)
}

func mutationKey(path string, body []byte) string {
	return path + " " + string(body)
}

func (c Client) attemptMutation(ctx context.Context, path string, body []byte, observe observeMutation) (result, error) {
	got, err := c.call(ctx, http.MethodPost, path, body)
	got, err, retry := c.reconcileMutation(ctx, got, err, observe)
	if !retry || !c.withinAllowance() {
		return got, err
	}
	got, err = c.call(ctx, http.MethodPost, path, body)
	got, err, _ = c.reconcileMutation(ctx, got, err, observe)
	return got, err
}

func (c Client) reconcileMutation(ctx context.Context, got result, err error, observe observeMutation) (result, error, bool) {
	if !responseMissing(err) || ctx.Err() != nil {
		return got, err, false
	}
	applied, unchanged := observe(ctx)
	if applied != nil {
		return c.reconciled(applied), nil, false
	}
	if !unchanged {
		return got, fmt.Errorf("%w: mutation effect could not be determined", err), false
	}

	// Check again before acting. A stable revision cannot exclude late
	// application of a request already delivered to a connection.
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return got, fmt.Errorf("KMS mutation reconciliation: %w", ctx.Err()), false
	case <-timer.C:
	}
	applied, unchanged = observe(ctx)
	if applied != nil {
		return c.reconciled(applied), nil, false
	}
	if !unchanged {
		return got, fmt.Errorf("%w: mutation effect could not be determined", err), false
	}
	if got.connected || errors.Is(err, errIncomplete) {
		// The API does not document a write fence or an idempotency token.
		// Two matching snapshots cannot prove the first request won't apply later.
		return got, fmt.Errorf("%w: unchanged readback cannot rule out a late effect", err), false
	}
	return got, err, true
}

func (c Client) reconciled(applied *reply) result {
	if c.Unanswered != nil {
		c.Unanswered.t.Log("KMS mutation outcome=confirmed_by_readback")
	}
	return result{readback: applied}
}

func (c Client) readKey(ctx context.Context, id string) (reply, bool) {
	got, err := c.probe(ctx, http.MethodGet, "/"+id, nil)
	defer clear(got.raw)
	var meta reply
	if err != nil || got.code != http.StatusOK || json.Unmarshal(got.raw, &meta) != nil || meta.ID != id || meta.Status == "" {
		return reply{}, false
	}
	return meta, true
}

func (c Client) namedKeys(ctx context.Context, name, configured string) ([]reply, bool) {
	got, err := c.probe(ctx, http.MethodGet, "", nil)
	defer clear(got.raw)
	var list struct {
		Keys *[]reply `json:"kms-keys"`
	}
	if err != nil || got.code != http.StatusOK || json.Unmarshal(got.raw, &list) != nil || list.Keys == nil {
		return nil, false
	}
	var matches []reply
	for _, candidate := range *list.Keys {
		if candidate.Name == name {
			if !canMutateDisposable(configured, candidate.ID) {
				return nil, false
			}
			matches = append(matches, candidate)
		}
	}
	return matches, true
}

func createObserver(c Client, name, configured string) observeMutation {
	return func(ctx context.Context) (*reply, bool) {
		matches, ok := c.namedKeys(ctx, name, configured)
		if !ok || len(matches) > 1 {
			return nil, false
		}
		if len(matches) == 0 {
			return nil, true
		}
		meta, ok := c.readKey(ctx, matches[0].ID)
		if !ok || meta.Name != name {
			return nil, false
		}
		return &meta, false
	}
}

func keyObserver(c Client, id, operation string, days int, before reply) observeMutation {
	return func(ctx context.Context) (*reply, bool) {
		after, ok := c.readKey(ctx, id)
		if !ok {
			return nil, false
		}
		if mutationApplied(operation, days, before, after) {
			return &after, false
		}
		unchanged := after.Status == before.Status && sameRevision(after.Revision, before.Revision) &&
			after.Material == before.Material && after.Rotation == before.Rotation &&
			slices.Equal(after.Replicas, before.Replicas) && sameDeletion(after.DeleteAt, before.DeleteAt)
		if operation == "replicate" {
			unchanged = unchanged && before.MultiZone != nil && !*before.MultiZone &&
				after.MultiZone != nil && !*after.MultiZone && len(after.Replicas) == 0
		}
		return nil, unchanged
	}
}

func sameRevision(a, b *revisionStamp) bool {
	return a != nil && b != nil && !a.At.IsZero() && a.Seq == b.Seq && a.At.Equal(b.At)
}

func sameDeletion(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func mutationApplied(operation string, days int, before, after reply) bool {
	switch operation {
	case "rotate":
		return before.Status == "enabled" && after.Status == "enabled" &&
			after.Material.Version == before.Material.Version+1 && after.Rotation.ManualCount == before.Rotation.ManualCount+1
	case "enable":
		return before.Status == "disabled" && after.Status == "enabled"
	case "disable":
		return before.Status == "enabled" && after.Status == "disabled"
	case "schedule-deletion":
		return days >= 7 && before.Status == "enabled" && deletionScheduled(after, days)
	case "cancel-deletion":
		return before.Status == "pending-deletion" && after.Status == "disabled" && after.DeleteAt == nil
	default:
		return false
	}
}

func mutateKey(t *testing.T, c Client, id, operation string, body []byte, days int, before reply) result {
	t.Helper()
	got, err := c.mutate(t.Context(), "/"+id+"/"+operation, body, keyObserver(c, id, operation, days, before))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(got.raw) })
	return got
}

func disposablePost(t *testing.T, c Client, configured, id, op string, body []byte, days int) result {
	t.Helper()
	if !canMutateDisposable(configured, id) {
		t.Fatal("lifecycle request refused for configured or invalid key")
	}
	return mutateKey(t, c, id, op, body, days, metadata(t, c, id))
}

func cleanupDisposable(t *testing.T, c Client, configured, name, id string, triedCreate bool) {
	t.Helper()
	cleanupOwned(t, c, configured, name, id, triedCreate, c.scheduleCleanup, nil)
}

func cleanupOwned(t *testing.T, c Client, configured, name, id string, triedCreate bool, schedule func(context.Context, string) int, afterSchedule func(context.Context, string)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 75*time.Second)
	defer cancel()
	matches, complete := c.namedKeys(ctx, name, configured)
	ids := make(map[string]bool)
	if canMutateDisposable(configured, id) {
		ids[id] = true
	}
	for _, match := range matches {
		ids[match.ID] = true
	}
	if id == "" && (!complete || (triedCreate && len(ids) == 0)) {
		t.Error("could not reconcile a disposable create; check the test account for the named kms-conformance key")
	}
	if len(ids) > 1 {
		t.Error("multiple disposable keys had the run's generated name")
	}
	var scheduled []string
	for candidate := range ids {
		if days := schedule(ctx, candidate); days != 0 {
			t.Logf("KMS disposable_cleanup status=pending-deletion delay_days=%d", days)
			if afterSchedule != nil {
				scheduled = append(scheduled, candidate)
			}
		} else {
			t.Error("could not confirm disposable key cleanup; check the test account for the named kms-conformance key")
		}
	}
	for _, candidate := range scheduled {
		afterSchedule(ctx, candidate)
	}
}

const (
	minimumDeletionDelay = 7
	maximumDeletionDelay = 30
)

func (c Client) scheduleCleanup(ctx context.Context, id string) int {
	return c.scheduleCleanupWithRecovery(ctx, id, true)
}

func (c Client) scheduleMultiZoneCleanup(ctx context.Context, id string) int {
	return c.scheduleCleanupWithRecovery(ctx, id, false)
}

func (c Client) scheduleCleanupWithRecovery(ctx context.Context, id string, recoverState bool) int {
	if c.blocked == nil {
		c.blocked = make(map[string]bool)
	}
	const recoveryAttempts = 2
	remaining := map[string]int{"disabled": recoveryAttempts, "pending-deletion": recoveryAttempts}
	meta, ok := c.readKey(ctx, id)
	for ok && ctx.Err() == nil {
		if days := scheduledDelay(meta); days != 0 {
			return days
		}
		if count, recovery := remaining[meta.Status]; recovery {
			if !recoverState || count == 0 {
				break
			}
			remaining[meta.Status]--
		}
		meta, ok = c.cleanupStep(ctx, id, meta)
	}
	return 0
}

func (c Client) cleanupStep(ctx context.Context, id string, meta reply) (reply, bool) {
	prefix := "/" + id + "/"
	var operation string
	var body []byte
	var days int
	switch meta.Status {
	case "pending-deletion":
		operation = "cancel-deletion"
	case "disabled":
		operation = "enable"
	case "enabled":
		operation = "schedule-deletion"
		body, days = c.nextCleanupSchedule(prefix + operation)
		if days == 0 {
			return meta, false
		}
	default:
		return meta, false
	}
	path := prefix + operation
	key := mutationKey(path, body)
	if days == 0 {
		// Final cleanup can retry enable or cancel only after a fresh readback
		// confirms that the disposable key still needs that transition.
		delete(c.blocked, key)
	}
	got, _ := c.mutate(ctx, path, body, keyObserver(c, id, operation, days, meta))
	clear(got.raw)
	if days != 0 {
		// An acknowledged plan may still be absent from a readback. Give each
		// cleanup plan one turn even in that case.
		c.blocked[key] = true
	}
	// Choose the next action using the state actually read back.
	return c.readKey(ctx, id)
}

func (c Client) nextCleanupSchedule(path string) ([]byte, int) {
	for days := minimumDeletionDelay; days <= maximumDeletionDelay; days++ {
		body := fmt.Appendf(nil, `{"delay-days":%d}`, days)
		if !c.blocked[mutationKey(path, body)] {
			return body, days
		}
	}
	return nil, 0
}

func scheduledDelay(meta reply) int {
	for days := minimumDeletionDelay; days <= maximumDeletionDelay; days++ {
		if deletionScheduled(meta, days) {
			return days
		}
	}
	return 0
}

func deletionScheduled(meta reply, days int) bool {
	if meta.Status != "pending-deletion" || meta.DeleteAt == nil {
		return false
	}
	const slack = time.Hour
	delay := time.Until(*meta.DeleteAt)
	want := time.Duration(days) * 24 * time.Hour
	return delay >= want-slack && delay <= want+slack
}

func canMutateDisposable(configured, id string) bool {
	return kmsapi.ValidKeyID(id) && !strings.EqualFold(id, configured)
}
