// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

func TestLiveProvider(t *testing.T) {
	if os.Getenv("EXOSCALEKMS_LIVE") != "1" || os.Getenv("EXOSCALEKMS_KEY_ID") == "" ||
		(os.Getenv("EXOSCALE_API_KEY") == "" && os.Getenv("EXOSCALEKMS_API_KEY_FILE") == "") ||
		(os.Getenv("EXOSCALE_API_SECRET") == "" && os.Getenv("EXOSCALEKMS_API_SECRET_FILE") == "") {
		t.Skip("requires explicit live opt-in, a KMS key ID and Exoscale credentials")
	}
	ctx := t.Context()
	cfg, err := kmsapi.Resolve(ctx, nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kmsapi.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	load := func(context.Context) (*kmsapi.Client, kmsapi.Config, error) { return client, cfg, nil }
	first := exchange(t, []byte("null"), load)
	defer clear(first.Keys.Encryption)
	metadata, err := json.Marshal(first.Meta)
	if err != nil {
		t.Fatal("encode live provider metadata")
	}
	second := exchange(t, metadata, load)
	defer clear(second.Keys.Encryption)
	defer clear(second.Keys.Decryption)
	if !bytes.Equal(first.Keys.Encryption, second.Keys.Decryption) ||
		bytes.Equal(first.Keys.Encryption, second.Keys.Encryption) {
		t.Fatal("provider did not recover the old key and derive a fresh state key")
	}
	t.Logf("state protocol generated and recovered a %d-byte data key, wrapped size %d bytes",
		len(first.Keys.Encryption), len(first.Meta.ExternalData.WrappedKey))
	// The role check needs a credential bound to the state role; a broader
	// test credential is allowed to encrypt, so the check is a separate opt-in.
	if os.Getenv("EXOSCALEKMS_LIVE_LEAST_PRIVILEGE") != "1" {
		t.Log("state role denial unmeasured; set EXOSCALEKMS_LIVE_LEAST_PRIVILEGE=1 with a credential bound to the state role")
		return
	}
	_, err = client.Encrypt(ctx, cfg.KeyID, make([]byte, kmsapi.KeySize))
	var status *kmsapi.StatusError
	if !errors.As(err, &status) || status.Code != http.StatusForbidden {
		t.Fatalf("expected the state role to deny encrypt with HTTP 403: %v", err)
	}
	t.Log("seal encrypt denied with HTTP 403")
}
