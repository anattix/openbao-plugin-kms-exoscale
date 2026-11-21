// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
)

const (
	headerLine      = "{\"magic\":\"OpenTofu-External-Key-Provider\",\"version\":1}\n"
	metadataVersion = 1
	maxInput        = 64 << 10
)

type metadata struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	WrappedKey []byte `json:"wrapped_key"`
}

type metadataEnvelope struct {
	ExternalData *metadata `json:"external_data"`
}

type keys struct {
	Encryption []byte `json:"encryption_key"`
	Decryption []byte `json:"decryption_key,omitempty"`
}

type output struct {
	Keys keys             `json:"keys"`
	Meta metadataEnvelope `json:"meta"`
}

func run(ctx context.Context, in io.Reader, out io.Writer, load func(context.Context) (*kmsapi.Client, kmsapi.Config, error)) error {
	if _, err := io.WriteString(out, headerLine); err != nil {
		return errors.New("cannot write OpenTofu protocol header")
	}
	meta, err := readMetadata(in)
	if err != nil {
		return err
	}
	client, cfg, err := load(ctx)
	if err != nil {
		return fmt.Errorf("configure key provider: %w", err)
	}
	result, err := provide(ctx, client, cfg, meta)
	if err != nil {
		return err
	}
	defer clear(result.Keys.Encryption)
	defer clear(result.Keys.Decryption)
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return errors.New("cannot write OpenTofu protocol result")
	}
	return nil
}

func readMetadata(in io.Reader) (*metadata, error) {
	data, err := io.ReadAll(io.LimitReader(in, maxInput+1))
	if err != nil || len(data) > maxInput {
		return nil, errors.New("cannot read OpenTofu metadata")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, nil
	}
	var input metadataEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&input) != nil || !json.Valid(data) || input.ExternalData == nil {
		return nil, errors.New("invalid OpenTofu metadata")
	}
	meta := input.ExternalData
	if meta.Version != metadataVersion || !kmsapi.ValidKeyID(meta.KeyID) ||
		len(meta.WrappedKey) == 0 || len(meta.WrappedKey) > kmsapi.MaxWrappedKey {
		return nil, errors.New("invalid Exoscale KMS key provider metadata")
	}
	return meta, nil
}

func provide(ctx context.Context, client *kmsapi.Client, cfg kmsapi.Config, meta *metadata) (output, error) {
	var result output
	if meta != nil {
		id, err := kmsapi.ResolveDecryptionKey(cfg.KeyID, meta.KeyID, cfg.AllowedKeyIDs)
		if err != nil {
			return result, err
		}
		raw, err := client.Decrypt(ctx, id, meta.WrappedKey)
		if err != nil {
			return result, err
		}
		defer clear(raw)
		result.Keys.Decryption, err = derive(raw)
		if err != nil {
			return result, err
		}
	}
	fresh, wrapped, err := client.GenerateDataKey(ctx, cfg.KeyID)
	if err != nil {
		clear(result.Keys.Decryption)
		return output{}, err
	}
	defer clear(fresh)
	result.Keys.Encryption, err = derive(fresh)
	if err != nil {
		clear(result.Keys.Decryption)
		return output{}, err
	}
	result.Meta.ExternalData = &metadata{Version: metadataVersion, KeyID: cfg.KeyID, WrappedKey: wrapped}
	return result, nil
}

func derive(raw []byte) ([]byte, error) {
	if len(raw) != kmsapi.KeySize {
		return nil, errors.New("Exoscale KMS returned an invalid AES-256 data key length")
	}
	key, err := hkdf.Key(sha256.New, raw, nil, "exoscalekms/opentofu/state-key/v1", kmsapi.KeySize)
	if err != nil {
		return nil, fmt.Errorf("derive OpenTofu key: %w", err)
	}
	return key, nil
}
