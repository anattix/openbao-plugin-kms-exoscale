// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/anattix/openbao-plugin-kms-exoscale/internal/kmsapi"
	"github.com/anattix/openbao-plugin-kms-exoscale/internal/testkms"
)

func TestOpenTofuProtocol(t *testing.T) {
	cfg := testkms.Start(t, nil)
	client, err := kmsapi.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	load := func(context.Context) (*kmsapi.Client, kmsapi.Config, error) { return client, cfg, nil }
	initial := exchange(t, []byte("null"), load)
	defer clear(initial.Keys.Encryption)
	if len(initial.Keys.Encryption) != kmsapi.KeySize || len(initial.Keys.Decryption) != 0 ||
		initial.Meta.ExternalData == nil || initial.Meta.ExternalData.KeyID != cfg.KeyID ||
		initial.Meta.ExternalData.Version != 1 || len(initial.Meta.ExternalData.WrappedKey) == 0 {
		t.Fatal("invalid first-use key or metadata")
	}
	meta, err := json.Marshal(initial.Meta)
	if err != nil {
		t.Fatal("marshal metadata")
	}
	next := exchange(t, meta, load)
	defer clear(next.Keys.Encryption)
	defer clear(next.Keys.Decryption)
	if !bytes.Equal(initial.Keys.Encryption, next.Keys.Decryption) ||
		len(next.Keys.Encryption) != kmsapi.KeySize ||
		bytes.Equal(next.Keys.Encryption, initial.Keys.Encryption) {
		t.Fatal("returned decryption key must match the prior entry and the new encryption key must be fresh")
	}
	if raw, err := client.Decrypt(t.Context(), cfg.KeyID, initial.Meta.ExternalData.WrappedKey); err != nil {
		t.Fatal(err)
	} else {
		defer clear(raw)
		if bytes.Equal(raw, initial.Keys.Encryption) {
			t.Fatal("protocol exposed the raw Exoscale data key")
		}
	}
}

func exchange(t *testing.T, input []byte, load func(context.Context) (*kmsapi.Client, kmsapi.Config, error)) output {
	t.Helper()
	validateSchema(t, "input", input)
	var stdout bytes.Buffer
	defer func() { clear(stdout.Bytes()) }()
	if err := run(t.Context(), &handshakeReader{bytes.NewReader(input), &stdout}, &stdout, load); err != nil {
		t.Fatalf("protocol exchange failed: %v", err)
	}
	header, payload, found := bytes.Cut(stdout.Bytes(), []byte("\n"))
	if !found {
		t.Fatal("missing newline-delimited OpenTofu header")
	}
	validateSchema(t, "header", header)
	validateSchema(t, "output", payload)
	var result output
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatal("invalid OpenTofu provider response")
	}
	return result
}

type handshakeReader struct {
	in  io.Reader
	out *bytes.Buffer
}

func (r *handshakeReader) Read(p []byte) (int, error) {
	if !bytes.HasSuffix(r.out.Bytes(), []byte("\n")) {
		return 0, errors.New("header was not emitted before reading stdin")
	}
	return r.in.Read(p)
}

func validateSchema(t *testing.T, name string, payload []byte) {
	t.Helper()
	doc, err := os.ReadFile(filepath.Join("testdata", name+".schema.json"))
	if err != nil {
		t.Fatal("read pinned OpenTofu schema")
	}
	schemaValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		t.Fatal("parse pinned OpenTofu schema")
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertContent()
	uri := "https://schema.invalid/" + name + ".json"
	if err := compiler.AddResource(uri, schemaValue); err != nil {
		t.Fatal("add pinned OpenTofu schema")
	}
	schema, err := compiler.Compile(uri)
	if err != nil {
		t.Fatal("compile pinned OpenTofu schema")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil || schema.Validate(value) != nil {
		t.Fatalf("%s does not match OpenTofu 1.13.1 schema", name)
	}
}

func TestProviderFailsClosed(t *testing.T) {
	var calls atomic.Int32
	cfg := testkms.Start(t, func(w http.ResponseWriter, _ *http.Request, op string) bool {
		calls.Add(1)
		if op == "generate-data-key" {
			http.Error(w, "remote-probe-body", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	client, err := kmsapi.New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, input string
		calls       int32
	}{
		{"malformed JSON", `{"external_data":`, 0},
		{"multiple JSON values", `null null`, 0},
		{"unsupported metadata version", `{"external_data":{"version":2,"key_id":"` + cfg.KeyID + `","wrapped_key":"AA=="}}`, 0},
		{"wrong key", `{"external_data":{"version":1,"key_id":"` + testkms.OtherID + `","wrapped_key":"AA=="}}`, 0},
		{"generate retried once then fails", "null", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			before := calls.Load()
			err := run(t.Context(), strings.NewReader(tc.input), &stdout, func(context.Context) (*kmsapi.Client, kmsapi.Config, error) {
				return client, cfg, nil
			})
			if err == nil || strings.Contains(err.Error(), "remote-probe-body") || stdout.String() != headerLine ||
				calls.Load()-before != tc.calls {
				t.Fatal("provider did not fail closed")
			}
		})
	}
}
