// SPDX-License-Identifier: MPL-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"testing"

	gp "github.com/hashicorp/go-plugin"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func TestPluginExecutable(t *testing.T) {
	binary := os.Getenv("EXOSCALEKMS_TEST_PLUGIN_BINARY")
	if binary == "" {
		t.Skip("set EXOSCALEKMS_TEST_PLUGIN_BINARY to the built executable")
	}
	cfg, endpoint := fakeEndpoint(t, nil)
	client := gp.NewClient(&gp.ClientConfig{
		Cmd:              exec.CommandContext(t.Context(), binary),
		HandshakeConfig:  plugin.HandshakeConfig,
		VersionedPlugins: plugin.PluginSets,
		AllowedProtocols: []gp.Protocol{gp.ProtocolGRPC},
		AutoMTLS:         true,
	})
	t.Cleanup(client.Kill)
	conn, err := client.Client()
	if err != nil {
		t.Fatal("built executable failed to serve the OpenBao protocol:", err)
	}
	wire, err := conn.Dispense("wrapper")
	if err != nil {
		t.Fatal("built executable did not serve a wrapper:", err)
	}
	w := wire.(wrapping.Wrapper)
	ctx := t.Context()
	if err := configureRemote(ctx, w, cfg.KeyID, endpoint); err != nil {
		t.Fatal("configure built plugin:", err)
	}
	payload := []byte("executable smoke fixture")
	blob, err := w.Encrypt(ctx, payload)
	if err != nil {
		t.Fatal("built plugin encrypt:", err)
	}
	got, err := w.Decrypt(ctx, blob)
	defer clear(got)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("built plugin did not recover the fixture")
	}
}
