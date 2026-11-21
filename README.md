<!-- SPDX-License-Identifier: MPL-2.0 -->

# Exoscale KMS for OpenBao and OpenTofu

- `openbao-plugin-kms-exoscale` provides the `exoscale` auto-unseal seal for
  OpenBao 2.7.2. It serves the `exoscalekms` wrapper proposed by the Exoscale
  KMS team, pinned to commit
  `cde32eb9b902bae1d97b3ef2b8b92e00d9c47f4e`. [OpenBao wrapper PR 168](https://github.com/openbao/go-kms-wrapping/pull/168)
- `tofu-keyprovider-exoscale-kms` implements the OpenTofu 1.13.1 external key
  provider protocol for encrypting state and plans with `aes_gcm`.

The plugin stores the upstream wrapper's envelope unchanged. Once OpenBao
publishes a plugin that uses this format, replace this binary and its pinned
version and digest while keeping the seal name, KMS key and zone. This
replacement requires no seal migration. Use the seal migration procedure
below to move from a different seal, including an earlier prototype that
stored a private envelope format.

The seal binary uses the upstream wrapper and its Exoscale Go SDK to avoid a
second envelope implementation. The state provider retains its small
standard-library EXO2 signing client. Its production binary links no
third-party modules. The SDK and JSON Schema validator support the provider's
tests.

## Build and verify

Build from a pinned source commit archive with Go 1.27.4. Verify the source
archive digest against a trusted copy before extracting it. Use the same Go
patch release and target for both builds in a digest comparison.

```sh
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
test "$(go env GOVERSION)" = go1.27.4
go mod download
go mod verify
mkdir -p bin
for command in openbao-plugin-kms-exoscale tofu-keyprovider-exoscale-kms; do
  go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w' \
    -o "bin/$command" "./cmd/$command"
done
(cd bin && sha256sum openbao-plugin-kms-exoscale tofu-keyprovider-exoscale-kms)
```

Keep the expected `SHA256SUMS` from a separately trusted build or release.
Verify it in the directory with the binaries using `sha256sum -c SHA256SUMS`.
Use the verified plugin digest in OpenBao's configuration. CI compares
digests built in different checkout paths on two runner images.

## Configure the OpenBao seal

OpenBao 2.7 removed the built-in cloud seals. A KMS plugin must be configured
on disk because the server loads it while the store is sealed. Install the
verified executable in the real directory named by `plugin_directory`.
Keep this directory writable only by the operator.

```hcl
plugin_directory = "/opt/openbao/plugins"

plugin "kms" "exoscale" {
  command   = "openbao-plugin-kms-exoscale"
  version   = "v0.1.0" # Use the version assigned to your pinned build.
  sha256sum = "<verified 64-character SHA-256 digest>"
}

seal "exoscale" {
  key_id     = "<Exoscale KMS key UUID>"
  zone       = "ch-gva-2"
  endpoint   = "https://api-ch-gva-2.exoscale.com/v2"
  api_key    = "file:///etc/openbao/exoscale/api-key"
  api_secret = "file:///etc/openbao/exoscale/api-secret"
}
```

The seal name matches the plugin declaration. Use an enabled symmetric
Exoscale KMS key usable for encryption and decryption. Mount credential files
readable by the plugin process or inject environment variables. Keep literal
credentials out of HCL and deployment arguments.

| Seal option | Upstream environment name | Value |
| --- | --- | --- |
| `key_id` | `EXOSCALEKMS_KEY_ID` | KMS key UUID |
| `zone` | `EXOSCALEKMS_ZONE` | Zone hosting the key |
| `endpoint` | `EXOSCALEKMS_ENDPOINT` | Optional explicit HTTPS API base URL including `/v2` |
| `api_key` | `EXOSCALE_API_KEY` | API key environment value or `file:///absolute/path` in HCL |
| `api_secret` | `EXOSCALE_API_SECRET` | API secret environment value or `file:///absolute/path` in HCL |

When the plugin client permits environment reads, a nonempty environment
value takes precedence. Credential options also support `env://VARIABLE`
with environment reads enabled. File references work with environment
reads disabled. Files are limited to 8 KiB and must hold the value exactly,
with no surrounding whitespace or trailing newline (write them with
`printf '%s'`). The upstream wrapper reads `file://` values without trimming,
so this plugin refuses a file that would only work after trimming.
OpenBao starts the plugin as a child process. Use the `env` parameter of the
`plugin` stanza for non-secret values and mount credential files for the
plugin. Entries in `env` are configuration literals. Verify environment
forwarding in your deployment if you inject credentials through the parent
environment. [OpenBao plugin configuration](https://openbao.org/docs/configuration/plugins/)

By default the plugin uses `https://api-ZONE.exoscale.com/v2` directly.
Allow outbound HTTPS to `api-ch-gva-2.exoscale.com:443` for `ch-gva-2` or to
`api-ch-dk-2.exoscale.com:443` for `ch-dk-2`. With an explicit endpoint, allow
its configured HTTPS destination. These are the direct destinations. The SDK
can use a proxy configured in the plugin environment. The bare upstream
wrapper discovers the zone
through `ListZones` at `api-ch-gva-2.exoscale.com:443` when given only a zone.
This binary supplies the zone endpoint and skips discovery. Set `endpoint`
explicitly, as in the example, so that a future upstream plugin binary using
the same stanza also skips discovery and targets that host. Startup makes a
signed `GetKmsKey` call to that endpoint. OpenBao periodically checks seal
health by encrypting and decrypting a small value.
[OpenBao seal configuration](https://openbao.org/docs/configuration/seal/)

### IAM

Use independent API credentials and default-deny policies. The seal needs
`get-kms-key` at startup and `encrypt` and `decrypt` during service. The
state provider needs `generate-data-key` and `decrypt`.

```json
{
  "default-service-strategy": "deny",
  "services": {
    "kms": {
      "type": "rules",
      "rules": [
        {
          "action": "allow",
          "expression": "operation in ['get-kms-key', 'encrypt', 'decrypt'] && has(resources.kms_key) && resources.kms_key.id == '<seal-key-uuid>'"
        }
      ]
    }
  }
}
```

For the state provider use
`operation in ['generate-data-key', 'decrypt'] && has(resources.kms_key) && resources.kms_key.id == '<state-key-uuid>'`.
During an older-UUID transition, grant only `decrypt` for a retired UUID that
still protects stored data. Keep rotation, replication, enable, disable and
deletion permissions on operator credentials. Validate the policy with
the restricted credentials and a disposable key before rollout.
[Exoscale IAM policy guide](https://community.exoscale.com/product/security/iam/how-to/policy-guide/#key-management-service-kms)

### Migrate another auto-unseal seal

1. Back up storage and verify recovery access. Keep both KMS keys, both
   plugins and their credentials available. Schedule for downtime.
2. Stop one standby and add the new plugin and seal declarations. Keep the old
   plugin declaration and add `disabled = "true"` to the old seal. Restart
   that standby and submit the required recovery keys using
   `bao operator unseal -migrate`. Repeat with each standby, one at a time,
   preserving storage quorum.
3. Step down the active node. Wait for the new active node to log completion
   and for the new seal state to replicate.
4. Restart the old active node with only the new seal and verify auto-unseal.
   Remove the old declarations from the remaining nodes as they restart.
   Preserve old key access for retained backups.
   [OpenBao seal migration](https://openbao.org/docs/concepts/seal/#seal-migration)

## OpenTofu state and plans

Install the provider binary where OpenTofu runs. Supply `EXOSCALE_ZONE`, `EXOSCALEKMS_KEY_ID`, and credentials using file paths or an injected environment. The file variables are `EXOSCALEKMS_API_KEY_FILE` and
`EXOSCALEKMS_API_SECRET_FILE`. The value variables are `EXOSCALE_API_KEY` and
`EXOSCALE_API_SECRET`. Set these per invocation when stacks share a runner.
Apply the encryption configuration consistently to every runner with access
to the same state.

```hcl
terraform {
  encryption {
    key_provider "external" "exoscale" {
      command = ["/usr/local/bin/tofu-keyprovider-exoscale-kms"]
    }

    method "aes_gcm" "exoscale" {
      keys = key_provider.external.exoscale
    }

    state {
      method   = method.aes_gcm.exoscale
      enforced = true
    }

    plan {
      method   = method.aes_gcm.exoscale
      enforced = true
    }
  }
}
```

To migrate from AWS KMS, keep the original provider and method, including their names and any metadata alias. For example, if their existing names are both `original`, merge the following into the same `encryption` block, replacing the example ARN and retaining the original AWS settings:

```hcl
key_provider "aws_kms" "original" {
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111"
  key_spec   = "AES_256"
  region     = "us-east-1"
}

method "aes_gcm" "original" {
  keys = key_provider.aws_kms.original
}

state {
  method   = method.aes_gcm.exoscale
  enforced = true
  fallback {
    method = method.aes_gcm.original
  }
}

plan {
  method   = method.aes_gcm.exoscale
  enforced = true
  fallback {
    method = method.aes_gcm.original
  }
}
```

Back up encrypted state first. Run a reviewed operation that writes state. New writes use Exoscale. Verify state can be read with the new-only configuration before removing the fallback. Regenerate or expire old saved plans and keep the former credentials available for retained backups. For an expressly approved plaintext migration, use a temporary `unencrypted` fallback and remove it once the state has been rewritten. [OpenTofu state and plan encryption](https://opentofu.org/docs/v1.13/language/state/encryption/)

The provider bounds wrapped metadata at 32 KiB and KMS response bodies at
64 KiB. Each attempt has a 3-second default timeout, configurable with
`EXOSCALEKMS_TIMEOUT` up to 10 seconds. It retries one eligible transient
failure and respects caller cancellation. `EXOSCALEKMS_CA_FILE` adds
certificates to the system pool. For a deliberate old-key transition, list
permitted older UUIDs in `EXOSCALEKMS_ALLOWED_KEY_IDS` and retain their
decrypt permissions. The provider validates its stored metadata and key UUID
before requesting a decryption key.

## Failure behavior and limits

A persistent KMS failure prevents unseal or state-key retrieval. Neither
command substitutes a local key. The seal uses a 15-second request budget
per configuration, encryption or decryption call. Calls honor cancellation.
The SDK retries eligible connection errors and statuses within a 5-second
attempt. When an attempt reaches its own deadline, the plugin starts another
within the remaining operation budget. An encrypt retry can wrap a fresh
data key if the previous response was lost. The wrapper reuses its configured
zone for decrypt and uses the
stored UUID when present. Keep the relevant UUIDs and key versions usable
for the life of the sealed data and backups.

The seal requires an HTTPS endpoint and uses system certificate verification.
Install any additional CA alongside existing system trust. The SDK owns its
HTTP client and can follow redirects, including a downgrade, and reads
response bodies before the plugin can validate them. Until the upstream
wrapper provides a transport hook, constrain the seal process's egress to
the configured HTTPS destination and use a KMS endpoint that never redirects.
The state provider refuses all redirects itself.

Seal storage contains the AES-GCM ciphertext and nonce and a key record with
the configured UUID and the opaque KMS-wrapped data key. Each seal encrypt
sends a 32-byte data key to KMS. The payload is encrypted locally. The live
service's ciphertext format, maximum request size, throttling behavior,
rotation semantics and replica interoperability require measurement.

## Tests

With the module cache populated as above, run the local tests with
`GOPROXY=off`. The KMS integration suite uses loopback TLS and the upstream
plugin test harness. Run the unchanged wrapper tests from the root module
so they use the pinned dependency graph.

```sh
go list ./... | while IFS= read -r package; do
  GOPROXY=off go test -mod=readonly -timeout 10m -count=1 "$package" || exit
done
GOPROXY=off go test -mod=readonly -timeout 10m -count=1 \
  github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2
```

Live tests require `EXOSCALEKMS_LIVE=1`, `EXOSCALEKMS_KEY_ID` and credentials
in the environment or file variables. Set `EXOSCALEKMS_ZONE` for the plugin
and `EXOSCALE_ZONE` for the state provider and raw API probes. Run the
commands separately with the credentials for each component.

```sh
go test -v -timeout 10m -count=1 -run '^TestLiveConformance$' ./cmd/openbao-plugin-kms-exoscale
go test -v -timeout 10m -count=1 -run '^TestLiveProvider$' ./cmd/tofu-keyprovider-exoscale-kms
go test -v -timeout 10m -count=1 -run '^TestLiveAPIConformance$' ./internal/kmsapi
```

The plugin test records round-trip timings and serialized and wrapped sizes.
Set `EXOSCALEKMS_LIVE_REPLICA_ZONE` to an existing synchronized replica for a
two-way decrypt check. Set `EXOSCALEKMS_LIVE_ROTATE=1` only with a disposable
key and credentials allowed to rotate it. The test creates one rotation and
tries ciphertext written before and after it. The state test runs the JSON
protocol against the service and checks that the state role denies seal
`encrypt`. The raw API probes use a separate probe credential with both
crypto roles to test request sizes through 16 KiB and record status codes.
An optional disabled test key uses `EXOSCALEKMS_LIVE_DISABLED_KEY_ID`.
`EXOSCALEKMS_LIVE_RATE_PROBE=1` runs a paced, bounded decrypt probe.
For raw API IAM validation with seal credentials, use
`EXOSCALEKMS_LIVE_LEAST_PRIVILEGE=1` and, optionally,
`EXOSCALEKMS_LIVE_OTHER_KEY_ID` for a distinct enabled key. Use
`EXOSCALEKMS_LIVE_DISPOSABLE=1` only with a disposable key. The attempted
lifecycle denials can modify it if the credential is over-privileged.

This project is distributed under the Mozilla Public License 2.0. The
carried module retains its original notices and [provenance](third_party/exoscalekms/README.md).
See the [security policy](SECURITY.md) for private vulnerability reporting.
