<!-- SPDX-License-Identifier: MPL-2.0 -->

# Exoscale KMS for OpenBao and OpenTofu

Release candidate `v0.2.0-rc.4`.

- `openbao-plugin-kms-exoscale` provides the `exoscale` auto-unseal seal for
  OpenBao 2.7.2. It serves the `exoscalekms` wrapper proposed by the Exoscale
  KMS team, pinned to commit
  `aad18865db438363ffd9927dda970ce3bbd952fb`. [OpenBao wrapper PR 168](https://github.com/openbao/go-kms-wrapping/pull/168)
- `tofu-keyprovider-exoscale-kms` implements the OpenTofu 1.13.1 external key
  provider protocol for encrypting state and plans with `aes_gcm`.

This repository provides an interim OpenBao seal plugin. The author of
PR 168, who is on the Exoscale KMS team, says a plugin in
`openbao-plugins` will follow the merge of PR 168, which was open and
awaiting maintainer review on 2026-11-24.
Move to that plugin when it is available. The seal here stores the
upstream envelope unchanged. If the published plugin preserves the
envelope and can use your stanza, rehearse replacing the binary and its
pinned version and digest with the same seal name, KMS key and zone.
That replacement requires no seal migration. Use the migration
procedure below for a different seal or an earlier prototype with
a private envelope format. [PR author's reply](https://github.com/openbao/go-kms-wrapping/pull/168#issuecomment-7125989148)

The seal binary uses the upstream wrapper and its Exoscale Go SDK to avoid a
second envelope implementation. The state provider retains its small
standard-library EXO2 signing client. Its production binary links no
third-party modules. The SDK and JSON Schema validator support the provider's
tests.

## Build and verify

The root module requires Go 1.27.4, egoscale v3.1.65, wrapping v2.9.0,
and wrapping/plugin v2.4.0. The carried wrapper declares Go 1.25.0 and
egoscale v3.1.63. Go module version selection resolves egoscale v3.1.65.
The OpenBao plugin uses handshake protocol version 1 over gRPC. The OpenTofu
external provider protocol also uses version 1. Inspect the build with
`go version -m bin/openbao-plugin-kms-exoscale`.

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

## Upgrade from v0.2.0-rc.3 to v0.2.0-rc.4

Install the new OpenBao seal executable, update the plugin stanza to
`v0.2.0-rc.4` and pin its new SHA-256 from the verified release build.
Restart a standby node first. The OpenTofu key provider binary has the
same SHA-256 when built with the same Go patch release, target and
flags. Keep its current pin. Existing sealed data and OpenTofu state can
be read with the same keys and settings.

The seal accepts one optional slash after an explicit `/v2` endpoint
and sends requests to the same canonical path as the bare wrapper.
The new upstream 30-second deadline leaves the seal's five-second
attempts and 15-second call budget in effect. Option and environment
names, credential handling and proxy behavior carry forward from rc.3.
The conformance suite now checks the issuing zone when asserting
ciphertext lengths. That change affects test expectations only.
[PR author's reply](https://github.com/openbao/go-kms-wrapping/pull/168#issuecomment-7125989148)

## Configure the OpenBao seal

OpenBao 2.7 removed the built-in cloud seals. A KMS plugin must be configured
on disk because the server loads it while the store is sealed. Install the
verified executable in the real directory named by `plugin_directory`.
Keep this directory writable only by the operator.

```hcl
plugin_directory = "/opt/openbao/plugins"

plugin "kms" "exoscale" {
  command   = "openbao-plugin-kms-exoscale"
  version   = "v0.2.0-rc.4"
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
Exoscale KMS key usable for encryption and decryption (see `plugin_roundtrip`). Mount credential files
readable by the plugin process or inject environment variables. Keep literal
credentials out of HCL and deployment arguments.

| Seal option | Upstream environment name | Value |
| --- | --- | --- |
| `key_id` | `EXOSCALEKMS_KEY_ID` | KMS key UUID |
| `zone` | `EXOSCALEKMS_ZONE` | Zone hosting the key |
| `endpoint` | `EXOSCALEKMS_ENDPOINT` | Optional explicit HTTPS API base URL ending in `/v2` or `/v2/` |
| `api_key` | `EXOSCALE_API_KEY` | API key environment value or `file:///absolute/path` in HCL |
| `api_secret` | `EXOSCALE_API_SECRET` | API secret environment value or `file:///absolute/path` in HCL |

When the plugin client permits environment reads, a nonempty environment
value takes precedence after any configured reference resolves successfully.
Credential options support `env://VARIABLE` in this mode. This plugin also
resolves absolute `file://` references under `WithDisallowEnvVars(true)`.
The bare wrapper passes those references literally in that mode. The
plugin supports this configuration so credentials can stay in mounted
files when the caller forbids environment reads. A future bare-wrapper
binary needs to support file resolution in that mode before it can use
the same stanza. Both forms are exercised in `TestStanzaPortability`.
The plugin removes one trailing slash from `/v2/` so that the same
endpoint spelling works with the bare wrapper and the SDK receives
`/v2` before it appends the operation path. The plugin rejects double
slashes, escaped paths and any other endpoint path. Both servers use
the canonical endpoint in the loopback `TestStanzaPortability` test.

The plugin rejects unresolved credential references. An overridden file
reference still needs to designate a readable regular file of at most
8 KiB. The plugin leaves its bytes unread, so a trailing newline is
harmless when the environment supplies the credential.
`TestStanzaPortability` checks the precedence and rejection cases.

When a file supplies the credential, it must hold the exact nonempty
value, up to 8 KiB, with no surrounding whitespace or trailing newline
(write it with `printf '%s'`). The upstream wrapper reads file contents
without trimming.
OpenBao starts the plugin as a child process. Use the `env` parameter of the
`plugin` stanza for non-secret values and mount credential files for the
plugin. Entries in `env` are configuration literals. Verify environment
forwarding in your deployment if you inject credentials through the parent
environment. [OpenBao plugin configuration](https://openbao.org/docs/configuration/plugins/)

The plugin connects directly to `https://api-ZONE.exoscale.com/v2` unless its
environment selects a proxy. See [HTTPS proxy](#https-proxy) for supported proxies.
For direct connections, allow outbound HTTPS to `api-ch-gva-2.exoscale.com:443`
for `ch-gva-2` or to `api-ch-dk-2.exoscale.com:443` for `ch-dk-2`. With an
explicit endpoint, allow its configured HTTPS destination.
The bare upstream wrapper discovers the zone
through `ListZones` at `api-ch-gva-2.exoscale.com:443` when given only a zone.
This binary supplies the zone endpoint and skips discovery. Set `endpoint`
explicitly, as in the example, so that a future upstream plugin binary using
the same stanza also skips discovery and targets that host. Startup makes a
signed `GetKmsKey` call to that endpoint, exercised by `plugin_roundtrip`.
[OpenBao seal configuration](https://openbao.org/docs/configuration/seal/)

### Upgrading from v0.1.x

v0.2.0-rc.4 accepts the single trailing slash that v0.1.x normalized.
Since v0.2.0-rc.1, the plugin refuses unresolved `file://` or `env://`
credential references even when `EXOSCALE_API_KEY` or
`EXOSCALE_API_SECRET` supplies a value. Fix or remove unresolved
references on every node before replacing the binary. Update `version`
and `sha256sum` in the plugin stanza and restart a standby node first.
Follow the migration procedure below if the older executable used the
private envelope format.

Diagnostics now end with a fixed problem URI or `(unclassified)`, for
example `Exoscale KMS decrypt: HTTP 400 (#/kms-key/key-disabled)` or
`Exoscale KMS configure: HTTP 400 (#/kms-key/not-found)`. Earlier releases
printed phrases such as `(key disabled)` and `(key not found)`, or ended at
the status. Update log alerts that match the old text. See `disabled`,
`unknown_key` in the plugin test and `refused_credential`.

### IAM

Use independent API credentials and default-deny policies. The seal
calls `get-kms-key`, `encrypt` and `decrypt` (`plugin_roundtrip`).
The provider calls `generate-data-key` and `decrypt`
(`provider_roundtrip`). Scope those operations to the respective UUID
and grant only decrypt on retired UUIDs needed for backups or migration.
The role design and policy grammar are unmeasured. The separate
`least_privilege` subtests check selected allow/deny behavior with a
credential the operator has already scoped.
[Exoscale IAM policy guide](https://community.exoscale.com/product/security/iam/how-to/policy-guide/#key-management-service-kms)

### Rehearsed seal migrations

The operator rehearsed the four directions below on a single-node
OpenBao 2.7.2 raft store, with one share, outside the suite. See
`scripts/e2e-openbao.sh`. Cluster migration is unmeasured here. For HA, follow the OpenBao procedure and preserve
quorum. Back up storage and verify recovery access before changing the seal.
Retain credentials and key access needed for old backups.
[OpenBao seal migration](https://openbao.org/docs/concepts/seal/#seal-migration)

Use the plugin registration and active `seal "exoscale"` stanza above.
For an exoscale seal being retired, use this full stanza with the same
key, zone, and credential files.

```hcl
seal "exoscale" {
  disabled   = "true"
  key_id     = "<Exoscale KMS key UUID>"
  zone       = "ch-gva-2"
  endpoint   = "https://api-ch-gva-2.exoscale.com/v2"
  api_key    = "file:///etc/openbao/exoscale/api-key"
  api_secret = "file:///etc/openbao/exoscale/api-secret"
}
```

The rehearsal used the built-in static seal as its second auto-unseal
seal. Keep the same static key file and identifier throughout migration.

```hcl
seal "static" {
  current_key_id = "static-rehearsal-key"
  current_key    = "file:///etc/openbao/static.key"
}
```

When retiring static, use:

```hcl
seal "static" {
  disabled       = "true"
  current_key_id = "static-rehearsal-key"
  current_key    = "file:///etc/openbao/static.key"
}
```

| Direction | Stanzas during migration | Stanzas for the clean restart |
| --- | --- | --- |
| Shamir to exoscale | Active exoscale and its plugin | Active exoscale and its plugin |
| Exoscale to static | Disabled exoscale and its plugin, active static | Active static |
| Static to exoscale | Disabled static, active exoscale and its plugin | Active exoscale and its plugin |
| Exoscale to Shamir | Disabled exoscale and its plugin | No seal or plugin stanza |

Stop the server before editing the configuration. Start it with the
migration stanzas and verify it is sealed with migration in progress.
Run `bao operator unseal -migrate` with the required existing Shamir
shares or auto-unseal recovery shares, using the interactive prompt.
Verify migration completed and read a probe secret. Restart with the
clean configuration in the last column. An auto-unseal destination
should come up unsealed. For Shamir, submit the shares with
`bao operator unseal`. Read the probe again in each case.

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

### Bind state keys to an encryption context

Set `EXOSCALEKMS_ENCRYPTION_CONTEXT` to a nonsecret name such as
`production-stack`. The provider sends its UTF-8 bytes to KMS as
`encryption-context` on key generation and decryption. The empty value
omits the field and keeps version 1 metadata and key derivation compatible
with this project's earlier release. The context is supplied by the
runner and stays out of stored metadata. The provider accepts up to
1024 UTF-8 bytes without Unicode control characters. The service's
context size limit is unmeasured. Use the same value on every
runner that reads the state. `provider_context` verifies that the same
name works and that removing, changing, or adding a name refuses existing
wrapped keys. The OpenBao seal has no service encryption-context option.

For existing context-free state, retain its old provider and method names
and any metadata alias. The example assumes both old names are `exoscale`.
Use distinct names for the new provider and method, and set the context
per command so both providers can run in the same OpenTofu process.

```hcl
terraform {
  encryption {
    key_provider "external" "exoscale" {
      command = ["/usr/bin/env", "EXOSCALEKMS_ENCRYPTION_CONTEXT=", "/usr/local/bin/tofu-keyprovider-exoscale-kms"]
    }

    key_provider "external" "exoscale_bound" {
      command = ["/usr/bin/env", "EXOSCALEKMS_ENCRYPTION_CONTEXT=production-stack", "/usr/local/bin/tofu-keyprovider-exoscale-kms"]
    }

    method "aes_gcm" "exoscale" {
      keys = key_provider.external.exoscale
    }

    method "aes_gcm" "exoscale_bound" {
      keys = key_provider.external.exoscale_bound
    }

    state {
      method   = method.aes_gcm.exoscale_bound
      enforced = true
      fallback {
        method = method.aes_gcm.exoscale
      }
    }

    plan {
      method   = method.aes_gcm.exoscale_bound
      enforced = true
      fallback {
        method = method.aes_gcm.exoscale
      }
    }
  }
}
```

Back up state, then run a reviewed operation that rewrites it. Verify the
new configuration can read state after removing the fallback. Regenerate
or expire old plans and keep the context-free configuration available for
backups that still need it. The fallback procedure follows OpenTofu's
documented rollover behavior. The live provider exchange covers both
configurations. A full OpenTofu state rewrite is unmeasured in this release.
[OpenTofu key and method rollover](https://opentofu.org/docs/v1.13/language/state/encryption/#key-and-method-rollover)

The provider bounds wrapped metadata at 32 KiB and KMS response bodies at
64 KiB. Each attempt has a 3-second default timeout, configurable with
`EXOSCALEKMS_TIMEOUT` up to 10 seconds. It retries one eligible transient
failure and respects caller cancellation. `EXOSCALEKMS_CA_FILE` adds
certificates to the system pool. For a deliberate old-key transition, list
permitted older UUIDs in `EXOSCALEKMS_ALLOWED_KEY_IDS` and retain their
decrypt permissions. The provider validates its stored metadata and key UUID
before requesting a decryption key.

## HTTPS proxy

Since v0.2.0-rc.2, the OpenTofu key provider has gained proxy support. The
OpenBao seal already used the proxy environment through its upstream SDK,
and its network behavior is unchanged. The seal imports the shared
`internal/kmsapi` package for validation. The provider's transport changes
modify that package and affect Go's build metadata and source line tables
in the seal executable. Verify and pin the new seal SHA-256 when installing
the v0.2.0-rc.3 binary.

Both binaries use `HTTPS_PROXY` (or `https_proxy`) for KMS HTTPS requests.
`NO_PROXY` (or `no_proxy`) bypasses the proxy for matching destinations.
Without a matching proxy setting, the connection is direct. Go uses
`HTTP_PROXY` and `http_proxy` for HTTP requests.

| Binary | `http://` CONNECT proxy | `https://` CONNECT proxy |
| --- | --- | --- |
| OpenTofu key provider | Supported for proxies without authentication. | Uses HTTP/1.1 for CONNECT and for the KMS request through the tunnel. This works with a proxy that also offers HTTP/2 when it accepts HTTP/1.1. |
| OpenBao seal plugin | Supported for proxies without authentication. | Works with a proxy that negotiates HTTP/1.1. The upstream SDK offers HTTP/2 to the proxy and then sends an HTTP/1.1 CONNECT, so the call fails closed if the proxy selects HTTP/2. With `GODEBUG=http2client=0` in the plugin environment the SDK offers only HTTP/1.1, and such a proxy works. |

For OpenTofu, supply the settings in the external key provider's process
environment. For OpenBao, use the plugin stanza's `env` parameter for
non-secret settings, such as `NO_PROXY` and proxy URLs without user
information. Entries in `env` are configuration literals. Inject a proxy
URL containing credentials through a deployment secret into the plugin's
process environment and verify that the launcher forwards it.
`GODEBUG=http2client=0` is a non-secret setting for `env`, for example
`env = ["GODEBUG=http2client=0"]`; add it to any existing `GODEBUG` value
with a comma. It turns off HTTP/2 only in the plugin's Go HTTP client. The
plugin's gRPC connection to OpenBao does not depend on it, and the KMS
service answered with HTTP/1.1 in measured requests that offered HTTP/2, so
the KMS exchange stays the same. `TestPluginHTTPSProxy` covers the three seal cases.

Use a supported `https://` proxy for proxy authentication. Go sends proxy
credentials in the CONNECT request's `Proxy-Authorization` header, which
travels in clear text over an `http://` proxy connection. A CONNECT proxy
sees the tunnel destination. The client verifies the KMS server certificate
through the tunnel. End-to-end TLS protects the KMS body, API credentials
and signature. Exempt KMS destinations from TLS inspection, since a
trusted TLS-inspecting proxy can read KMS requests and responses.
The provider's optional `EXOSCALEKMS_CA_FILE` adds certificates to system trust.
The existing attempt and call deadlines include the proxy connection,
CONNECT negotiation and TLS handshake. The seal's SDK redirect behavior is
described below.

## Failure behavior and limits

A persistent KMS failure prevents unseal or state-key retrieval. Neither
command substitutes a local key. The bare wrapper now applies a 30-second
deadline to client setup (including discovery when needed), Encrypt and
Decrypt. An earlier caller deadline or cancellation ends the call sooner.
The seal supplies a 15-second budget per configuration, encryption or
decryption call and at most five seconds per upstream attempt, so the
wrapper's 30-second deadline does not extend either plugin limit. The SDK
retries eligible connection errors and statuses within an attempt. When
an attempt reaches its own deadline, the plugin starts another within the
remaining operation budget. [PR author's reply](https://github.com/openbao/go-kms-wrapping/pull/168#issuecomment-7125989148) An encrypt retry can wrap a fresh
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
sends a 32-byte data key to KMS. The payload is encrypted locally.

An HTTP refusal reports the status and a fixed problem URI or the label
`unclassified`. The provider reads the wire type. The plugin reads the
typed HTTP 400 response exposed by egoscale. For other statuses egoscale
v3.1.65 does not expose a general problem type to the wrapper. Both
commands discard remote details, titles, messages and identifiers. The
PR author plans to address refusal reasons in egoscale, whose error text
would then carry the service's title and detail. The plugin builds its
errors from the status and problem type only and keeps discarding that
text; a bare-wrapper binary built on such an egoscale would log it. The
carried wrapper settles the review's single-slash handling and overall
deadline. Per-attempt time limits and the other
[published review notes](docs/upstream-review-pr168.md) remain open.
[PR author's reply](https://github.com/openbao/go-kms-wrapping/pull/168#issuecomment-7125989148)

`TestPluginRemoteErrors`, `TestPluginReportsInvalidWrappedKey` and
`TestRemoteProblemTypeAllowlist` cover these diagnostics.

### Operations

- **HTTP 400 with `#/kms-key/key-disabled`**. Check the key's management
  status. Enable a disabled key after confirming the change with the key
  owner. For pending deletion, cancel deletion, then enable the key.
  Cancellation leaves it disabled (`disabled`, `pending_deletion`,
  `cancel_deletion`).
- **HTTP 400 with `#/crypto/invalid-ciphertext`**. Confirm the stored
  key UUID and, for OpenTofu, the original context. Preserve the state
  or storage snapshot and investigate tampering or corruption.
  `random_ciphertext`, `tampered_ciphertext` and `encryption_context`
  check the complete type. A ciphertext of another key returned HTTP 400
  with an ERN mismatch (`ciphertext_of_another_key`). Its type is unmeasured.
- **HTTP 400 with `#/kms-key/not-found`**. Check the configured UUID and
  zone at startup, or the stored UUID and zone when decrypting. The
  metadata read, encrypt and decrypt calls returned this type
  (`unknown_key_metadata`, `unknown_key_encrypt`, `remote_refusals/unknown_key`).
  The plugin startup assertion is `TestLiveConformance/unknown_key`.
- **HTTP 403**. Verify that the intended credential is mounted and that
  it has access to the intended UUID. Restart OpenBao with the corrected
  credential. See `refused_credential` and the end-to-end rehearsal.
- **Rotation**. Keep the same UUID and verify that pre-rotation and new
  blobs decrypt. HTTP 400 with `#/kms-key/manual-rotation-limit` means the
  key has spent its ten manual rotations. The service still accepted
  encryption, decryption, data-key generation and re-encrypt on the
  enabled key at the limit. Send management operations to the origin.
  A rotate or schedule-deletion at a replica returned HTTP 400 with
  `#/kms-key/multi-zone/operation-not-allowed-on-a-replica`.
  Automatic rotation remains unmeasured.
- **Context deadline exceeded**. The seal's total call budget is about
  15 seconds. The zone may be unreachable, or it may return repeated
  HTTP 429 or 5xx responses that the SDK retries without surfacing the
  status. `TestPluginPersistentServerError` reproduces this against a
  local TLS fixture. The live seal behavior for repeated refusals is
  unmeasured. Check provider diagnostics or a raw conformance probe
  against the same zone to observe the HTTP status.
- **Request failed or invalid response** during seal decrypt. Preserve
  the storage snapshot and check whether the zone returns a valid unwrap
  response. Both a malformed response and a local envelope authentication
  failure produce this message because the wrapper supplies no typed
  distinction.
- **Zone unavailable**. Check DNS, connectivity and certificate trust.
  If that key has a ready replica with the same UUID, deliberately change
  the seal's `zone` and `endpoint` together, or change the provider's
  `EXOSCALE_ZONE`. Verify decrypt and local recovery before treating the
  replica as active. Both paths use one endpoint at a time. Two-way decrypt
  was observed (`replica`, `plugin_replica`), including after rotation
  (`post_rotation_replica`). Failover during an
  outage and worst-case synchronization lag are unmeasured.

## Measured service behavior

The operator measured the service on 2026-11-21, 2026-11-22 and
2026-11-24 in `ch-gva-2` and `ch-dk-2`. On November 22 in
`ch-gva-2`, encrypting
1, 32 and 1024 plaintext bytes on a newly created key added 191
ciphertext bytes at each material version from 1 through 9 and 192 at
versions 10 and 11. The configured test key also added 192 bytes at
version 10. Larger plaintexts were outside this overhead sampling. The
suite applies the same overhead to its larger accepted test sizes.
The header contains a printable run that can end in the decimal material
version. Adjacent printable bytes sometimes extended the run, so the
tests use material metadata where available. The sixth-edition raw API
runs at version 11 also passed the 192-byte overhead checks at the larger
asserted sizes of 4096, 65536 and 262144 bytes. The ciphertext at the
other accepted payload sizes was checked for presence.

### Ciphertext length policy

On November 24 a multi-zone key at version 1 added 191 bytes when
encrypting in `ch-gva-2` and 190 in `ch-dk-2` for plaintexts of
1, 32 and 1024 bytes. Both zones decrypted the other zone's output
using the same UUID. The cause of the length difference is unmeasured.

Version-aware tests and the offline fake use the following overheads.

| Issuing zone | Versions 1–9 | Versions 10–99 |
| --- | ---: | ---: |
| `ch-gva-2` | 191 | 192 |
| `ch-dk-2` | 190 | 191 |

The two-digit rule in `ch-gva-2` was measured at 10 and 11 and
extrapolated through 99. For `ch-dk-2`, the model applies the
one-byte difference measured at version 1 throughout the same range.
Other zones use the `ch-gva-2` baseline pending measurements. A
missing or invalid required version fails the check. The suite and
fake stop at versions above 99. Tests with no material metadata
use the two lengths for the issuing zone, including the provider-only
IAM path and the replica round trips. For seal tests, a standard API
endpoint identifies the issuing zone. Set the zone to match the
destination whenever using a custom endpoint. Both production
commands treat wrapped ciphertext as opaque.

The table names the live assertions. Timings are observations without a
latency target.

| Observation | Live subtest |
| --- | --- |
| The fixture adds 103 bytes to the wrapped key. At material version 1 this gives a 326-byte seal envelope in `ch-gva-2` and a 325-byte envelope with the `ch-dk-2` overhead. The suite checks the issuing zone's wrapped length and protobuf length, then decrypts the fixture. | `plugin_roundtrip` |
| OpenTofu recovered a prior 32-byte derived key and generated a fresh one. The test accepts the two wrap lengths for the issuing zone and uses generation and decrypt permissions. | `provider_roundtrip` |
| Correct context decrypts. An absent, different or newly added context returned HTTP 400 with `#/crypto/invalid-ciphertext`. The raw absent and different samples captured title `Invalid ciphertext`. The provider also tested the mismatch directions using context on generate-data-key. | `encryption_context/{same,absent,different,added}`, `provider_context` |
| AES-256 returned 32 bytes. Counts of 1, 64 and 1024 returned the requested size. For measured material versions, wrapped lengths use the overhead above. Both or neither selector returned HTTP 400 with `#/http-problem-types/request-invalid-parameters` and title `Invalid argument`; counts 0 and 1025 returned the same type with title `Invalid Request`. | `generate_data_key/{aes_256,one_byte,64_bytes,1024_bytes,both,neither,too_small,too_large}` |
| Encrypt tests assert the overhead for measured material versions. Repeat encryptions shared a nine-byte prefix. The largest accepted plaintext tested was 524288 bytes (512 KiB), and the smallest refused was 786432 bytes (768 KiB). All three sixth-edition runs and all four seventh-edition runs verified HTTP 500, an absent Content-Type header and exactly the 12-byte body `server error` at 786432 bytes. Response framing is unmeasured. The subtest logs only fixed response fields. The exact boundary between 524288 and 786432 bytes and the behavior at intervening sizes are unmeasured. | `ciphertext_shape`, `payload_bound` |
| Manual rotation advanced version and manual count by one. Ciphertexts and plugin blobs from before and after rotation decrypted, and the old ciphertext re-encrypted under the same UUID. The test checks all lengths against their versions. | `rotation`, `plugin_blobs_after_rotation` |
| On both the earlier multi-zone key and a newly created single-zone key, the eleventh manual rotation returned HTTP 400 at manual count 10 and material version 11, with `#/kms-key/manual-rotation-limit` and title `Maximum rotation limit exceeded`. The November 21 OpenAPI description specifies ten manual rotations per key. | `rotation/manual_rotation_limit` |
| One newly created multi-zone key started enabled at version 1 and count 0. Replicate at the origin returned HTTP 200. The original ciphertext decrypted at the replica. Rotate and schedule-deletion at the replica each returned HTTP 400 with `#/kms-key/multi-zone/operation-not-allowed-on-a-replica`. The origin rotated to version 2 and count 1. A fresh ciphertext decrypted at the replica on the first attempt, and replica metadata showed version 2 and count 1. In the earlier probe the replica showed pending deletion on the second poll, then refused encrypt with `#/kms-key/key-disabled`. All three seventh-edition multi-zone runs confirmed pending deletion and the seven-day plan from the origin readback, then pending deletion and HTTP 400 for encrypt at the replica. | `rotation/replica_refusals`, `rotation/post_rotation_replica`, replica cleanup |
| The same UUID decrypted both directions across zones. The test checks the ciphertext length for each issuing zone and, for the plugin, the extra 103 bytes in the seal fixture. | `replica`, `plugin_replica` |
| Same-key and cross-key re-encrypt succeeded. Decrypt under the wrong key returned HTTP 400 with an ERN mismatch. Its exact type, title and content type are unmeasured. | `same_key_reencrypt`, `different_key_reencrypt`, `ciphertext_of_another_key` |
| A single-zone key refused replication with HTTP 400 and `#/kms-key/multi-zone/key-is-not-multi-zone`. The full header shape of that refusal is unmeasured. | `single_zone_replication` |
| Disabled keys, keys pending deletion and cancelled-but-disabled keys refused encrypt, decrypt and generate-data-key with HTTP 400, `#/kms-key/key-disabled`, title `Key is disabled`. Enable restored decrypt. Six days was refused and seven accepted for deletion. The full six-day refusal shape is unmeasured. | `disabled`, `enabled_again`, `pending_deletion`, `cancel_deletion` |
| Unknown UUID metadata, encrypt and decrypt returned HTTP 400, `#/kms-key/not-found`, title `Key not found`. Malformed UUID metadata and decrypt returned HTTP 400 with a JSON message and field errors. | `remote_refusals/{unknown_key_metadata,unknown_key_encrypt,unknown_key,malformed_key_metadata,malformed_key_id}` |
| Random bytes and a flipped ciphertext bit returned HTTP 400, `#/crypto/invalid-ciphertext`, title `Invalid ciphertext`. Non-base64 returned HTTP 400, `#/http-problem-types/request-invalid-parameters`, title `Invalid Request`. | `remote_refusals/{random_ciphertext,tampered_ciphertext,non_base64_ciphertext}` |
| Wrong-secret metadata and encrypt returned HTTP 403 with JSON message `Invalid request signature`. An unknown API key in EXO format paired with a wrong secret returned HTTP 403 with message `Invalid key or request signature`. Wrong-secret decrypt returned HTTP 403. Its body is unmeasured. | `remote_refusals/{refused_signature_metadata_and_encrypt,unknown_api_key_metadata,refused_credential}` |
| 32 paced decrypt requests in about four seconds returned no HTTP 429. Service quota is unmeasured. | `paced_requests` |
| The vendor description that day exposed one usage, encrypt-decrypt, and one symmetric key type, AES-256. It exposed no signing operation or algorithm selection. Live absence of additional capabilities is unmeasured. | Operator inspection outside the suite |

`bare_wrapper` also decrypts a serialized plugin blob against the live
service. The offline cross-read covers both directions.

### Live run record

These rounds ran on earlier test suites and the published v0.2.0-rc.1 tree using the current plaintext
ceiling. The dates and times are UTC+01:00. All-switch rounds used
replica, rotation, disposable and rate probes. Least-privilege checks
were outside these rounds.

| Run | Start | Outcome | Interruptions |
| --- | --- | --- | --- |
| 5-1 | November 21, about 22:11 | Provider passed. Plugin rotation and raw generation with neither selector failed. | Two incomplete replies (HTTP 200 and 400). |
| Plain 1 | November 21, about 22:19 | All passed. | One unanswered first attempt. |
| Plain 2 | November 21, same series | All passed. | None recorded. |
| Plain 3 | November 21, about 22:19 | All passed. | One unanswered first attempt. |
| Plain 4 | November 21, same series | All passed. | None recorded. |
| Plain 5 | November 21, same series | All passed. | None recorded. |
| Plain 6 | November 21, same series | All passed. | None recorded. |
| 6-1 | November 22, 00:06 | All 55 tests and subtests passed. | None recorded. |
| 6-2 | November 22, 00:06 | All 55 passed. | None recorded. |
| 6-3 | November 22, 00:06 | All 55 passed. | None recorded. |
| 7-1 | November 22, 01:16 | Plugin passed and advanced the key to version 10. Provider and raw API failed the old fixed-length checks. | None recorded. |
| 7-2 | November 22, 01:16 | Plugin, provider and raw API failed the old fixed-length checks. | None recorded. |
| 7-3 | November 22, 01:17 | Plugin, provider and raw API failed the old fixed-length checks. | None recorded. |
| 8-1 | November 22, 02:56 | All 55 passed. Plugin entered at version 10 and spent the tenth manual rotation, advancing the key to version 11. | None recorded. |
| 8-2 | November 22, 02:56 | Provider and raw API passed. Only plugin rotation failed, on the manual-limit HTTP 400. | None recorded. |
| 8-3 | November 22, 02:57 | Provider and raw API passed. Only plugin rotation failed, on the manual-limit HTTP 400. | None recorded. |
| 9-1 | November 22, 06:23 | All 58 test and subtest entries passed, with rotation, disposable lifecycle, paced requests and a replica zone. | None recorded. |
| 9-2 | November 22, 06:24 | All 58 passed, with rotation, disposable lifecycle, paced requests and a replica zone. | None recorded. |
| 9-3 | November 22, 06:24 | All 58 passed, with rotation, disposable lifecycle, paced requests and a replica zone. | None recorded. |
| 9 single-zone | November 22, 06:24 | All 52 entries across the three packages passed, with rotation and disposable probes and no replica zone. | None recorded. |

Seventeen of the twenty rounds recorded no unanswered or incomplete
reply, including all thirteen November 22 rounds. The 7-series stopped
before the refused-size check. The 8-series completed it and recorded
a 192-byte overhead, a 224-byte wrapped key and a 327-byte seal blob.
The times in entries without a preserved transcript come from the
operator's summary of the plain series.

The November 22 rc.3 run passed all 58 entries on the former bench at
material version 11. On November 24 the rc.3 and wrapper-repin trees
each passed 41 entries on the new version-1 bench with the origin only.
With the replica enabled, cross-zone decrypts worked in the raw API
and the replica plugin decrypted the origin blob. Both trees then
failed the same two old length checks for ciphertext issued in
`ch-dk-2`. The updated checks were verified offline against the
two-zone fake. A live run of this release candidate is pending.

In the multi-zone disposable sample, replica decrypt took 103 ms before
rotation and 92 ms afterward. On the configured key, the earlier suites'
post-rotation replica decrypt, which waits 200 ms before its first
attempt, succeeded at the first attempt in four runs (355 to 372 ms) and
at the second attempt in two (570 ms on November 21, 679 ms on
November 22). In the earlier disposable sample, the replica reported pending deletion
on the second poll, about half a second later. In each seventh-edition
multi-zone run, the created key passed replication readiness, manual
rotation history, re-encryption and plugin blob checks. Replica decrypt
succeeded on the first attempt before and after rotation (298–307 ms
and 366–381 ms respectively). Origin cleanup confirmed the seven-day
plan from the deletion timestamp. The replica reported pending deletion
and refused encryption. The replica refusals' Problem Details status
member remains unmeasured.

The restricted-role probes run separately from the lifecycle probes.

The seventh-edition single-zone run confirmed the eleventh rotation
refusal at material version 11 and manual count 10. Crypto operations
still worked and cleanup confirmed deletion was scheduled. The
configured key had the same revision, material version 11 and manual
count 10 before and after the four runs. Worst-case lag, automatic rotation, a third
zone, multi-zone deletion cancellation and origin emission of the new
width at a multi-zone digit boundary remain unmeasured. So do the
service quota, exact payload boundary and framing of the refused-size
response.

### Unanswered and incomplete responses

The suite's largest request is 786432 plaintext bytes, the smallest
refused size in the table above. The account holder reports the
details of what preceded unanswered requests privately to Exoscale.
The request size, sequence and per-trial counts are omitted from
public documentation. The observed interruptions remain
unexplained, including the earliest isolated misses and the incomplete
replies in run 5-1. The cause and the effects for other credentials
and source addresses remain unmeasured.

The raw probe records `KMS unanswered_requests count=N limit=4` before
any response bytes, and `KMS incomplete_responses count=N limit=4` when
a response starts but times out or ends early. Both increment one counter.
A fifth interruption fails the suite. The probe can try a read, encrypt,
decrypt, data-key generation or re-encrypt once more within the allowance.
A complete response, including a refusal, ends the transport attempt.
The replica readiness subtest separately samples decryptability after
rotation, and the paced subtest makes its prescribed set of calls.

After an unanswered or incomplete mutation the suite reads back the key
or lists the disposable name. A confirmed effect resolves the attempt.
Lifecycle probes end the attempt after an incomplete response and use readback to check its effect. An
unanswered mutation may be resent once after two unchanged snapshots
only if the transport never obtained a connection. An unchanged snapshot
cannot rule out a late write on an established connection. The published
API description gives no idempotency key or write fence for these
operations.

Final cleanup reads back the disposable key and verifies pending deletion.
It starts with seven days and, if the key still reads as enabled, moves
to the next unused delay in the documented 7 to 30 day range. Enable and
cancel-deletion each have a single request form. Cleanup may send either
one again after a fresh readback confirms the transition is still needed,
including after a complete refusal or an incomplete response. Each
transition gets at most two cleanup attempts. If the 75-second cleanup
budget expires or pending deletion cannot be verified, the suite fails
and asks the operator to reconcile the disposable key. The initial log
reports `first_cleanup_plan_days`. The later `KMS disposable_cleanup
status=pending-deletion` line reports the verified `delay_days`.

The seal starts a new five-second attempt after each stalled one while its
15-second call budget lasts. It makes up to three attempts and can recover
after two stalls if the third attempt finishes within the budget. Earlier
caller cancellation still applies (`TestPluginRecoversStalledAttempt` covers
recovery after one stall). The state provider makes one retry after an attempt
timeout, using its configured HTTP timeout (default three seconds) and
respecting its caller's deadline (`TestTransportDiagnostics`).
If no attempt yields a usable answer, the caller gets an error.
Live timeout recovery by either path is unmeasured.

## Tests

With the module cache populated as above, run the local tests with
`GOPROXY=off`. The KMS integration suite uses loopback TLS and the upstream
plugin test harness. Run the unchanged wrapper tests from the root module
so they use the pinned dependency graph.

The offline fake-backed provider and KMS client suites clear inherited proxy variables unless
`EXOSCALEKMS_LIVE=1`, so a proxy in the test environment does not reach the
loopback fakes. The raw API client of the live suites connects directly and
ignores proxy variables, so run `TestLiveAPIConformance` and the rotation and
disposable switches where the KMS endpoints are directly reachable.

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

Without optional switches the suites perform data-plane requests and
read metadata. The following switches opt into additional probes.

- `EXOSCALEKMS_LIVE_REPLICA_ZONE` names a ready replica of the configured
  key for read-only interoperability probes. With rotation enabled it
  also selects the destination for a newly created multi-zone key.
- `EXOSCALEKMS_LIVE_ROTATE=1` gives the plugin test a disposable key in the
  configured origin zone. With a replica zone it creates one multi-zone
  key, replicates it, performs one successful manual rotation at the
  origin, and verifies both refusal responses at the replica. Without
  a replica zone it creates one single-zone key and spends ten manual
  rotations on that key to check the eleventh refusal and continuing
  crypto operations. Cleanup schedules deletion at the origin and
  checks pending deletion. When replication was confirmed, the suite
  also checks the replica. Earlier pre-releases spent a manual rotation
  of the configured key each time the rotation probe ran. The configured
  key now serves only the read and data-plane probes, including when
  its manual count is at the limit.
- `EXOSCALEKMS_LIVE_DISPOSABLE=1` gives the raw API suite a separate
  single-zone key for re-encrypt and lifecycle probes. It spends zero
  rotations and verifies pending deletion after the probes.
- Run either lifecycle switch with a separate test credential. Give it
  permission to list and create KMS keys, use the configured test key,
  and read the keys it creates. The rotation switch also reads their
  rotation history and exercises encrypt, decrypt, re-encrypt, rotate,
  replicate and schedule-deletion. The disposable switch exercises encrypt,
  decrypt, re-encrypt, replicate, disable, enable, schedule-deletion and
  cancel-deletion. Keep these permissions separate from the seal and
  state roles.
- Leave at least three minutes before the Go test deadline for either
  lifecycle switch. If the process is killed or reports a cleanup
  failure, reconcile the exact `KMS disposable_name` in the test account
  and origin zone. Confirm that the disposable key belongs to the run,
  then confirm scheduled deletion. For the single-zone lifecycle key
  enable it first if it is disabled. Keep the configured key outside
  this cleanup.
- The raw live suite rejects the retired `EXOSCALEKMS_LIVE_OTHER_KEY_ID`
  and `EXOSCALEKMS_LIVE_DISABLED_KEY_ID` from v0.1 when either variable
  is set. Unset both and use the disposable switch for those probes.
- `EXOSCALEKMS_LIVE_RATE_PROBE=1` runs the bounded paced sample.
- `EXOSCALEKMS_LIVE_LEAST_PRIVILEGE=1` opts into restricted-role checks.
  Run the raw API suite with the seal role and the provider suite with
  the state role. The probe does not attempt lifecycle writes with a
  credential being checked for least privilege.

In the 2026-11-22 operator rehearsal on OpenBao 2.7.2 against live KMS,
all eight stages passed in 38 seconds with a known key. These included initialization,
auto-unseal after restart, wrong-credential refusal with the fixed
`Exoscale KMS configure: HTTP 403 (unclassified)` diagnostic, recovery
after restoring credentials and all four migration directions. With an
unknown key UUID, the script failed at initialization and reported
`Exoscale KMS configure: HTTP 400 (#/kms-key/not-found)`. Linux startup
log framing and behavior on a multi-node cluster remain unmeasured.

To rehearse the two restart scenarios and four migration directions on a
scratch OpenBao 2.7.2 server:

```sh
bash scripts/e2e-openbao.sh /path/to/bao "$EXOSCALEKMS_KEY_ID" "$EXOSCALEKMS_ZONE" \
  "$EXOSCALEKMS_API_KEY_FILE" "$EXOSCALEKMS_API_SECRET_FILE" \
  /path/to/openbao-plugin-kms-exoscale
```

The last argument is optional. Omit it to build the plugin using the Go
toolchain on PATH. The script needs Bash, Python 3.11 or later and OpenSSL.
It uses a test key and local raft storage, with TLS on loopback. On exit
it stops the scratch server and deletes the scratch directory. It waits
for two default `sys/health` HTTP 200 responses at least 300 ms apart before
probe writes and reads. The plain-unseal trace measured health and mount
writes. Health during post-migration transitions remains unmeasured.
Failures report the stage, safe seal-status fields, an HTTP status if
available, the fixed plugin diagnostic on a seal configuration error,
and recent warning and error events with free text removed.
The diagnostic and configuration paths also have offline coverage in
`scripts/test-e2e-openbao.py`.

This project is distributed under the Mozilla Public License 2.0. The
carried module retains its original notices and [provenance](third_party/exoscalekms/README.md).
See the [security policy](SECURITY.md) for private vulnerability reporting.
