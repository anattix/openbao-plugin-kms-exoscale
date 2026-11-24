<!-- SPDX-License-Identifier: MPL-2.0 -->

# Review notes for Exoscale KMS wrapper PR 168

These notes were written while building and testing this repository on
[OpenBao wrapper PR 168](https://github.com/openbao/go-kms-wrapping/pull/168).
They are offered to the authors and maintainers of that wrapper. The
evidence file names below refer to our measurement records, which are not
part of this repository; ask and we will share the ones you need. The
record of what preceded the unanswered requests is reported to Exoscale
support and is not published here.

The review started at `cde32eb9b902bae1d97b3ef2b8b92e00d9c47f4e` and was updated
for head `aad18865db438363ffd9927dda970ce3bbd952fb` on 2026-11-24. PR 168 was
open and awaiting maintainer review. The author addressed the single
trailing slash and added the 30-second overall deadline. A separate
attempt budget is open, as are the other items in the table. The author
said that refusal reasons will be addressed in egoscale and that an
Exoscale KMS plugin in `openbao-plugins` will follow the merge. This
repository's seal plugin is interim.
[Upstream author's reply](https://github.com/openbao/go-kms-wrapping/pull/168#issuecomment-7125989148)
Wrapper paths are relative to `wrappers/exoscalekms`. SDK references are
to egoscale v3.1.65, the version selected for this integration. The PR's
module declares v3.1.63. Service observations are from 2026-11-21, 2026-11-22 and 2026-11-24.

| Location | Finding and proposed upstream change |
| --- | --- |
| `exoscalekms.go:97–127,142–164,179–200` | The head adds a 30-second total deadline; an earlier caller deadline still wins. Add a shorter per-attempt limit that includes body reads and leaves time for retries. Test stalled GetKmsKey, Encrypt and Decrypt and cancellation during I/O. |
| `exoscalekms.go:97–119`, SDK `client.go:45–65,197–210` | Add a wrapper constructor option accepting an `*http.Client` and pass it via `ClientOptWithHTTPClient`. Validate HTTPS endpoints, retain certificate and hostname verification, add optional CA certificates to system roots, and refuse redirects with `http.ErrUseLastResponse`. This lets integrations enforce the same origin on every request without changing the envelope. Keep `http.ProxyFromEnvironment` on the transport. The current SDK already uses it through `go-cleanhttp` v0.5.2. Test CONNECT with end-to-end certificate and hostname verification, `NO_PROXY` direct routing, and fixed errors when CONNECT fails. Have a verified HTTPS fake return a 307 to a loopback HTTP listener. Assert one HTTPS request, zero HTTP requests, and a configuration error. |
| `exoscalekms.go:97–119`, SDK `client.go:58–60,197–210`, go-cleanhttp v0.5.2 `cleanhttp.go:23–38` | With Go 1.27.4, the SDK transport can negotiate HTTP/2 on a TLS connection to an `https://` proxy and then write an HTTP/1.1 CONNECT. A proxy that selects HTTP/2 rejects that exchange. Determine the route with `http.ProxyFromEnvironment`, including its bypass rules. For an `https://` proxy, use a transport that offers HTTP/1.1 for CONNECT while retaining verification of the proxy and KMS certificates. Test an HTTPS proxy that offers both protocols, an untrusted proxy, and a matching `NO_PROXY` direct route. |
| `exoscalekms.go:112–127`, SDK `client.go:80–124` | Zone-only configuration uses ListZones at the SDK default API endpoint and a signed GetKmsKey in the selected zone. Document the destination and SDK's conditional signed discovery retry. An explicit endpoint skips discovery. Document the observed startup and crypto calls for IAM scoping. Least-privilege policy syntax and the discovery role are unmeasured. |
| `exoscalekms.go:83–84,104–106`, SDK `operations.go` GetKmsKey | Resolved for a single slash. The head normalizes `/v2/` to `/v2` before the SDK appends the operation path, and the carried unit test checks the metadata. The integration also tests both spellings on a loopback KMS. Reject doubled or escaped slashes if endpoint validation is added; the live service's response to a doubled slash is unmeasured. |
| `exoscalekms.go:121–124` | Validate the metadata object from startup GetKmsKey, including ID, usage, and enabled state. Require valid symmetric key metadata when exposed by the API version in use. A key can change state after startup, so return a typed error when a crypto call reports disabled. |
| `exoscalekms.go:71–127` | Repeat configuration updates fields while the old client can remain active. Construct and validate a new client and publish the new settings together, or reject reconfiguration of an initialized wrapper. Test retry after a failed configuration and a second configuration with different routing. |
| `exoscalekms.go:77–95,191–198` | Validate both configured UUIDs and nonempty stored UUIDs before interpolating them into paths. Document that a stored UUID selects the decryption key. Preserve the existing fallback for old blobs with an empty stored UUID and describe scoped permissions for retired UUIDs used by backups. |
| `exoscalekms.go:114–124,162–164,198–200`, SDK `errors.go:100–121,131–202` | The KMS SDK endpoints expose an `*ErrorResponse` for declared HTTP 400 responses and its RFC 9457 `Type`. The generic `APIError` decoder retains the raw body privately and exposes status, title and detail, with no generic type field. The author plans to address refusal reasons in egoscale. In egoscale decode the JSON field `type` into a string in the decoder's temporary struct and expose `Type string` on `APIError`. Populate it before status-specific decoding. In the wrapper map exact known types plus HTTP status to a typed, safe diagnostic, with a neutral label for an absent or unknown type. Preserve cancellation and deadline causes and omit response text from the public error chain. Test a declared 400, an undeclared 403 and a spoofed title or type. |
| `exoscalekms.go:162–174,198–211`, SDK `api.go:193–204`, `errors.go:136–159` | SDK success and error decoders read response bodies before the wrapper can bound them. Apply a bounded reader with overflow detection to both paths and require HTTP 200 for these KMS responses. On success require a nonempty wrapped key and a 32-byte DEK. Reject successful but empty or malformed replies and retain the existing wire fields. |
| `exoscalekms.go:142–174,179–211` | Add an optional service encryption context to the wrapper and pass the same bytes on KMS Encrypt and Decrypt. Leave it absent by default, keep it outside the serialized envelope and keep it distinct from the application AAD on the local GCM envelope. The live API rejected an absent, different or newly added context with HTTP 400 and title `Invalid ciphertext`. The new raw capture shows the complete `#/crypto/invalid-ciphertext` type for absent and different contexts. The provider also observed that type when adding a context to previously unbound data. Test the default cross-read, correct context and all three mismatch directions. |
| `exoscalekms.go:195–211`, wrapping core `envelope.go:63–87` | Distinguish local AES-GCM authentication failure from a remote refusal using a typed error such as `ErrEnvelopeAuth`. Test changed local ciphertext and wrong local AAD with one remote decrypt call and zero returned plaintext. |
| `exoscalekms.go:151–174,198–211` | Clear owned scratch DEK buffers after their last use. Keep HTTP tracing disabled for KMS calls and finish authentication before returning decrypted payloads. |
| `options.go:25–43`, `exoscalekms.go:218–225` | A disallow-environment option currently skips file-path resolution too. Allow bounded reads of absolute `file://` credentials independently of the environment policy. Define reference validation and override precedence, reject surrounding whitespace with a safe diagnostic, and keep resolved values out of metadata and errors. Test file references under disallow, missing files alongside environment values, and trailing newlines in both selected and overridden files. |
| SDK `client.go:58–60,197–210`, retryablehttp v0.7.8 `client.go:829–846` | The SDK retries HTTP 429 and most 5xx responses and discards the final response after retry exhaustion. A shorter caller deadline can expire during retries and has no response to classify. Use `retryablehttp.PassthroughErrorHandler` with a retry policy bounded below the caller deadline, or allow a caller-supplied `*http.Client` via `ClientOptWithHTTPClient`. With 429 and 503 fixtures, assert that Encrypt returns an `APIError` with the last status before the deadline, without surfacing response text. |
| `exoscalekms.go:198–211`, SDK `api.go:193–205` | A truncated or malformed success response may return a read or decode error without either a `*url.Error` or an `APIError`. The absence of those two types cannot identify local envelope failure. Keep the typed envelope error proposal above and test both failure stages. |

## Live evidence relevant to the wrapper

- The seal wrote 325–326 byte envelopes with 222–223 byte wrapped DEKs
  in earlier runs. The origin and a ready replica decrypted each other's
  samples using the same UUID. On November 21, post-rotation replica
  decrypt succeeded at about 0.2 s on attempt 1 and 0.570 s on attempt 2.
  On November 22 it succeeded at 0.359 s, 0.355 s and 0.358 s on attempt 1,
  and at 0.679 s on attempt 2. The sixth-edition all-switch run added a
  first-attempt success at 0.372 s. At `exoscalekms.go:167–174,191–211`,
  preserve the UUID and opaque KMS ciphertext in stored envelopes. Test
  reads in both directions and decrypt of old and new blobs after rotating
  across the version 9 to 10 boundary. Worst-case lag and automatic
  rotation are unmeasured.
- The service returned HTTP 400 and `#/kms-key/key-disabled` with title
  `Key is disabled` for disabled crypto operations and for decrypt during
  pending deletion. Cancelling deletion left the key disabled. Invalid
  ciphertext returned HTTP 400 and `#/crypto/invalid-ciphertext`. A wrong
  secret returned HTTP 403. The guard's typed HTTP 400 path makes the
  first two distinctions available without exposing the response body.
  Keep the exact types and HTTP status in the wrapper's diagnostics.
- On November 22, the operator encrypted 1, 32 and 1024 bytes at each
  version from 1 through 11 on a new key. The overhead was 191 bytes at
  versions 1–9 and 192 bytes at versions 10–11. The configured test key at
  version 10 also had 192 bytes of overhead. A printable header run can end
  in the decimal version, with adjacent printable bytes sometimes extending
  the run. Versions 12 through 99 were outside the sample. The suite
  extrapolates the two-digit overhead to them. Versions of three or more
  digits are unmeasured. Later raw API runs confirmed 192 bytes at material
  version 11 for 4096, 65536 and 262144 plaintext bytes. The captures also leave the immediate origin
  overhead after a digit-boundary rotation open. On November 24 at
  material version 1, the same multi-zone key added 191 bytes in
  `ch-gva-2` and 190 in `ch-dk-2` for 1, 32 and 1024 plaintext bytes.
  Both zones could decrypt the other's output. The wrapper repin kept
  the origin's 326-byte seal blob and 223-byte wrapped key. At
  `exoscalekms.go:148–175,185–211`, keep ciphertext opaque and test both
  issuing zones and both sides of the version-width boundary. The
  November 24 records are `kms-zone-overhead-probe-run-1.txt`,
  `live-run-12-{control,repin}.txt` and the origin-only
  `live-run-13-{control,repin}-origin-only.txt`. The largest
  plaintext accepted in the suite was 524288 bytes and the smallest refused
  was 786432 bytes. Three live runs on 2026-11-22 measured the same complete
  refusal at 786432 bytes. The sixth-edition runs confirmed HTTP 500 with
  an absent Content-Type header and exactly 12 bytes, `server error`.
  The response framing at this size is unmeasured. The November 21 OpenAPI snapshot lists
  HTTP 200 and 400 for Encrypt and gives no plaintext limit. Document the
  observed refusal and expose a typed size error once a limit is specified.
  At `exoscalekms.go:151–174`, keep ciphertext opaque and cap response
  reads for a 32-byte DEK. The exact boundary between the two measured
  sizes, quota, worst-case replica lag and automatic rotation are unmeasured.
- At `exoscalekms.go:151–174,191–211`, keep rotation an operator action
  and test decrypt of old blobs and wrapping of fresh DEKs at the manual
  rotation limit. The November 22 all-switch suite passed at material
  version 10 and advanced to 11. It produced a 224-byte wrapped DEK and
  a 327-byte fixture blob. In the two later runs the provider and raw
  API suites passed. The plugin rotation subtest received HTTP 400,
  type `#/kms-key/manual-rotation-limit`, title
  `Maximum rotation limit exceeded`. The separate limit probe confirmed
  manual count 10 at version 11, in line with the Rotate Key HTTP 400 description, which specifies ten manual rotations per key.
  Use an owned disposable key for tests that rotate. The seventh-edition
  single-zone run confirmed the eleventh refusal on a created key with
  count 10 and version 11, followed by working crypto and confirmed
  cleanup. See `live-run-9-single-zone-limit.txt`, `live-run-8-{1,2,3}.txt`
  and `kms-rotation-limit-run-1.txt`.
- At `exoscalekms.go:97–124,191–211`, test replica decrypt before and
  after origin rotation and fail closed after origin deletion. The
  disposable multi-zone probe observed HTTP 200 on origin replication,
  and replica decrypt succeeded in 103 ms before rotation and 92 ms
  afterward. Replica rotate and schedule-deletion returned HTTP 400
  with `#/kms-key/multi-zone/operation-not-allowed-on-a-replica`.
  Origin scheduling for seven days propagated pending deletion by the
  second replica poll. Replica encrypt then returned HTTP 400 with
  `#/kms-key/key-disabled`. Use HTTP status, type and title to check
  these refusals. Three seventh-edition all-switch runs with a replica
  zone passed all 58 entries each on v0.2.0-rc.1. They confirmed replica
  readiness before rotation, manual rotation history, re-encryption and
  decrypt of old and new plugin blobs on the created multi-zone key.
  Replica decrypt succeeded on the first attempt before and after rotation
  (298–307 ms and 366–381 ms). Each origin readback confirmed pending
  deletion and the seven-day plan from the deletion timestamp. Each replica
  reported pending deletion and refused encrypt with HTTP 400. The
  configured key's revision, material version 11 and manual count 10
  were unchanged across those three runs and the single-zone run.
  The replica refusals' body status member, multi-zone deletion
  cancellation, replication to a third zone and worst-case lag remain
  unmeasured. See `kms-multizone-disposable-probe-run-1.txt` and
  `live-run-9-{1,2,3}.txt`.
- At `exoscalekms.go:121–124`, add integration cases for typed startup
  failures and for recovery with corrected configuration. On OpenBao
  2.7.2, the v0.2.0-rc.1 rehearsal passed all eight stages in 38 seconds,
  including initialization, restart, HTTP 403 with a wrong credential,
  recovery after restoring the credential and four migrations among
  Shamir, exoscale and static. With an unknown UUID it failed at
  initialization with HTTP 400 and `#/kms-key/not-found`. See
  `e2e-repo-script-run-5.txt` and `e2e-repo-script-wrong-key-run-3.txt`.
  Multi-node migration and Linux startup log framing remain unmeasured.

- At `exoscalekms.go:121–124,162–164,198–200`, map HTTP 400 types by
  exact equality. The measured list includes `#/kms-key/not-found`
  (unknown UUID on metadata, encrypt and decrypt),
  `#/crypto/invalid-ciphertext` (absent or different context, flipped bit
  and random bytes), `#/kms-key/key-disabled` and
  `#/http-problem-types/request-invalid-parameters` (non-base64 ciphertext,
  both or neither data-key selector, and counts 0 and 1025). The
  raw single-zone replication probe also recorded
  `#/kms-key/multi-zone/key-is-not-multi-zone`. Include the two types
  confirmed on disposable keys in edition seven. The types are
  `#/kms-key/manual-rotation-limit` and
  `#/kms-key/multi-zone/operation-not-allowed-on-a-replica`. Some HTTP 400
  responses, including malformed IDs, carry a JSON message and field errors.
  Wrong and unknown API credentials returned HTTP 403 with JSON messages.
  Use a neutral label when no approved type is available. Add tests for
  unknown-key startup, a validation error and a message-only refusal, and
  check that no detail, title or message escapes the wrapper.
- At `exoscalekms.go:97–127,142–164,179–200`, the caller supplies the
  earlier deadline when it has one. The head bounds setup and crypto at
  30 seconds. The SDK creates its client with retryablehttp (egoscale v3.1.65
  `client.go:58–60`). That client uses `cleanhttp.DefaultPooledClient`
  (retryablehttp v0.7.8 `client.go:438–448`). The pooled client sets no
  `http.Client.Timeout`, and its transport sets no
  `ResponseHeaderTimeout` (go-cleanhttp v0.5.2 `cleanhttp.go:23–38,54–58`).
  An individual attempt can consume the wrapper's entire budget.
  In roughly 420 raw requests over about 15 minutes,
  four missed a three-second deadline. There were none in about 3000
  requests sampled immediately afterward, and no failures in 800 plugin
  calls. Other runs recorded interruptions, described below. The cause is
  unmeasured. Preserve the overall and earlier caller deadlines when
  adding a shorter attempt deadline. Distinguish observed HTTP statuses
  from missing replies. Test withheld headers and incomplete bodies with
  and without a shorter caller deadline.

Evidence files include `kms-refusals-run-1.txt`, `kms-probe-run-1.txt`,
`live-run-3.txt`, `live-run-4-1.txt`, `live-run-4-2.txt`,
`kms-stall-http-version-run-1.txt`, `kms-stall-probe-run-1.txt`,
`kms-plugin-stress-run-1.txt`, `README.txt`, `e2e-outcomes.txt` and
`exoscale-kms-openapi-2026-11-21.json`.

## Incomplete and unanswered responses

At `exoscalekms.go:97–127,142–164,179–200`, bound response-header and
body reads within the caller's total deadline. Test against loopback
servers that withhold headers or stop after sending HTTP headers and an
incomplete body. Run both tests with and without an earlier caller
deadline. Preserve any observed HTTP status and omit the response body
from errors.

The account holder reports what preceded the unanswered requests
privately to Exoscale. Those details are omitted here.

On November 21, one all-switch run observed two incomplete replies
(HTTP 200 and 400). Two of six plain runs that evening each observed an
unanswered first attempt. Of twenty suite invocations at the current
request ceiling, seventeen recorded neither interruption. These were
four November 21 plain runs and all thirteen November 22 rounds,
including the four seventh-edition runs. The cause, the role of connection
reuse, and the effects in other zones or with other credentials or
source addresses remain unmeasured. See `README.txt` and
`live-run-8-{1,2,3}.txt` and `live-run-9-{1,2,3}.txt`.
