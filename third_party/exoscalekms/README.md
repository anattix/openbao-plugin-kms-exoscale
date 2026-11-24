# Exoscale KMS wrapper

This local Go module carries the six files in the accompanying manifest from
[OpenBao go-kms-wrapping PR 168](https://github.com/openbao/go-kms-wrapping/pull/168)
at commit `aad18865db438363ffd9927dda970ce3bbd952fb`. The files are
distributed under the [Mozilla Public License 2.0](LICENSE).

The root module uses a local Go module replacement. To switch to the published
module, require its release version and remove the replacement and this directory.
Build against the root module graph when testing these files. For example, run
`go test github.com/openbao/go-kms-wrapping/wrappers/exoscalekms/v2` from the root.
