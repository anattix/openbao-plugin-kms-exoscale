<!-- SPDX-License-Identifier: MPL-2.0 -->

# Security policy

Use a current release built with the patched Go toolchain pinned in its module.
Report vulnerabilities privately through the repository's **Security** tab
using **Report a vulnerability**. Include the source revision, binary digest,
Go version, affected component and steps to reproduce with a disposable KMS
key or the local fake. Omit credentials, signed headers, plaintext, encrypted
state files, and key material. Keep details private while maintainers assess
and prepare a fix.

If application credentials may have been exposed, revoke or rotate those
credentials in Exoscale. For an affected KMS key, preserve decryption access to
previous key material while planning recovery and re-encryption.
