# Security policy

NoxShark treats capture files as untrusted input.

- Parsers check format magic, block and packet sizes, link-layer types, and slice bounds before decoding.
- The core crate has no network access, shell execution, plugin loading, live capture, or decryption-key storage.
- The desktop app opens only files that a user explicitly selects.
- TLS inspection is metadata-only. NoxShark does not bypass encryption.

## Reporting a vulnerability

Do not include sensitive captures, credentials, or private keys in public reports. Provide a minimized synthetic reproducer and a description of the observed behavior.

