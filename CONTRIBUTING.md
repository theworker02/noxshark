# Contributing to NoxShark

NoxShark is an original Rust packet-analysis project. Contributions should improve the local-first analyzer without copying Wireshark source, branding, assets, or proprietary capture data.

## Development setup

Install the stable Rust toolchain, then run:

```powershell
cargo fmt --all -- --check
cargo test --workspace
cargo build --workspace
```

## Contribution boundaries

- Keep `noxshark-core` free of privileged capture, socket, and shell-execution behavior.
- Treat capture files as untrusted input: every offset, length, and recursion path must be bounded.
- Put parser regression coverage next to the behavior or add scrubbed, redistributable fixtures under `tests/fixtures/`.
- Keep application behavior honest in the README and changelog; do not describe unsupported protocol coverage as complete.
- Discuss platform capture adapters before adding Npcap, libpcap, or elevated privileges.

## Pull requests

Use focused commits with a concise description of user-visible behavior, security implications, and validation commands run. New dissectors should describe their supported subset and malformed-input handling.
