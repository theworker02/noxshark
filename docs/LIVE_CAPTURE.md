# Windows live capture

NoxShark's `noxshark-capture-npcap` crate uses the Rust `pcap` binding, which links to Npcap's `wpcap.lib` and uses Npcap at runtime.

## Developer setup

1. Install the current Npcap runtime for Windows.
2. Download the matching Npcap SDK.
3. Add the SDK library directory matching your Rust target to `LIB` before building. For a 64-bit MSVC build, that is typically the SDK's `Lib/x64` directory.
4. Build and test the workspace:

```powershell
cargo test --workspace
cargo build --workspace
```

The adapter enumerates interfaces, applies a caller-supplied BPF filter, and emits timestamped raw packets on a background thread. It does not inject packets, run shell commands, or silently start capture.

## Product safeguards

- Capture begins only after explicit user action and interface selection.
- Promiscuous mode is an explicit configuration value and defaults to off in future UI flows.
- Capture filters are validated before reaching the adapter.
- Interface, driver, and permission errors are returned to the caller.
- Npcap redistribution has separate licensing considerations; users should install Npcap themselves unless the project has appropriate redistribution rights.
