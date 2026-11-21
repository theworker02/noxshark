# NoxShark architecture

NoxShark is a new Rust project, designed as an offline-first packet-inspection application.

```text
PCAP file → bounded parser → packet model → dissectors → filters → desktop inspector
```

`noxshark-core` has no third-party dependencies and no privileged behavior. It owns classic PCAP and little-endian PCAPNG file-format validation, protocol decoding, packet models, statistics, and filter evaluation. Its dissectors include bounded VLAN / QinQ link-layer unwrapping, TCP header metadata, DNS questions, HTTP headers, and TLS ClientHello SNI. Packet byte access is bounded, unsupported formats fail explicitly, and parsed captures never execute content.

`noxshark-desktop` is a native `eframe` frontend. It calls the core parser on an explicitly user-selected file and presents packet rows plus a bounded hex preview. It has no live-capture implementation.

## Planned extension boundaries

- **Capture adapter:** a separately permissioned Windows Npcap/libpcap adapter, with validated filters and explicit interface selection.
- **Dissector registry:** protocol modules registered against stable packet-layer data, starting with ARP, ICMP, HTTP, TCP stream reassembly, and DNS response decoding.
- **PCAPNG expansion:** timestamp-resolution options, additional packet blocks, and big-endian sections with the same block-size validation model.
- **TLS inspector:** handshake and certificate metadata parsing only. Key logs, if added, must use explicit file selection and never be stored by default.

These are intentionally separate so future privileged capture capability cannot leak into the parser or UI layer.
