# NoxShark

NoxShark is an original, clean-room Rust packet analysis application. It is a new project with an offline-first architecture; it does not copy Wireshark code, assets, branding, or logo. Its original project mark is available at [`assets/noxshark-mark.svg`](assets/noxshark-mark.svg).

## Current capability

- Native Rust desktop UI built with `eframe`/egui
- Safe, bounded parsing of classic Ethernet PCAP and little-endian PCAPNG files
- Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS-question, HTTP/1 header, and TLS-record recognition
- Display filters: `protocol == TLS`, `ip.addr == 192.0.2.10`, `port == 443`, and `contains == text`
- Validated capture-filter language ready for a future approved live-capture adapter: `tcp and port 443`, `host 192.0.2.10`, `http`, `arp`, `not udp`
- TLS metadata and ClientHello SNI only; this project does **not** decrypt traffic or circumvent encryption

## Run

```powershell
cargo run -p noxshark-desktop
```

## Verify

```powershell
cargo test -p noxshark-core
cargo clippy --workspace --all-targets -- -D warnings
```

## Scope and security

Live capture remains intentionally unimplemented in this first slice. It requires a platform-specific, permissioned adapter (Npcap/libpcap or equivalent) and must never expose raw shell execution or unvalidated BPF input. TCP stream reassembly, full TLS handshake extension decoding, timestamp-resolution options, and decryption-key support are planned follow-on work—not claimed functionality.

