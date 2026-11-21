<div align="center">
  <img src="assets/noxshark-mark.svg" width="144" alt="NoxShark original mark" />

  # NoxShark

  **A Rust-native packet analysis engine and desktop inspector.**

  _An original clean-room rewrite inspired by the workflow of Wireshark._
</div>

## What it is

NoxShark is a new packet-analysis application written in Rust. It preserves the familiar goals of a desktop network inspector—open capture files, dissect packets, filter results, and inspect protocol details—while using an original codebase, visual identity, and user interface.

It is **not** a Wireshark mirror or a copy of Wireshark source code. This repository remains a GitHub fork to preserve the upstream relationship and its GPL-2.0-or-later licensing context; NoxShark's active implementation is independently authored in Rust.

## Current capability

| Area | Implemented today |
| --- | --- |
| Desktop | Native Rust GUI with `eframe` / `egui` |
| Capture files | Bounded parsing for classic Ethernet PCAP and little-endian PCAPNG |
| Protocols | Ethernet with 802.1Q / QinQ VLAN tags, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, DHCPv4, HTTP/1, and TLS records |
| Inspection | TCP sequence / acknowledgement numbers, flags, and payload lengths; DNS response status and answers; DHCP message / hostname metadata; HTTP headers; TLS record and ClientHello SNI metadata |
| Filtering | Display filters for protocol, address, port, and text, combinable with `and`, `or`, and `not`; validated capture-filter language for a future live-capture adapter |
| TLS | Record metadata and ClientHello SNI recognition—no decryption or encryption bypassing |

## Run locally

Prerequisite: a current stable [Rust toolchain](https://www.rust-lang.org/tools/install).

```powershell
cargo run -p noxshark-desktop
```

## Command-line inspection and export

The Rust workspace also includes a headless reader for reproducible inspection and simple exports:

```powershell
cargo run -p noxshark-cli -- capture.pcap --filter "protocol == DNS" --format json
```

Supported formats are `table`, `csv`, and `json`. The CLI reads only the explicitly supplied capture file.

## Verify

```powershell
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Project status

NoxShark is an early, working foundation—not a feature-complete replacement for Wireshark. Live capture, TCP stream reassembly, complete TLS extension coverage, timestamp-resolution options, and controlled decryption-key support remain future work.

Live capture will require a platform-specific, permissioned adapter such as Npcap or libpcap. NoxShark will not expose arbitrary shell execution or accept unvalidated BPF input.

## Project organization

The workspace separates capture-file readers, dissectors, filters, analysis models, and the desktop UI. See [docs/ORGANIZATION.md](docs/ORGANIZATION.md) for the clean-room structure comparison and growth boundaries.

The full rewrite program is tracked in [docs/PARITY_PLAN.md](docs/PARITY_PLAN.md). It marks implemented Rust capabilities separately from planned parity work.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local development checks, parser safety requirements, and capture-fixture policy.

## Identity and attribution

The NoxShark name, mark, UI, and Rust implementation are original. Wireshark is a trademark of the Wireshark Foundation; NoxShark is not affiliated with or endorsed by the Wireshark Foundation. See [NOTICE.md](NOTICE.md) and [COPYING](COPYING) for licensing and attribution information.
