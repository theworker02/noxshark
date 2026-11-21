# NoxShark organization

NoxShark follows the same broad product boundaries users expect from a mature packet analyzer while keeping an original Rust workspace and a smaller, auditable codebase.

| Concern | NoxShark location | Responsibility |
| --- | --- | --- |
| Capture file I/O | `crates/noxshark-core/src/pcap.rs`, `pcapng.rs` | Validates and reads offline PCAP and PCAPNG captures. |
| Protocol dissection | `crates/noxshark-core/src/dissect.rs` | Bounded Ethernet, VLAN, IP, transport, and application metadata parsing. |
| Filter engine | `crates/noxshark-core/src/capture_filter.rs`, `display_filter.rs` | Validated capture-filter syntax and composable display filtering. |
| Packet model and analysis | `crates/noxshark-core/src/model.rs`, `statistics.rs` | Stable analysis data and capture-wide summaries. |
| Desktop UI | `crates/noxshark-desktop/src/main.rs` | Local-native packet list, filtering, statistics, and inspector. |
| Documentation | `docs/`, `ARCHITECTURE.md`, `SECURITY.md` | Contributor-facing design, safety boundaries, and product scope. |

This is deliberately comparable by responsibility—not a copied directory tree. Wireshark's upstream organization is built around C/C++, CMake, a broad collection of platforms, and decades of dissectors. NoxShark uses Rust crates and explicit parser boundaries so the project can grow without introducing privileged capture behavior into the offline-analysis core.

## Growth boundaries

- Add protocol modules under `crates/noxshark-core/src/` with fixture-backed tests.
- Keep format readers separate from dissectors and from privileged live-capture adapters.
- Put native UI work in `noxshark-desktop`; keep it dependent on the stable core model.
- Add test captures only when they are redistributable and scrubbed of private traffic.
