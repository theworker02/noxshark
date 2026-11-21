# Rust rewrite parity plan

NoxShark's objective is a clean-room Rust implementation of the major capabilities people rely on in a full packet analyzer. This is a product and engineering plan, not a claim that feature parity already exists.

| System | Current Rust status | Next implementation boundary |
| --- | --- | --- |
| Offline capture readers | Classic PCAP, little-endian PCAPNG, microsecond/nanosecond timestamps, PCAPNG interface timestamp options | PCAPNG name-resolution blocks and additional link types |
| Dissection | Ethernet, VLAN/QinQ, ARP, IPv4/IPv6, ICMP, TCP/UDP, DNS, DHCPv4, HTTP/1, TLS metadata | Modular protocol registry, IPv4 options, deeper IPv6 options, DNS answers, TLS certificate metadata |
| Display filtering | Protocol, address, port, text, `and` / `or` / `not` | Typed fields, parentheses, ranges, saved filters, parser diagnostics |
| Capture filtering | Validated offline filter grammar | Permissioned native adapter that compiles only approved filters for Npcap/libpcap |
| Analysis | Protocol totals, endpoint/directional conversation summaries, TCP metadata, bounded direction-specific stream reconstruction, DNS/DHCP/TLS inspection | Bidirectional conversations, service response timing, and expert diagnostics |
| Desktop UI | Native packet table, filter bar, statistics, packet inspector, bounded hex preview | Expandable protocol tree, byte-range selection, saved views, follow-stream UX, preferences |
| Command line and export | Headless PCAP/PCAPNG inspection with table, JSON, and CSV output | Reports, richer export schema, and batch operation |
| Extensibility | Built-in dissector descriptor registry and typed packet-field projection | Versioned Rust dissector traits and restricted plugin process boundary |
| Live capture | Windows Npcap presence detection only; no DLL loading or capture | Windows-first Npcap adapter with explicit interface selection and user approval |

## Engineering rules

1. Every migration milestone must add parser fixtures or regression tests.
2. Protocol handling remains bounded and non-executing: captures are data, never instructions.
3. Privileged capture and file parsing stay separate crates or processes.
4. New support is documented as a supported subset until interoperability tests prove broader coverage.
5. Compatibility goals guide behavior, but implementation, UI, assets, and branding remain original.
