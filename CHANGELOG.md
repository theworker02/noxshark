# Changelog

## Unreleased

- Added bounded 802.1Q and QinQ VLAN decapsulation.
- Added TCP sequence number, acknowledgement number, flags, and payload-length metadata to the inspector.
- Added composable display filters using `and`, `or`, and `not`.
- Improved the project README with the NoxShark mark, product positioning, verified scope, and attribution.
- Added classic PCAP nanosecond timestamp handling and bounded IPv6 extension-header traversal.
- Added DHCPv4 message, hostname, and requested-address inspection plus DNS response status and answer counts.
- Added an explicit Rust rewrite parity matrix to keep future compatibility work measurable and honest.
- Documented the Rust workspace organization alongside the responsibilities expected in a mature packet-analysis project.
- Added contributor guidance, capture-fixture policy, and repository ignore rules for local capture data and build artifacts.

## 0.1.0 — Foundation

- Created original NoxShark branding and native Rust desktop shell.
- Added dependency-free parsing for Ethernet PCAP and little-endian PCAPNG captures.
- Added IPv4, IPv6, TCP, UDP, DNS question, and TLS record / ClientHello SNI inspection.
- Added validated capture filters, display filters, capture statistics, and regression tests.
- Defined explicit security and future live-capture boundaries.
- Added ARP, ICMP/ICMPv6, and HTTP/1 header inspection with desktop statistics and metadata views.
