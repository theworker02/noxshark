//! Stable metadata describing the built-in clean-room dissectors.

use crate::Protocol;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DissectorDescriptor {
    pub protocol: Protocol,
    pub name: &'static str,
    pub transport: &'static str,
    pub status: &'static str,
}

/// Returns the built-in protocol modules surfaced by the current engine.
#[must_use]
pub const fn builtin_dissectors() -> &'static [DissectorDescriptor] {
    &[
        DissectorDescriptor {
            protocol: Protocol::Arp,
            name: "ARP",
            transport: "EtherType 0x0806",
            status: "bounded metadata",
        },
        DissectorDescriptor {
            protocol: Protocol::Dns,
            name: "DNS",
            transport: "UDP/53",
            status: "question and response metadata",
        },
        DissectorDescriptor {
            protocol: Protocol::Dhcp,
            name: "DHCPv4",
            transport: "UDP/67, UDP/68",
            status: "options metadata",
        },
        DissectorDescriptor {
            protocol: Protocol::Http,
            name: "HTTP/1",
            transport: "TCP",
            status: "header metadata",
        },
        DissectorDescriptor {
            protocol: Protocol::Tls,
            name: "TLS",
            transport: "TCP",
            status: "record and ClientHello SNI metadata",
        },
    ]
}
