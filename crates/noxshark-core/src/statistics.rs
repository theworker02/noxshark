use crate::{Packet, Protocol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureStatistics {
    pub total_packets: usize,
    pub total_bytes: u64,
    pub tls_packets: usize,
    pub dns_packets: usize,
    pub ipv4_packets: usize,
    pub ipv6_packets: usize,
    pub http_packets: usize,
    pub arp_packets: usize,
}

impl CaptureStatistics {
    pub fn from_packets(packets: &[Packet]) -> Self {
        let has = |protocol| {
            packets
                .iter()
                .filter(|packet| packet.protocols.contains(&protocol))
                .count()
        };
        Self {
            total_packets: packets.len(),
            total_bytes: packets
                .iter()
                .map(|packet| u64::from(packet.captured_len))
                .sum(),
            tls_packets: has(Protocol::Tls),
            dns_packets: has(Protocol::Dns),
            ipv4_packets: has(Protocol::Ipv4),
            ipv6_packets: has(Protocol::Ipv6),
            http_packets: has(Protocol::Http),
            arp_packets: has(Protocol::Arp),
        }
    }
}

