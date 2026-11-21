//! Bounded, offline TCP stream reconstruction.

use std::collections::BTreeMap;

use crate::Packet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TcpStreamKey {
    pub source: String,
    pub source_port: u16,
    pub destination: String,
    pub destination_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpStream {
    pub key: TcpStreamKey,
    pub packet_numbers: Vec<usize>,
    pub bytes: Vec<u8>,
    pub gap_count: usize,
}

/// Reconstructs direction-specific TCP payloads from packets already dissected.
/// Overlapping retransmissions are ignored; gaps are counted rather than filled.
#[must_use]
pub fn reassemble_tcp_streams(packets: &[Packet]) -> Vec<TcpStream> {
    let mut groups: BTreeMap<TcpStreamKey, Vec<(&Packet, u32, &[u8])>> = BTreeMap::new();
    for packet in packets {
        let (Some(tcp), Some(source_port), Some(destination_port)) = (
            packet.tcp.as_ref(),
            packet.summary.source_port,
            packet.summary.destination_port,
        ) else {
            continue;
        };
        let payload = tcp.payload.as_slice();
        if payload.is_empty() {
            continue;
        }
        groups
            .entry(TcpStreamKey {
                source: packet.summary.source.clone(),
                source_port,
                destination: packet.summary.destination.clone(),
                destination_port,
            })
            .or_default()
            .push((packet, tcp.sequence_number, payload));
    }
    groups
        .into_iter()
        .map(|(key, mut segments)| {
            segments.sort_by_key(|(_, sequence, _)| *sequence);
            let mut bytes = Vec::new();
            let mut packet_numbers = Vec::new();
            let mut expected = None;
            let mut gap_count = 0;
            for (packet, sequence, payload) in segments {
                if expected.is_some_and(|value| sequence > value) {
                    gap_count += 1;
                }
                let start = expected
                    .map_or(0, |value| value.saturating_sub(sequence) as usize)
                    .min(payload.len());
                if start < payload.len() {
                    bytes.extend_from_slice(&payload[start..]);
                }
                expected = Some(sequence.wrapping_add(payload.len() as u32));
                packet_numbers.push(packet.number);
            }
            TcpStream {
                key,
                packet_numbers,
                bytes,
                gap_count,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::reassemble_tcp_streams;
    use crate::dissect::dissect;

    fn tcp(sequence: u32, payload: &[u8]) -> crate::Packet {
        let mut bytes = vec![0; 14 + 20 + 20];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[23] = 6;
        bytes[34..36].copy_from_slice(&1234_u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&80_u16.to_be_bytes());
        bytes[38..42].copy_from_slice(&sequence.to_be_bytes());
        bytes[46] = 0x50;
        bytes[47] = 0x18;
        bytes.extend_from_slice(payload);
        dissect(sequence as usize, 0, bytes)
    }
    #[test]
    fn joins_ordered_tcp_segments() {
        let streams = reassemble_tcp_streams(&[tcp(10, b"hello "), tcp(16, b"world")]);
        assert_eq!(streams[0].bytes, b"hello world");
        assert_eq!(streams[0].gap_count, 0);
    }
}
