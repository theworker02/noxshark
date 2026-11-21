//! Capture-wide endpoint and directional conversation summaries.

use crate::Packet;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSummary {
    pub address: String,
    pub packets: usize,
    pub bytes: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSummary {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub packets: usize,
    pub bytes: u64,
}

#[must_use]
pub fn endpoints(packets: &[Packet]) -> Vec<EndpointSummary> {
    let mut values: BTreeMap<String, (usize, u64)> = BTreeMap::new();
    for packet in packets {
        for address in [&packet.summary.source, &packet.summary.destination] {
            if address != "—" {
                let item = values.entry(address.clone()).or_default();
                item.0 += 1;
                item.1 += u64::from(packet.captured_len);
            }
        }
    }
    values
        .into_iter()
        .map(|(address, (packets, bytes))| EndpointSummary {
            address,
            packets,
            bytes,
        })
        .collect()
}

#[must_use]
pub fn conversations(packets: &[Packet]) -> Vec<ConversationSummary> {
    let mut values: BTreeMap<(String, String, String), (usize, u64)> = BTreeMap::new();
    for packet in packets {
        let key = (
            packet.summary.source.clone(),
            packet.summary.destination.clone(),
            packet.summary.protocol.label().into(),
        );
        let item = values.entry(key).or_default();
        item.0 += 1;
        item.1 += u64::from(packet.captured_len);
    }
    values
        .into_iter()
        .map(
            |((source, destination, protocol), (packets, bytes))| ConversationSummary {
                source,
                destination,
                protocol,
                packets,
                bytes,
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{conversations, endpoints};
    use crate::dissect::dissect;

    #[test]
    fn groups_endpoints_and_conversations() {
        let mut bytes = vec![0; 14 + 20 + 8];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[23] = 17;
        bytes[26..30].copy_from_slice(&[192, 0, 2, 1]);
        bytes[30..34].copy_from_slice(&[198, 51, 100, 2]);
        let packet = dissect(1, 0, bytes);
        assert_eq!(endpoints(&[packet.clone()]).len(), 2);
        assert_eq!(conversations(&[packet]).len(), 1);
    }
}
