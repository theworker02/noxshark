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
