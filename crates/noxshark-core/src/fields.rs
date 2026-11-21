//! Typed, display-safe fields derived from an already dissected packet.

use crate::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketFieldValue {
    Text(String),
    Unsigned(u64),
    Boolean(bool),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketField {
    pub name: &'static str,
    pub value: PacketFieldValue,
}

#[must_use]
pub fn packet_fields(packet: &Packet) -> Vec<PacketField> {
    let mut fields = vec![
        PacketField {
            name: "frame.number",
            value: PacketFieldValue::Unsigned(packet.number as u64),
        },
        PacketField {
            name: "frame.length",
            value: PacketFieldValue::Unsigned(u64::from(packet.captured_len)),
        },
        PacketField {
            name: "ip.src",
            value: PacketFieldValue::Text(packet.summary.source.clone()),
        },
        PacketField {
            name: "ip.dst",
            value: PacketFieldValue::Text(packet.summary.destination.clone()),
        },
    ];
    if let Some(tcp) = &packet.tcp {
        fields.push(PacketField {
            name: "tcp.seq",
            value: PacketFieldValue::Unsigned(u64::from(tcp.sequence_number)),
        });
        fields.push(PacketField {
            name: "tcp.ack",
            value: PacketFieldValue::Unsigned(u64::from(tcp.acknowledgement_number)),
        });
    }
    if let Some(dns) = &packet.dns {
        fields.push(PacketField {
            name: "dns.response",
            value: PacketFieldValue::Boolean(dns.is_response),
        });
        fields.push(PacketField {
            name: "dns.answers",
            value: PacketFieldValue::Unsigned(u64::from(dns.answer_count)),
        });
    }
    fields
}
