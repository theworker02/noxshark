use crate::{dissect::dissect, error::NoxSharkError, model::Packet, pcapng::read_pcapng};

/// Parses classic libpcap and PCAPNG captures containing Ethernet frames.
pub fn read_pcap(bytes: &[u8]) -> Result<Vec<Packet>, NoxSharkError> {
    if bytes.len() < 24 {
        return Err(NoxSharkError::InvalidCapture(
            "file is smaller than a pcap header".into(),
        ));
    }
    let (little, nanosecond_resolution) = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        [0x0a, 0x0d, 0x0d, 0x0a] => return read_pcapng(bytes),
        _ => return Err(NoxSharkError::InvalidCapture("unknown file magic".into())),
    };
    let read_u32 = |at: usize| -> u32 {
        let value: [u8; 4] = bytes[at..at + 4].try_into().expect("bounds checked");
        if little {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        }
    };
    if read_u32(20) != 1 {
        return Err(NoxSharkError::UnsupportedCapture(
            "only Ethernet link type is supported".into(),
        ));
    }
    let mut offset = 24;
    let mut packets = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 16 {
            return Err(NoxSharkError::TruncatedPacket {
                packet: packets.len() + 1,
            });
        }
        let seconds = read_u32(offset);
        let fraction = read_u32(offset + 4);
        let included = read_u32(offset + 8) as usize;
        offset += 16;
        if bytes.len() - offset < included {
            return Err(NoxSharkError::TruncatedPacket {
                packet: packets.len() + 1,
            });
        }
        packets.push(dissect(
            packets.len() + 1,
            u64::from(seconds) * 1_000_000
                + if nanosecond_resolution {
                    u64::from(fraction) / 1_000
                } else {
                    u64::from(fraction)
                },
            bytes[offset..offset + included].to_vec(),
        ));
        offset += included;
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_truncated_pcapng() {
        assert!(read_pcap(&[10, 13, 13, 10]).is_err());
    }

    #[test]
    fn converts_nanosecond_pcap_timestamps_to_micros() {
        let mut bytes = vec![0x4d, 0x3c, 0xb2, 0xa1];
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&1_500_u32.to_le_bytes());
        bytes.extend_from_slice(&14_u32.to_le_bytes());
        bytes.extend_from_slice(&14_u32.to_le_bytes());
        bytes.extend_from_slice(&[0; 14]);
        let packets = read_pcap(&bytes).expect("valid nanosecond PCAP");
        assert_eq!(packets[0].timestamp_micros, 1_000_001);
    }
}
