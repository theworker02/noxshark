use crate::{dissect::dissect, error::NoxSharkError, model::Packet, pcapng::read_pcapng};

/// Parses classic libpcap and PCAPNG captures containing Ethernet frames.
pub fn read_pcap(bytes: &[u8]) -> Result<Vec<Packet>, NoxSharkError> {
    if bytes.len() < 24 {
        return Err(NoxSharkError::InvalidCapture(
            "file is smaller than a pcap header".into(),
        ));
    }
    let little = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] => false,
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
        let micros = read_u32(offset + 4);
        let included = read_u32(offset + 8) as usize;
        offset += 16;
        if bytes.len() - offset < included {
            return Err(NoxSharkError::TruncatedPacket {
                packet: packets.len() + 1,
            });
        }
        packets.push(dissect(
            packets.len() + 1,
            u64::from(seconds) * 1_000_000 + u64::from(micros),
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
}

