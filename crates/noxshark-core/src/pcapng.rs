use crate::{dissect::dissect, error::NoxSharkError, model::Packet};

/// Reads little-endian PCAPNG Section Header, Interface Description, and
/// Enhanced Packet blocks. Unknown well-formed blocks are skipped.
pub fn read_pcapng(bytes: &[u8]) -> Result<Vec<Packet>, NoxSharkError> {
    if bytes.len() < 28 {
        return Err(NoxSharkError::InvalidCapture(
            "PCAPNG section header is truncated".into(),
        ));
    }
    if bytes[..4] != [10, 13, 13, 10] {
        return Err(NoxSharkError::InvalidCapture(
            "PCAPNG section header missing".into(),
        ));
    }
    if bytes[8..12] != [0x4d, 0x3c, 0x2b, 0x1a] {
        return Err(NoxSharkError::UnsupportedCapture(
            "only little-endian PCAPNG is supported".into(),
        ));
    }
    let mut offset = 0;
    let mut interfaces = Vec::new();
    let mut packets = Vec::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 12 {
            return Err(NoxSharkError::InvalidCapture(
                "PCAPNG block header is truncated".into(),
            ));
        }
        let block_type = u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("bounds checked"),
        );
        let block_len = usize::try_from(u32::from_le_bytes(
            bytes[offset + 4..offset + 8]
                .try_into()
                .expect("bounds checked"),
        ))
        .map_err(|_| NoxSharkError::InvalidCapture("invalid PCAPNG block size".into()))?;
        if block_len < 12 || block_len % 4 != 0 || block_len > bytes.len() - offset {
            return Err(NoxSharkError::InvalidCapture(
                "invalid PCAPNG block length".into(),
            ));
        }
        let trailer = u32::from_le_bytes(
            bytes[offset + block_len - 4..offset + block_len]
                .try_into()
                .expect("validated block"),
        ) as usize;
        if trailer != block_len {
            return Err(NoxSharkError::InvalidCapture(
                "PCAPNG block length trailer does not match".into(),
            ));
        }
        let body = &bytes[offset + 8..offset + block_len - 4];
        match block_type {
            1 => {
                if body.len() < 8 {
                    return Err(NoxSharkError::InvalidCapture(
                        "PCAPNG interface block is truncated".into(),
                    ));
                }
                interfaces.push(u16::from_le_bytes([body[0], body[1]]));
            }
            6 => {
                if body.len() < 20 {
                    return Err(NoxSharkError::InvalidCapture(
                        "PCAPNG enhanced packet block is truncated".into(),
                    ));
                }
                let interface =
                    u32::from_le_bytes(body[..4].try_into().expect("fixed header")) as usize;
                if interfaces.get(interface) != Some(&1) {
                    return Err(NoxSharkError::UnsupportedCapture(
                        "only Ethernet PCAPNG interfaces are supported".into(),
                    ));
                }
                let timestamp_high =
                    u32::from_le_bytes(body[4..8].try_into().expect("fixed header"));
                let timestamp_low =
                    u32::from_le_bytes(body[8..12].try_into().expect("fixed header"));
                let captured_len = usize::try_from(u32::from_le_bytes(
                    body[12..16].try_into().expect("fixed header"),
                ))
                .map_err(|_| {
                    NoxSharkError::InvalidCapture("PCAPNG captured length overflow".into())
                })?;
                let data = body.get(20..20 + captured_len).ok_or_else(|| {
                    NoxSharkError::TruncatedPacket {
                        packet: packets.len() + 1,
                    }
                })?;
                packets.push(dissect(
                    packets.len() + 1,
                    (u64::from(timestamp_high) << 32) | u64::from(timestamp_low),
                    data.to_vec(),
                ));
            }
            _ => {}
        }
        offset += block_len;
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::read_pcapng;
    #[test]
    fn reads_empty_section() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
        bytes.extend_from_slice(&28u32.to_le_bytes());
        bytes.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&(-1i64).to_le_bytes());
        bytes.extend_from_slice(&28u32.to_le_bytes());
        assert_eq!(read_pcapng(&bytes).expect("valid section").len(), 0);
    }
}

