use crate::model::{DnsMetadata, HttpMetadata, Packet, PacketSummary, Protocol, TlsMetadata};

pub fn dissect(number: usize, timestamp_micros: u64, bytes: Vec<u8>) -> Packet {
    let mut protocols = vec![Protocol::Ethernet];
    let mut summary = PacketSummary {
        source: "—".into(),
        destination: "—".into(),
        source_port: None,
        destination_port: None,
        protocol: Protocol::Unknown,
        info: "Unrecognized link-layer payload".into(),
    };
    let mut tls = None;
    let mut dns = None;
    let mut http = None;
    if bytes.len() >= 14 {
        match u16::from_be_bytes([bytes[12], bytes[13]]) {
            0x0800 => dissect_ipv4(
                &bytes[14..],
                &mut protocols,
                &mut summary,
                &mut tls,
                &mut dns,
                &mut http,
            ),
            0x86dd => dissect_ipv6(
                &bytes[14..],
                &mut protocols,
                &mut summary,
                &mut tls,
                &mut dns,
                &mut http,
            ),
            0x0806 => dissect_arp(&bytes[14..], &mut protocols, &mut summary),
            _ => {}
        }
    }
    Packet {
        number,
        timestamp_micros,
        captured_len: bytes.len() as u32,
        bytes,
        protocols,
        summary,
        tls,
        dns,
        http,
    }
}

fn dissect_ipv4(
    data: &[u8],
    protocols: &mut Vec<Protocol>,
    summary: &mut PacketSummary,
    tls: &mut Option<TlsMetadata>,
    dns: &mut Option<DnsMetadata>,
    http: &mut Option<HttpMetadata>,
) {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return;
    }
    let header_len = usize::from(data[0] & 0x0f) * 4;
    if header_len < 20 || data.len() < header_len {
        return;
    }
    protocols.push(Protocol::Ipv4);
    summary.source = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    summary.destination = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);
    match data[9] {
        1 => dissect_icmp(&data[header_len..], protocols, summary, Protocol::Icmp),
        6 => dissect_tcp(&data[header_len..], protocols, summary, tls, http),
        17 => dissect_udp(&data[header_len..], protocols, summary, dns),
        value => {
            summary.protocol = Protocol::Ipv4;
            summary.info = format!("IPv4 protocol {value}");
        }
    }
}

fn dissect_arp(data: &[u8], protocols: &mut Vec<Protocol>, summary: &mut PacketSummary) {
    if data.len() < 28
        || u16::from_be_bytes([data[0], data[1]]) != 1
        || u16::from_be_bytes([data[2], data[3]]) != 0x0800
    {
        return;
    }
    protocols.push(Protocol::Arp);
    summary.protocol = Protocol::Arp;
    summary.source = format!("{}.{}.{}.{}", data[14], data[15], data[16], data[17]);
    summary.destination = format!("{}.{}.{}.{}", data[24], data[25], data[26], data[27]);
    summary.info = match u16::from_be_bytes([data[6], data[7]]) {
        1 => format!("Who has {}? Tell {}", summary.destination, summary.source),
        2 => format!(
            "{} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            summary.source, data[8], data[9], data[10], data[11], data[12], data[13]
        ),
        value => format!("ARP opcode {value}"),
    };
}

fn dissect_ipv6(
    data: &[u8],
    protocols: &mut Vec<Protocol>,
    summary: &mut PacketSummary,
    tls: &mut Option<TlsMetadata>,
    dns: &mut Option<DnsMetadata>,
    http: &mut Option<HttpMetadata>,
) {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return;
    }
    protocols.push(Protocol::Ipv6);
    let source = <[u8; 16]>::try_from(&data[8..24]).expect("fixed IPv6 header");
    let destination = <[u8; 16]>::try_from(&data[24..40]).expect("fixed IPv6 header");
    summary.source = std::net::Ipv6Addr::from(source).to_string();
    summary.destination = std::net::Ipv6Addr::from(destination).to_string();
    match data[6] {
        6 => dissect_tcp(&data[40..], protocols, summary, tls, http),
        17 => dissect_udp(&data[40..], protocols, summary, dns),
        58 => dissect_icmp(&data[40..], protocols, summary, Protocol::Icmpv6),
        value => {
            summary.protocol = Protocol::Ipv6;
            summary.info = format!("IPv6 next header {value}");
        }
    }
}

fn dissect_icmp(
    data: &[u8],
    protocols: &mut Vec<Protocol>,
    summary: &mut PacketSummary,
    protocol: Protocol,
) {
    if data.len() < 2 {
        return;
    }
    protocols.push(protocol);
    summary.protocol = protocol;
    summary.info = match (protocol, data[0], data[1]) {
        (_, 8, 0) => "Echo request".into(),
        (_, 0, 0) => "Echo reply".into(),
        (Protocol::Icmpv6, 128, 0) => "Echo request".into(),
        (Protocol::Icmpv6, 129, 0) => "Echo reply".into(),
        (_, kind, code) => format!("ICMP type {kind}, code {code}"),
    };
}

fn dissect_tcp(
    data: &[u8],
    protocols: &mut Vec<Protocol>,
    summary: &mut PacketSummary,
    tls: &mut Option<TlsMetadata>,
    http: &mut Option<HttpMetadata>,
) {
    if data.len() < 20 {
        return;
    }
    protocols.push(Protocol::Tcp);
    summary.protocol = Protocol::Tcp;
    let src = u16::from_be_bytes([data[0], data[1]]);
    let dst = u16::from_be_bytes([data[2], data[3]]);
    summary.source_port = Some(src);
    summary.destination_port = Some(dst);
    let header_len = usize::from(data[12] >> 4) * 4;
    summary.info = format!("{src} → {dst}");
    if data.len() >= header_len + 5 && (src == 443 || dst == 443 || data[header_len] == 22) {
        if let Some(metadata) = parse_tls(&data[header_len..]) {
            protocols.push(Protocol::Tls);
            summary.protocol = Protocol::Tls;
            summary.info = format!(
                "{} {}",
                metadata.record_type,
                metadata
                    .server_name
                    .as_deref()
                    .unwrap_or("encrypted session")
            );
            *tls = Some(metadata);
            return;
        }
    }
    if let Some(metadata) = parse_http(&data[header_len..]) {
        protocols.push(Protocol::Http);
        summary.protocol = Protocol::Http;
        summary.info = format!(
            "{} {}",
            metadata.method_or_status, metadata.target_or_reason
        );
        *http = Some(metadata);
    }
}

fn parse_http(data: &[u8]) -> Option<HttpMetadata> {
    let header_end = data.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&data[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let first = lines.next()?;
    let host = lines.find_map(|line| {
        line.strip_prefix("Host:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    });
    if let Some(rest) = first.strip_prefix("HTTP/") {
        let mut fields = rest.splitn(3, ' ');
        let _version = fields.next()?;
        return Some(HttpMetadata {
            message_type: "Response".into(),
            method_or_status: fields.next()?.into(),
            target_or_reason: fields.next().unwrap_or_default().into(),
            host,
        });
    }
    let mut fields = first.splitn(3, ' ');
    let method = fields.next()?;
    let target = fields.next()?;
    let version = fields.next()?;
    if !version.starts_with("HTTP/") || !method.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return None;
    }
    Some(HttpMetadata {
        message_type: "Request".into(),
        method_or_status: method.into(),
        target_or_reason: target.into(),
        host,
    })
}

fn dissect_udp(
    data: &[u8],
    protocols: &mut Vec<Protocol>,
    summary: &mut PacketSummary,
    dns: &mut Option<DnsMetadata>,
) {
    if data.len() < 8 {
        return;
    }
    protocols.push(Protocol::Udp);
    summary.protocol = Protocol::Udp;
    let src = u16::from_be_bytes([data[0], data[1]]);
    let dst = u16::from_be_bytes([data[2], data[3]]);
    summary.source_port = Some(src);
    summary.destination_port = Some(dst);
    summary.info = format!("{src} → {dst}");
    if src == 53 || dst == 53 {
        protocols.push(Protocol::Dns);
        summary.protocol = Protocol::Dns;
        *dns = parse_dns(&data[8..]);
        summary.info = dns
            .as_ref()
            .and_then(|value| value.query_name.as_ref())
            .map_or_else(|| "DNS message".into(), |name| format!("DNS {name}"));
    }
}

fn parse_tls(data: &[u8]) -> Option<TlsMetadata> {
    if data.len() < 5 || !matches!(data[0], 20..=23) {
        return None;
    }
    let record_type = match data[0] {
        20 => "Change Cipher Spec",
        21 => "Alert",
        22 => "Handshake",
        23 => "Application Data",
        _ => return None,
    }
    .to_owned();
    let version = match (data[1], data[2]) {
        (3, 1) => "TLS 1.0",
        (3, 2) => "TLS 1.1",
        (3, 3) => "TLS 1.2+",
        _ => "Unknown TLS",
    }
    .to_owned();
    let record_length = usize::from(u16::from_be_bytes([data[3], data[4]]));
    let payload = data.get(5..5 + record_length)?;
    Some(TlsMetadata {
        record_type,
        version,
        server_name: parse_tls_server_name(payload),
    })
}

fn parse_tls_server_name(payload: &[u8]) -> Option<String> {
    if payload.len() < 4 || payload[0] != 1 {
        return None;
    }
    let handshake_len = ((usize::from(payload[1])) << 16)
        | ((usize::from(payload[2])) << 8)
        | usize::from(payload[3]);
    let hello = payload.get(4..4 + handshake_len)?;
    if hello.len() < 35 {
        return None;
    }
    let mut offset = 35 + usize::from(hello[34]);
    let cipher_len = usize::from(u16::from_be_bytes(
        hello.get(offset..offset + 2)?.try_into().ok()?,
    ));
    offset += 2 + cipher_len;
    let compression_len = usize::from(*hello.get(offset)?);
    offset += 1 + compression_len;
    let extensions_len = usize::from(u16::from_be_bytes(
        hello.get(offset..offset + 2)?.try_into().ok()?,
    ));
    offset += 2;
    let extensions = hello.get(offset..offset + extensions_len)?;
    let mut index = 0;
    while index + 4 <= extensions.len() {
        let extension_type = u16::from_be_bytes([extensions[index], extensions[index + 1]]);
        let extension_len = usize::from(u16::from_be_bytes([
            extensions[index + 2],
            extensions[index + 3],
        ]));
        index += 4;
        let extension = extensions.get(index..index + extension_len)?;
        index += extension_len;
        if extension_type == 0 && extension.len() >= 5 {
            let name_len = usize::from(u16::from_be_bytes([extension[3], extension[4]]));
            let name = extension.get(5..5 + name_len)?;
            if name.is_ascii() {
                return std::str::from_utf8(name).ok().map(str::to_owned);
            }
        }
    }
    None
}

fn parse_dns(data: &[u8]) -> Option<DnsMetadata> {
    if data.len() < 12 {
        return None;
    }
    let transaction_id = u16::from_be_bytes([data[0], data[1]]);
    let is_response = data[2] & 0x80 != 0;
    let questions = u16::from_be_bytes([data[4], data[5]]);
    if questions == 0 {
        return Some(DnsMetadata {
            transaction_id,
            is_response,
            query_name: None,
            query_type: None,
        });
    }
    let (name, offset) = parse_dns_name(data, 12, 0)?;
    let query_type = data.get(offset..offset + 2).map(|value| {
        match u16::from_be_bytes([value[0], value[1]]) {
            1 => "A",
            28 => "AAAA",
            5 => "CNAME",
            15 => "MX",
            16 => "TXT",
            _ => "OTHER",
        }
        .to_owned()
    });
    Some(DnsMetadata {
        transaction_id,
        is_response,
        query_name: Some(name),
        query_type,
    })
}

fn parse_dns_name(data: &[u8], mut offset: usize, depth: u8) -> Option<(String, usize)> {
    if depth > 8 {
        return None;
    }
    let start = offset;
    let mut labels = Vec::new();
    loop {
        let length = *data.get(offset)?;
        if length == 0 {
            return Some((labels.join("."), offset + 1));
        }
        if length & 0xc0 == 0xc0 {
            let next = *data.get(offset + 1)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(next);
            let (suffix, _) = parse_dns_name(data, pointer, depth + 1)?;
            labels.push(suffix);
            return Some((labels.join("."), start + 2));
        }
        if length > 63 {
            return None;
        }
        offset += 1;
        let label = data.get(offset..offset + usize::from(length))?;
        if !label.is_ascii() {
            return None;
        }
        labels.push(std::str::from_utf8(label).ok()?.to_owned());
        offset += usize::from(length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dissects_dns_over_udp() {
        let mut bytes = vec![0; 14 + 20 + 8];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[23] = 17;
        bytes[26..30].copy_from_slice(&[1, 1, 1, 1]);
        bytes[30..34].copy_from_slice(&[8, 8, 8, 8]);
        bytes[34..36].copy_from_slice(&1234_u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&53_u16.to_be_bytes());
        let packet = dissect(1, 0, bytes);
        assert_eq!(packet.summary.protocol, Protocol::Dns);
    }

    #[test]
    fn extracts_sni_from_a_tls_client_hello() {
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x13, 1]);
        hello.extend_from_slice(&[1, 0]);
        let mut sni = vec![0, 14, 0, 0, 11];
        sni.extend_from_slice(b"example.com");
        let mut extensions = vec![0, 0, 0, 16];
        extensions.append(&mut sni);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut tls = vec![22, 3, 3];
        tls.extend_from_slice(&(4 + hello.len() as u16).to_be_bytes());
        tls.push(1);
        let len = hello.len() as u32;
        tls.extend_from_slice(&len.to_be_bytes()[1..]);
        tls.extend_from_slice(&hello);

        let mut bytes = vec![0; 14 + 20 + 20];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[23] = 6;
        bytes[46] = 0x50;
        bytes[34..36].copy_from_slice(&55000_u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&443_u16.to_be_bytes());
        bytes.extend_from_slice(&tls);
        let packet = dissect(1, 0, bytes);
        assert!(packet.tls.is_some());
        assert_eq!(
            packet.tls.and_then(|metadata| metadata.server_name),
            Some("example.com".into())
        );
    }

    #[test]
    fn dissects_http_request_host() {
        let request = b"GET /status HTTP/1.1\r\nHost: api.example.test\r\n\r\n";
        let mut bytes = vec![0; 14 + 20 + 20];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[23] = 6;
        bytes[46] = 0x50;
        bytes[34..36].copy_from_slice(&51234_u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&80_u16.to_be_bytes());
        bytes.extend_from_slice(request);
        let packet = dissect(1, 0, bytes);
        assert_eq!(packet.summary.protocol, Protocol::Http);
        assert_eq!(
            packet.http.and_then(|metadata| metadata.host),
            Some("api.example.test".into())
        );
    }

    #[test]
    fn dissects_arp_request() {
        let mut bytes = vec![0; 14 + 28];
        bytes[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
        bytes[14..16].copy_from_slice(&1_u16.to_be_bytes());
        bytes[16..18].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[18] = 6;
        bytes[19] = 4;
        bytes[20..22].copy_from_slice(&1_u16.to_be_bytes());
        bytes[28..32].copy_from_slice(&[192, 0, 2, 1]);
        bytes[38..42].copy_from_slice(&[192, 0, 2, 2]);
        let packet = dissect(1, 0, bytes);
        assert_eq!(packet.summary.protocol, Protocol::Arp);
        assert!(packet.summary.info.contains("192.0.2.2"));
    }
}

