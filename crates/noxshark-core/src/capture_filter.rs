use crate::model::{Packet, Protocol};

/// A deliberately small, auditable capture-filter language. This is evaluated
/// after import in v0.1; a future privileged adapter may translate it to a BPF
/// program only after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureFilter {
    Any,
    Protocol(Protocol),
    Host(String),
    Port(u16),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
    Not(Box<Self>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFilterError(pub String);

impl std::fmt::Display for CaptureFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for CaptureFilterError {}

impl CaptureFilter {
    pub fn parse(input: &str) -> Result<Self, CaptureFilterError> {
        let tokens: Vec<_> = input.split_whitespace().collect();
        if tokens.is_empty() || input.trim() == "any" {
            return Ok(Self::Any);
        }
        parse_or(&tokens)
    }

    pub fn matches(&self, packet: &Packet) -> bool {
        match self {
            Self::Any => true,
            Self::Protocol(protocol) => packet.protocols.contains(protocol),
            Self::Host(host) => {
                &packet.summary.source == host || &packet.summary.destination == host
            }
            Self::Port(port) => {
                packet.summary.source_port == Some(*port)
                    || packet.summary.destination_port == Some(*port)
            }
            Self::And(left, right) => left.matches(packet) && right.matches(packet),
            Self::Or(left, right) => left.matches(packet) || right.matches(packet),
            Self::Not(inner) => !inner.matches(packet),
        }
    }
}

fn parse_or(tokens: &[&str]) -> Result<CaptureFilter, CaptureFilterError> {
    if let Some(index) = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("or"))
    {
        return Ok(CaptureFilter::Or(
            Box::new(parse_or(&tokens[..index])?),
            Box::new(parse_or(&tokens[index + 1..])?),
        ));
    }
    if let Some(index) = tokens
        .iter()
        .position(|token| token.eq_ignore_ascii_case("and"))
    {
        return Ok(CaptureFilter::And(
            Box::new(parse_or(&tokens[..index])?),
            Box::new(parse_or(&tokens[index + 1..])?),
        ));
    }
    if tokens
        .first()
        .is_some_and(|token| token.eq_ignore_ascii_case("not"))
    {
        return Ok(CaptureFilter::Not(Box::new(parse_or(&tokens[1..])?)));
    }
    match tokens {
        [protocol] => protocol_from_name(protocol).map(CaptureFilter::Protocol),
        ["host", host] => Ok(CaptureFilter::Host((*host).to_owned())),
        ["port", port] => port
            .parse()
            .map(CaptureFilter::Port)
            .map_err(|_| CaptureFilterError("port must be an unsigned 16-bit number".into())),
        _ => Err(CaptureFilterError(
            "expected protocol, `host ADDRESS`, `port NUMBER`, or boolean combination".into(),
        )),
    }
}

fn protocol_from_name(name: &str) -> Result<Protocol, CaptureFilterError> {
    match name.to_ascii_lowercase().as_str() {
        "tcp" => Ok(Protocol::Tcp),
        "udp" => Ok(Protocol::Udp),
        "dns" => Ok(Protocol::Dns),
        "tls" => Ok(Protocol::Tls),
        "http" => Ok(Protocol::Http),
        "arp" => Ok(Protocol::Arp),
        "icmp" => Ok(Protocol::Icmp),
        "icmpv6" => Ok(Protocol::Icmpv6),
        "ip" | "ipv4" => Ok(Protocol::Ipv4),
        "ip6" | "ipv6" => Ok(Protocol::Ipv6),
        _ => Err(CaptureFilterError(format!("unknown protocol `{name}`"))),
    }
}

#[cfg(test)]
mod tests {
    use crate::{Protocol, dissect::dissect};

    use super::CaptureFilter;

    #[test]
    fn combines_protocol_and_port_predicates() {
        let mut bytes = vec![0; 14 + 20 + 20];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[23] = 6;
        bytes[26..30].copy_from_slice(&[192, 0, 2, 1]);
        bytes[30..34].copy_from_slice(&[192, 0, 2, 2]);
        bytes[34..36].copy_from_slice(&51234_u16.to_be_bytes());
        bytes[36..38].copy_from_slice(&443_u16.to_be_bytes());
        bytes[46] = 0x50;
        let packet = dissect(1, 0, bytes);

        assert_eq!(packet.summary.protocol, Protocol::Tcp);
        assert!(
            CaptureFilter::parse("tcp and port 443")
                .expect("valid filter")
                .matches(&packet)
        );
    }
}

