use crate::model::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayFilter {
    Contains(String),
    Protocol(String),
    Address(String),
    Port(u16),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayFilterError(pub String);
impl std::fmt::Display for DisplayFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for DisplayFilterError {}

impl DisplayFilter {
    pub fn parse(input: &str) -> Result<Option<Self>, DisplayFilterError> {
        let text = input.trim();
        if text.is_empty() {
            return Ok(None);
        }
        let parts: Vec<_> = text.splitn(2, "==").map(str::trim).collect();
        match parts.as_slice() {
            ["protocol", value] => Ok(Some(Self::Protocol(value.to_ascii_uppercase()))),
            ["ip.addr", value] => Ok(Some(Self::Address((*value).to_owned()))),
            ["port", value] => value
                .parse()
                .map(|p| Some(Self::Port(p)))
                .map_err(|_| DisplayFilterError("port must be a number".into())),
            ["contains", value] if !value.is_empty() => {
                Ok(Some(Self::Contains(value.to_ascii_lowercase())))
            }
            _ => Err(DisplayFilterError(
                "use protocol == TLS, ip.addr == 1.2.3.4, port == 443, or contains == text".into(),
            )),
        }
    }
    pub fn matches(&self, packet: &Packet) -> bool {
        match self {
            Self::Protocol(name) => packet.protocols.iter().any(|p| p.label() == name),
            Self::Address(address) => {
                packet.summary.source == *address || packet.summary.destination == *address
            }
            Self::Port(port) => {
                packet.summary.source_port == Some(*port)
                    || packet.summary.destination_port == Some(*port)
            }
            Self::Contains(term) => format!(
                "{} {} {}",
                packet.summary.source, packet.summary.destination, packet.summary.info
            )
            .to_ascii_lowercase()
            .contains(term),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::dissect::dissect;

    use super::DisplayFilter;

    #[test]
    fn filters_by_ipv4_address() {
        let mut bytes = vec![0; 14 + 20 + 8];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[23] = 17;
        bytes[26..30].copy_from_slice(&[203, 0, 113, 10]);
        bytes[30..34].copy_from_slice(&[8, 8, 8, 8]);
        let packet = dissect(1, 0, bytes);
        assert!(
            DisplayFilter::parse("ip.addr == 203.0.113.10")
                .expect("valid filter")
                .expect("nonempty filter")
                .matches(&packet)
        );
    }
}

