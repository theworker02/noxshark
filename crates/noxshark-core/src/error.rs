use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoxSharkError {
    InvalidCapture(String),
    UnsupportedCapture(String),
    TruncatedPacket { packet: usize },
}

impl Display for NoxSharkError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCapture(reason) => write!(f, "Invalid capture: {reason}"),
            Self::UnsupportedCapture(reason) => write!(f, "Unsupported capture: {reason}"),
            Self::TruncatedPacket { packet } => write!(f, "Packet {packet} is truncated"),
        }
    }
}

impl std::error::Error for NoxSharkError {}

