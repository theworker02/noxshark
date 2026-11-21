//! Clean-room packet parsing and filtering primitives for NoxShark.
//!
//! This crate only parses capture files supplied by the caller. It does not
//! capture traffic, open sockets, or decrypt TLS payloads.

pub mod capture_filter;
pub mod display_filter;
pub mod dissect;
pub mod error;
pub mod model;
pub mod pcap;
pub mod pcapng;
pub mod statistics;

pub use capture_filter::{CaptureFilter, CaptureFilterError};
pub use display_filter::{DisplayFilter, DisplayFilterError};
pub use error::NoxSharkError;
pub use model::{
    DhcpMetadata, DnsMetadata, HttpMetadata, Packet, PacketSummary, Protocol, TcpMetadata,
    TlsMetadata,
};
pub use pcap::read_pcap;
pub use statistics::CaptureStatistics;
