//! Clean-room packet parsing and filtering primitives for NoxShark.
//!
//! This crate only parses capture files supplied by the caller. It does not
//! capture traffic, open sockets, or decrypt TLS payloads.

pub mod capture;
pub mod capture_filter;
pub mod display_filter;
pub mod dissect;
pub mod error;
pub mod fields;
pub mod model;
pub mod pcap;
pub mod pcapng;
pub mod reassembly;
pub mod registry;
pub mod statistics;

pub use capture::{CaptureAvailability, npcap_availability};
pub use capture_filter::{CaptureFilter, CaptureFilterError};
pub use display_filter::{DisplayFilter, DisplayFilterError};
pub use error::NoxSharkError;
pub use fields::{PacketField, PacketFieldValue, packet_fields};
pub use model::{
    DhcpMetadata, DnsMetadata, HttpMetadata, Packet, PacketSummary, Protocol, TcpMetadata,
    TlsMetadata,
};
pub use pcap::read_pcap;
pub use reassembly::{TcpStream, TcpStreamKey, reassemble_tcp_streams};
pub use statistics::CaptureStatistics;
