#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Ethernet,
    Vlan,
    Ipv4,
    Ipv6,
    Arp,
    Icmp,
    Icmpv6,
    Tcp,
    Udp,
    Dns,
    Dhcp,
    Tls,
    Http,
    Unknown,
}

impl Protocol {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ethernet => "ETH",
            Self::Vlan => "VLAN",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Arp => "ARP",
            Self::Icmp => "ICMP",
            Self::Icmpv6 => "ICMPv6",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Dns => "DNS",
            Self::Dhcp => "DHCP",
            Self::Tls => "TLS",
            Self::Http => "HTTP",
            Self::Unknown => "DATA",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsMetadata {
    pub record_type: String,
    pub version: String,
    pub server_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMetadata {
    pub transaction_id: u16,
    pub is_response: bool,
    pub query_name: Option<String>,
    pub query_type: Option<String>,
    pub answer_count: u16,
    pub response_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMetadata {
    pub message_type: Option<String>,
    pub client_hostname: Option<String>,
    pub requested_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMetadata {
    pub message_type: String,
    pub method_or_status: String,
    pub target_or_reason: String,
    pub host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpMetadata {
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub flags: Vec<&'static str>,
    pub payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSummary {
    pub source: String,
    pub destination: String,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Protocol,
    pub info: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub number: usize,
    pub timestamp_micros: u64,
    pub captured_len: u32,
    pub bytes: Vec<u8>,
    pub protocols: Vec<Protocol>,
    pub summary: PacketSummary,
    pub tls: Option<TlsMetadata>,
    pub dns: Option<DnsMetadata>,
    pub dhcp: Option<DhcpMetadata>,
    pub http: Option<HttpMetadata>,
    pub tcp: Option<TcpMetadata>,
}
