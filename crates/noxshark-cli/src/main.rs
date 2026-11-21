use noxshark_core::{CaptureStatistics, DisplayFilter, conversations, endpoints, read_pcap};

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or_else(|| {
        "usage: noxshark-cli <capture> [--filter EXPR] [--format table|csv|json]".to_owned()
    })?;
    let mut filter = String::new();
    let mut format = "table".to_owned();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--filter" => {
                filter = args
                    .next()
                    .ok_or_else(|| "--filter requires an expression".to_owned())?
            }
            "--format" => {
                format = args
                    .next()
                    .ok_or_else(|| "--format requires table, csv, or json".to_owned())?
            }
            "--summary" => format = "summary".to_owned(),
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    let packets = read_pcap(&std::fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let filter = DisplayFilter::parse(&filter).map_err(|error| error.to_string())?;
    let packets: Vec<_> = packets
        .iter()
        .filter(|packet| filter.as_ref().is_none_or(|item| item.matches(packet)))
        .collect();
    match format.as_str() {
        "summary" => {
            let stats = CaptureStatistics::from_packets(
                &packets
                    .iter()
                    .map(|packet| (*packet).clone())
                    .collect::<Vec<_>>(),
            );
            println!(
                "packets: {}\nbytes: {}\nendpoints: {}\nconversations: {}\ntcp: {}\nudp: {}\ntls: {}",
                stats.total_packets,
                stats.total_bytes,
                endpoints(
                    &packets
                        .iter()
                        .map(|packet| (*packet).clone())
                        .collect::<Vec<_>>()
                )
                .len(),
                conversations(
                    &packets
                        .iter()
                        .map(|packet| (*packet).clone())
                        .collect::<Vec<_>>()
                )
                .len(),
                stats.tcp_packets,
                stats.udp_packets,
                stats.tls_packets
            );
        }
        "table" => {
            for packet in packets {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    packet.number,
                    packet.summary.source,
                    packet.summary.destination,
                    packet.summary.protocol.label(),
                    packet.summary.info
                );
            }
        }
        "csv" => {
            println!("number,source,destination,protocol,info");
            for packet in packets {
                println!(
                    "{},{},{},{},{}",
                    packet.number,
                    csv(&packet.summary.source),
                    csv(&packet.summary.destination),
                    packet.summary.protocol.label(),
                    csv(&packet.summary.info)
                );
            }
        }
        "json" => {
            print!("[");
            for (index, packet) in packets.iter().enumerate() {
                if index > 0 {
                    print!(",");
                }
                print!(
                    "{{\"number\":{},\"source\":\"{}\",\"destination\":\"{}\",\"protocol\":\"{}\",\"info\":\"{}\"}}",
                    packet.number,
                    json(&packet.summary.source),
                    json(&packet.summary.destination),
                    packet.summary.protocol.label(),
                    json(&packet.summary.info)
                );
            }
            println!("]");
        }
        _ => return Err("--format must be table, csv, json, or summary".into()),
    }
    Ok(())
}
fn csv(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
fn json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
