use eframe::egui::{self, Color32, RichText};
use noxshark_core::{CaptureStatistics, DisplayFilter, Packet, read_pcap};
use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 780.0])
            .with_min_inner_size([900.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "NoxShark",
        options,
        Box::new(|cc| {
            configure_style(&cc.egui_ctx);
            Ok(Box::<NoxSharkApp>::default())
        }),
    )
}

fn configure_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = Color32::from_rgb(15, 18, 25);
    style.visuals.window_fill = Color32::from_rgb(20, 24, 33);
    style.spacing.item_spacing = egui::vec2(8.0, 8.0);
    ctx.set_style(style);
}

#[derive(Default)]
struct NoxSharkApp {
    packets: Vec<Packet>,
    filter_text: String,
    status: String,
    selected: Option<usize>,
    file: Option<PathBuf>,
}

impl NoxSharkApp {
    fn open_capture(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Capture files", &["pcap", "cap", "pcapng"])
            .pick_file()
        else {
            return;
        };
        match std::fs::read(&path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| read_pcap(&bytes).map_err(|e| e.to_string()))
        {
            Ok(packets) => {
                self.status = format!("Loaded {} packets", packets.len());
                self.file = Some(path);
                self.selected = None;
                self.packets = packets;
            }
            Err(error) => self.status = format!("Could not open capture: {error}"),
        }
    }
    fn filtered(&self) -> Result<Vec<usize>, String> {
        let filter = DisplayFilter::parse(&self.filter_text).map_err(|e| e.to_string())?;
        Ok(self
            .packets
            .iter()
            .enumerate()
            .filter_map(|(index, packet)| {
                filter
                    .as_ref()
                    .is_none_or(|value| value.matches(packet))
                    .then_some(index)
            })
            .collect())
    }
}

impl eframe::App for NoxSharkApp {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(
                    RichText::new("NOXSHARK")
                        .strong()
                        .color(Color32::from_rgb(137, 178, 255)),
                );
                ui.separator();
                if ui.button("Open capture").clicked() {
                    self.open_capture();
                }
                ui.add_enabled(false, egui::Button::new("Start capture"));
                ui.label(RichText::new("Offline analysis · Live capture adapter pending").weak());
            });
            ui.horizontal(|ui| {
                ui.label("Display filter");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.filter_text)
                        .hint_text("protocol == TLS   ·   ip.addr == 1.2.3.4   ·   port == 443"),
                );
                if response.changed() {
                    self.selected = None;
                }
            });
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(if self.status.is_empty() {
                    "Ready — open an Ethernet PCAP file to begin."
                } else {
                    &self.status
                });
                ui.separator();
                ui.label(format!("{} packets", self.packets.len()));
                if let Some(path) = &self.file {
                    ui.separator();
                    ui.label(path.display().to_string());
                }
            });
        });
        egui::SidePanel::left("sessions")
            .resizable(true)
            .default_width(210.0)
            .show(ctx, |ui| {
                ui.heading("Analysis");
                ui.separator();
                let stats = CaptureStatistics::from_packets(&self.packets);
                ui.label(RichText::new("Capture overview").strong());
                ui.label(format!("{} frames · {} bytes", stats.total_packets, stats.total_bytes));
                ui.small(format!("IPv4 {} · IPv6 {}", stats.ipv4_packets, stats.ipv6_packets));
                ui.small(format!("TLS {} · DNS {}", stats.tls_packets, stats.dns_packets));
                ui.small(format!("HTTP {} · ARP {}", stats.http_packets, stats.arp_packets));
                ui.separator();
                ui.label(RichText::new("Capture filters").strong());
                ui.small("Validated syntax ready for an approved live adapter:");
                ui.monospace("tcp and port 443");
                ui.monospace("host 10.0.0.1");
                ui.separator();
                ui.label(RichText::new("TLS visibility").strong());
                ui.small("NoxShark surfaces record and ClientHello SNI metadata. It does not decrypt traffic or bypass encryption.");
            });
        egui::CentralPanel::default().show(ctx, |ui| match self.filtered() {
            Err(error) => {
                ui.colored_label(Color32::LIGHT_RED, error);
            }
            Ok(rows) => {
                let mut requested_selection = None;
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Packets ({})", rows.len())).strong());
                    ui.label("Click a row to inspect its decoded layers.");
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("packet-list")
                    .show(ui, |ui| {
                        egui::Grid::new("packets")
                            .striped(true)
                            .min_col_width(68.0)
                            .show(ui, |ui| {
                                ui.strong("No.");
                                ui.strong("Source");
                                ui.strong("Destination");
                                ui.strong("Protocol");
                                ui.strong("Length");
                                ui.strong("Info");
                                ui.end_row();
                                for index in rows {
                                    let packet = &self.packets[index];
                                    let selected = self.selected == Some(packet.number);
                                    if ui
                                        .selectable_label(selected, packet.number.to_string())
                                        .clicked()
                                    {
                                        requested_selection = Some(packet.number);
                                    }
                                    ui.label(&packet.summary.source);
                                    ui.label(&packet.summary.destination);
                                    ui.label(packet.summary.protocol.label());
                                    ui.label(packet.captured_len.to_string());
                                    ui.label(&packet.summary.info);
                                    ui.end_row();
                                }
                            });
                    });
                if let Some(number) = requested_selection {
                    self.selected = Some(number);
                }
            }
        });
        egui::TopBottomPanel::bottom("detail")
            .resizable(true)
            .default_height(170.0)
            .show(ctx, |ui| {
                ui.heading("Packet inspector");
                if let Some(number) = self.selected {
                    if let Some(packet) = self.packets.iter().find(|packet| packet.number == number)
                    {
                        ui.monospace(format!(
                            "Frame {} · {} bytes · layers: {}",
                            packet.number,
                            packet.captured_len,
                            packet
                                .protocols
                                .iter()
                                .map(|p| p.label())
                                .collect::<Vec<_>>()
                                .join(" → ")
                        ));
                        if let Some(tls) = &packet.tls {
                            ui.label(format!(
                                "TLS: {} · {}{}",
                                tls.record_type,
                                tls.version,
                                tls.server_name
                                    .as_ref()
                                    .map(|s| format!(" · SNI {s}"))
                                    .unwrap_or_default()
                            ));
                        }
                        if let Some(dns) = &packet.dns {
                            ui.label(format!(
                                "DNS: {} · transaction {:04x}{}",
                                if dns.is_response { "response" } else { "query" },
                                dns.transaction_id,
                                dns.query_type
                                    .as_ref()
                                    .map(|query_type| format!(" · {query_type}"))
                                    .unwrap_or_default()
                            ));
                        }
                        if let Some(http) = &packet.http {
                            ui.label(format!(
                                "HTTP {}: {} {}{}",
                                http.message_type,
                                http.method_or_status,
                                http.target_or_reason,
                                http.host
                                    .as_ref()
                                    .map(|host| format!(" · Host {host}"))
                                    .unwrap_or_default()
                            ));
                        }
                        ui.separator();
                        ui.monospace(
                            packet
                                .bytes
                                .iter()
                                .take(128)
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" "),
                        );
                    }
                } else {
                    ui.weak("Select a packet to view its decoded details and bounded hex preview.");
                }
            });
    }
}

