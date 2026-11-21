//! Windows Npcap adapter. It is intentionally separate from offline parsing.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{self, Receiver, Sender},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureInterface {
    pub name: String,
    pub description: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConfiguration {
    pub interface: String,
    pub filter: String,
    pub promiscuous: bool,
    pub snaplen: i32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureEvent {
    Packet {
        timestamp_micros: u64,
        bytes: Vec<u8>,
    },
    Error(String),
    Stopped,
}
pub struct CaptureSession {
    receiver: Receiver<CaptureEvent>,
    stop: Arc<AtomicBool>,
}
impl CaptureSession {
    #[must_use]
    pub fn receiver(&self) -> &Receiver<CaptureEvent> {
        &self.receiver
    }
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

#[cfg(windows)]
pub fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    pcap::Device::list()
        .map_err(|error| error.to_string())
        .map(|devices| {
            devices
                .into_iter()
                .map(|device| CaptureInterface {
                    name: device.name,
                    description: device.desc,
                })
                .collect()
        })
}
#[cfg(not(windows))]
pub fn list_interfaces() -> Result<Vec<CaptureInterface>, String> {
    Err("Live capture is currently supported only on Windows with Npcap".into())
}

#[cfg(windows)]
pub fn start_capture(config: CaptureConfiguration) -> Result<CaptureSession, String> {
    if config.filter.trim().is_empty() {
        return Err("A validated capture filter is required".into());
    }
    let (sender, receiver) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("noxshark-npcap".into())
        .spawn(move || run_capture(config, worker_stop, sender))
        .map_err(|error| error.to_string())?;
    Ok(CaptureSession { receiver, stop })
}
#[cfg(not(windows))]
pub fn start_capture(_: CaptureConfiguration) -> Result<CaptureSession, String> {
    Err("Live capture is currently supported only on Windows with Npcap".into())
}

#[cfg(windows)]
fn run_capture(config: CaptureConfiguration, stop: Arc<AtomicBool>, sender: Sender<CaptureEvent>) {
    let result = (|| -> Result<(), String> {
        let device = pcap::Device::list()
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|device| device.name == config.interface)
            .ok_or_else(|| "Selected interface is no longer available".to_owned())?;
        let mut capture = pcap::Capture::from_device(device)
            .map_err(|error| error.to_string())?
            .promisc(config.promiscuous)
            .snaplen(config.snaplen)
            .timeout(250)
            .open()
            .map_err(|error| error.to_string())?;
        capture
            .filter(&config.filter, true)
            .map_err(|error| error.to_string())?;
        while !stop.load(Ordering::Acquire) {
            match capture.next_packet() {
                Ok(packet) => {
                    let seconds = u64::try_from(packet.header.ts.tv_sec).unwrap_or(0);
                    let micros = u64::try_from(packet.header.ts.tv_usec).unwrap_or(0);
                    if sender
                        .send(CaptureEvent::Packet {
                            timestamp_micros: seconds
                                .saturating_mul(1_000_000)
                                .saturating_add(micros),
                            bytes: packet.data.to_vec(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = sender.send(CaptureEvent::Error(error));
    }
    let _ = sender.send(CaptureEvent::Stopped);
}
