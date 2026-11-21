//! Explicit boundary for future privileged capture backends.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureAvailability {
    Available,
    Unavailable(String),
}

/// Windows Npcap discovery without loading a DLL or opening an interface.
/// Actual capture requires a separately reviewed native backend.
#[must_use]
pub fn npcap_availability() -> CaptureAvailability {
    if !cfg!(windows) {
        return CaptureAvailability::Unavailable("Npcap capture is Windows-only".into());
    }
    let windir = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
    let path = std::path::Path::new(&windir)
        .join("System32")
        .join("wpcap.dll");
    if path.is_file() {
        CaptureAvailability::Available
    } else {
        CaptureAvailability::Unavailable(
            "Npcap was not detected; install Npcap before enabling a reviewed capture backend"
                .into(),
        )
    }
}
