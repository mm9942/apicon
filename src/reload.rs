use nix::libc;
use serde::{Deserialize, Serialize};
use signal_hook::iterator::Signals;
use std::{
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tempfile::NamedTempFile;

#[derive(Serialize, Deserialize)]
pub struct ReloadState {
    pub config: PathBuf,
    pub queue_depth: usize,
    pub hash_dos_count: usize,
}

pub fn setup_reload_handler(queue: Arc<AtomicUsize>, hash: Arc<AtomicUsize>, config: PathBuf) {
    std::thread::spawn(move || {
        if let Ok(mut signals) = Signals::new([signal_hook::consts::signal::SIGHUP]) {
            for _ in signals.forever() {
                let state = ReloadState {
                    config: config.to_owned(),
                    queue_depth: queue.load(Ordering::SeqCst),
                    hash_dos_count: hash.load(Ordering::SeqCst),
                };
                if let Ok(tmp) = NamedTempFile::new() {
                    if serde_json::to_writer(&tmp, &state).is_ok() {
                        let path = tmp.into_temp_path();
                        if let Ok(exe) = std::env::current_exe() {
                            let args: Vec<String> = std::env::args().skip(1).collect();
                            let mut cmd = Command::new(exe);
                            cmd.args(&args);
                            cmd.env("APICON_STATE_FILE", &path);
                            if cmd.spawn().is_ok() {
                                unsafe {
                                    libc::raise(libc::SIGQUIT);
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

pub fn load_state() {
    if let Ok(path) = std::env::var("APICON_STATE_FILE") {
        if let Ok(file) = std::fs::File::open(path) {
            if let Ok(state) = serde_json::from_reader::<_, ReloadState>(file) {
                tracing::info!(
                    target = "reload",
                    queue_depth = state.queue_depth,
                    hash_dos_count = state.hash_dos_count,
                    "state restored",
                );
            }
        }
    }
}
