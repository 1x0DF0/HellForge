use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
};

use eframe::egui;

use crate::types::{BuildState, Log};

pub struct BuildConfig<'a> {
    pub build_bin:    &'a PathBuf,
    pub use_dll:      bool,
    pub file_path:    &'a str,
    pub early_bird:   bool,
    pub inject_field: &'a str,
    pub aa:           bool,
    pub debug:        bool,
    pub etw:          bool,
    pub unhook:       bool,
    pub sleep_obf:    bool,
    pub sleep_ms:     &'a str,
    pub out_name:     &'a str,
}

/// Spawns the `build` subprocess and streams its output into `log`.
/// Returns the command string that was run (for display in the log).
pub fn spawn_build(
    cfg:         BuildConfig,
    log:         Log,
    build_state: Arc<Mutex<BuildState>>,
    ctx:         egui::Context,
) -> Result<String, String> {
    let mut cmd = Command::new(cfg.build_bin);

    if cfg.use_dll {
        cmd.args(["--dll", cfg.file_path]);
    } else {
        cmd.args(["--payload", cfg.file_path]);
    }

    if cfg.early_bird {
        cmd.args(["--inject", "early-bird"]);
        if !cfg.inject_field.is_empty() {
            cmd.args(["--spawn", cfg.inject_field]);
        }
    } else if !cfg.inject_field.is_empty() {
        cmd.args(["--target", cfg.inject_field]);
    }

    if !cfg.aa       { cmd.arg("--no-aa");    }
    if cfg.debug     { cmd.arg("--debug");     }
    if cfg.etw       { cmd.arg("--etw-patch"); }
    if cfg.unhook    { cmd.arg("--unhook");    }
    if cfg.sleep_obf {
        cmd.arg("--sleep-obf");
        if !cfg.sleep_ms.is_empty() {
            cmd.args(["--sleep-ms", cfg.sleep_ms]);
        }
    }
    if !cfg.out_name.is_empty() {
        cmd.args(["--out", cfg.out_name]);
    }

    let cmd_display = format!(
        "> {} {}\n",
        cfg.build_bin.display(),
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    );

    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| e.to_string())?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    *build_state.lock().unwrap() = BuildState::Running;

    thread::spawn(move || {
        // read stderr on a sub-thread so neither stream blocks the other
        let log_err = Arc::clone(&log);
        let ctx_err = ctx.clone();
        let t_err = stderr.map(|s| {
            thread::spawn(move || {
                for line in BufReader::new(s).lines().map_while(Result::ok) {
                    log_err.lock().unwrap().push_str(&format!("{line}\n"));
                    ctx_err.request_repaint();
                }
            })
        });

        if let Some(s) = stdout {
            for line in BufReader::new(s).lines().map_while(Result::ok) {
                log.lock().unwrap().push_str(&format!("{line}\n"));
                ctx.request_repaint();
            }
        }

        if let Some(t) = t_err { t.join().ok(); }

        let ok = child.wait().map(|s| s.success()).unwrap_or(false);
        let msg = if ok { "[+] Build succeeded.\n" } else { "[!] Build failed.\n" };
        log.lock().unwrap().push_str(msg);
        *build_state.lock().unwrap() = BuildState::Idle;
        ctx.request_repaint();
    });

    Ok(cmd_display)
}
