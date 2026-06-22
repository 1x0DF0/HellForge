use std::sync::{Arc, Mutex};

use eframe::egui;

pub fn show(ui: &mut egui::Ui, log: &Arc<Mutex<String>>) {
    let mut log_snap = log.lock().unwrap().clone();
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
}
