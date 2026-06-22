#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod injection;
mod logger;
mod msf;
mod runner;
mod types;

use app::HellForge;

fn main() -> eframe::Result {
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HellForge  [Windows x64 output only]")
            .with_inner_size([640.0, 640.0])
            .with_min_inner_size([500.0, 500.0]),
        ..Default::default()
    };
    eframe::run_native(
        "HellForge",
        opts,
        Box::new(|cc| Ok(Box::new(HellForge::new(cc)))),
    )
}
