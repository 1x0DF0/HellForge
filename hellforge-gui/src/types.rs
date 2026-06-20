use std::sync::{Arc, Mutex};

pub type Log = Arc<Mutex<String>>;

#[derive(PartialEq, Clone, Copy)]
pub enum BuildState {
    Idle,
    Running,
}

pub const PAYLOAD_TYPES: &[&str] = &[
    "windows/x64/exec CMD=calc.exe",
    "windows/x64/exec CMD=cmd.exe",
    "windows/x64/meterpreter/reverse_tcp",
    "windows/x64/meterpreter/reverse_https",
    "windows/x64/meterpreter_reverse_tcp",
    "windows/x64/meterpreter_reverse_https",
    "windows/x64/shell_reverse_tcp",
];

pub fn needs_conn(p: &str) -> bool {
    p.contains("reverse") || p.contains("bind")
}
