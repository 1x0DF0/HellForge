use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

pub fn dll_injection(dll_path: &PathBuf, log: Arc<Mutex<String>>) -> Result<(), String> {
    let _ = (dll_path, log);
    Err("not yet implemented".into())
}
