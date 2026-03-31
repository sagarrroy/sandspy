// sandspy::platform::windows — Windows-specific enhancements

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};

pub fn process_tree(pid: u32) -> Vec<u32> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let handle = match snapshot {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };

    if handle == HANDLE(INVALID_HANDLE_VALUE.0) {
        return Vec::new();
    }

    let mut children = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut has_entry = unsafe { Process32FirstW(handle, &mut entry).is_ok() };
    while has_entry {
        if entry.th32ParentProcessID == pid {
            children.push(entry.th32ProcessID);
        }
        has_entry = unsafe { Process32NextW(handle, &mut entry).is_ok() };
    }

    let _ = unsafe { CloseHandle(handle) };
    children
}
