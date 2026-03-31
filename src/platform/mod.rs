// sandspy::platform — OS-specific implementations

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub fn process_tree(pid: u32) -> Vec<u32> {
    #[cfg(target_os = "windows")]
    {
        return windows::process_tree(pid);
    }

    #[cfg(target_os = "linux")]
    {
        return linux::process_tree(pid);
    }

    #[allow(unreachable_code)]
    {
        let _ = pid;
        Vec::new()
    }
}
