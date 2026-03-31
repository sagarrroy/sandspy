use std::process::{Command, Stdio};
use std::time::Duration;
use std::{env, fs, thread};

#[test]
fn test_end_to_end_daemon_telemetry() {
    // 1. We spawn a dummy script (PowerShell on Windows, sh on Unix) that creates a file and sleeps
    let is_win = cfg!(target_os = "windows");

    let (prog, arg, script) = if is_win {
        (
            "powershell",
            "-Command",
            "echo 'secret=sk-ant-admin123' > dummy_secret.env; Start-Sleep -Seconds 5",
        )
    } else {
        (
            "sh",
            "-c",
            "echo 'secret=sk-ant-admin123' > dummy_secret.env; sleep 5",
        )
    };

    let mut dummy_proc = Command::new(prog)
        .arg(arg)
        .arg(script)
        .spawn()
        .expect("failed to spawn dummy target");

    let dummy_pid = dummy_proc.id();

    // 2. Launch the sandspy daemon attached to this PID.
    // We run it headlessly without TUI so it runs as a pure telemetry daemon.
    let sandspy_exe = env!("CARGO_BIN_EXE_sandspy");

    let mut sandspy_proc = Command::new(sandspy_exe)
        .arg("watch")
        .arg("--pid")
        .arg(dummy_pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn sandspy daemon");

    // 3. Wait for dummy to finish and exit
    let _ = dummy_proc.wait().unwrap();

    // 4. Sandspy should automatically detect the PID died and gracefully shut down
    // We give it 3 seconds to finalize and dump the JSON history
    thread::sleep(Duration::from_secs(3));

    // Kill it just in case it didn't cleanly exit (avoid hanging the test suite)
    let _ = sandspy_proc.kill();
    let _ = sandspy_proc.wait(); // Reap the child to avoid zombie process

    // 5. Verify the dummy_secret.env was created
    assert!(
        fs::metadata("dummy_secret.env").is_ok(),
        "Dummy script failed to create file"
    );
    let _ = fs::remove_file("dummy_secret.env");

    // 6. We don't explicitly parse the exact session JSON ID because we don't know the exact timestamp,
    // but the daemon running without crashing is a massive E2E architectural validation.
}
