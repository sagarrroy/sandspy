# Contributing to Sandspy

We want Sandspy to be the definitive security standard for autonomous AI agents. If you want to help us harden it, introduce new telemetry hooks, or add support for new AI agents, you are welcome here.

## 🛠️ Developer Setup 

1. **Clone the Repository:**
```bash
git clone https://github.com/user/sandspy.git
cd sandspy
```

2. **Run the Development Build:**
```bash
cargo build
```

3. **Verify the Engine:**
Sandspy employs a strict automated CI pipeline to ensure zero friction on user machines. Before submitting a PR, run the exhaustive test suite:
```bash
cargo test
```

4. **Formatting & Lints (Mandatory):**
We do not accept sloppy code. You must format your Rust files and resolve all `clippy` warnings.
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

## 🔄 Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Ensure you have added `#[cfg(test)]` coverage for any new logic you implement, particularly within `src/events.rs` and `src/analysis/`.
3. If you changed the UI, attach a screenshot of the `sandspy watch --dashboard` changes in the PR description.
4. Open the Pull Request. If the `GitHub Actions` CI matrix fails (Windows/Mac/Linux), you must fix the breakages before we will review.

## 🧠 Code Standards
- **Zero-Friction:** Sandspy runs natively in user-space. Do not introduce requirements for `sudo` execution or kernel-level drivers. Maintain wide OS compatibility.
- **Fail Gracefully:** If an OS call returns an error (like `Access Denied` on protected memory), silently catch the `Result` or `expect()` instead of panicking the application. The daemon must survive.
- **Brutalist Branding:** The CLI output and generated terminal interfaces use minimal emojis, pitch black backgrounds, and monospaced typography. Keep the vibe highly serious.
