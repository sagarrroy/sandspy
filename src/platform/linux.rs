// sandspy::platform::linux — Linux-specific enhancements

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

pub fn process_tree(pid: u32) -> Vec<u32> {
	let task_root = PathBuf::from(format!("/proc/{pid}/task"));
	let entries = match fs::read_dir(&task_root) {
		Ok(value) => value,
		Err(_) => return Vec::new(),
	};

	let mut children = HashSet::new();
	for entry in entries.flatten() {
		let tid = entry.file_name().to_string_lossy().to_string();
		let children_path = task_root.join(tid).join("children");
		let content = match fs::read_to_string(children_path) {
			Ok(value) => value,
			Err(_) => continue,
		};

		for token in content.split_whitespace() {
			if let Ok(child_pid) = token.parse::<u32>() {
				children.insert(child_pid);
			}
		}
	}

	let mut output = children.into_iter().collect::<Vec<_>>();
	output.sort_unstable();
	output
}
