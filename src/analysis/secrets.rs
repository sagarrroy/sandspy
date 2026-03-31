// sandspy::analysis::secrets — Secret/credential pattern detection
//
// Scans text content for credentials, API keys, and sensitive data.
// Patterns are compiled once from embedded definitions (no file dependency).

use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub matched_value: String,
    pub start: usize,
    pub end: usize,
}

struct CompiledPattern {
    name: &'static str,
    regex: Regex,
}

static PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();

/// Scan arbitrary text for secrets. Returns all matches, deduplicated by pattern.
pub fn scan_text(content: &str) -> Vec<SecretMatch> {
    if content.is_empty() {
        return Vec::new();
    }

    let patterns = PATTERNS.get_or_init(build_patterns);
    let mut findings = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for pattern in patterns {
        for m in pattern.regex.find_iter(content) {
            let key = format!("{}:{}", pattern.name, m.as_str());
            if seen.insert(key) {
                findings.push(SecretMatch {
                    pattern_name: pattern.name.to_string(),
                    matched_value: m.as_str().to_string(),
                    start: m.start(),
                    end: m.end(),
                });
            }
        }
    }

    findings.sort_by_key(|e| e.start);
    findings
}

/// Also check if a file EXTENSION or NAME strongly implies it contains secrets,
/// even without scanning content (for binary or large files).
pub fn is_sensitive_filename(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let sensitive_names = [
        ".env",
        "credentials",
        "secrets",
        "keystore",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        "known_hosts",
    ];
    let sensitive_exts = [
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".cer",
        ".crt",
    ];

    for name in &sensitive_names {
        if lower.contains(name) {
            return true;
        }
    }
    for ext in &sensitive_exts {
        if lower.ends_with(ext) {
            return true;
        }
    }
    false
}

/// Risk contribution for a secret match (0–100 additive scale).
pub fn secret_risk_score(pattern_name: &str) -> u32 {
    match pattern_name {
        "Private Key" => 30,
        "Anthropic API Key" | "OpenAI API Key" | "OpenAI Legacy Key" => 25,
        "AWS Access Key" | "AWS Secret Key" => 25,
        "GitHub Token" | "GitHub Fine-Grained Token" => 20,
        "Stripe Live Key" => 25,
        "Stripe Test Key" => 10,
        "Google API Key" => 20,
        "Slack Token" => 15,
        "JWT Token" => 15,
        "Connection String" => 20,
        "Password in URL" => 20,
        "Env File Secret" | "Generic API Key" => 15,
        _ => 10,
    }
}

/// Returns true if the matched string looks like a placeholder, example, or documentation key.
/// These show up in READMEs, handoff docs, and test code but are not real credentials.
pub fn is_placeholder_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();

    // AWS documentation example key
    if lower.contains("example") || lower.contains("your_key") || lower.contains("your-key") {
        return true;
    }

    // Common placeholder words
    let placeholders = [
        "placeholder",
        "changeme",
        "replace_me",
        "insert_here",
        "xxxxxxxx",
        "aaaaaaaa",
        "12345678",
        "abcdefgh",
        "1234567890",
        "testtest",
        "dummy",
        "fake",
        "sample",
        "demo",
        "password",
        "user:pass",
        "user:password",
        "MIIEowIBAAKCAQEA",
    ];
    if placeholders.iter().any(|p| lower.contains(p)) {
        return true;
    }

    // Detect low-entropy values: if more than 60% of chars are from the same 4-char set,
    // it's probably a repeating fake sequence like "aaabbbcccdddeee"
    let alnum: Vec<char> = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if alnum.len() >= 16 {
        let mut freq = [0u32; 128];
        for &c in &alnum {
            freq[c as usize] += 1;
        }
        let max_freq = freq.iter().max().copied().unwrap_or(0);
        // If any single character makes up >35% of the value, it's low entropy
        if max_freq as f64 / alnum.len() as f64 > 0.35 {
            return true;
        }
    }

    false
}

// ─── Pattern definitions (embedded — no file dependency) ─────────────────────

fn build_patterns() -> Vec<CompiledPattern> {
    // (name, regex)
    let defs: &[(&'static str, &str)] = &[
        // === Cloud Provider Keys ===
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        (
            "AWS Secret Key",
            r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        ),
        ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}"),
        // === AI Provider Keys ===
        ("Anthropic API Key", r"sk-ant-[a-zA-Z0-9_\-]{20,}"),
        ("OpenAI API Key", r"sk-proj-[a-zA-Z0-9_\-]{20,}"),
        ("OpenAI Legacy Key", r"sk-[a-zA-Z0-9]{48}"),
        // === Source Control ===
        ("GitHub Token", r"ghp_[A-Za-z0-9]{36}"),
        ("GitHub Fine-Grained Token", r"github_pat_[A-Za-z0-9_]{82}"),
        ("GitLab Token", r"glpat-[A-Za-z0-9\-_]{20}"),
        // === Payment ===
        ("Stripe Live Key", r"sk_live_[0-9a-zA-Z]{24,}"),
        ("Stripe Test Key", r"sk_test_[0-9a-zA-Z]{24,}"),
        // === Communication ===
        (
            "Slack Token",
            r"xox[bpraos]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}",
        ),
        (
            "Slack Webhook",
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        ),
        // === Auth Tokens ===
        (
            "JWT Token",
            r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+",
        ),
        ("Bearer Token", r"(?i)bearer\s+[A-Za-z0-9\-_\.]{30,}"),
        // === Private Keys ===
        (
            "Private Key",
            r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY( BLOCK)?-----",
        ),
        // === Database ===
        (
            "Connection String",
            r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|mssql|sqlserver)://[^\s]{10,}",
        ),
        // === Generic credential patterns ===
        ("Password in URL", r"://.{1,64}:.{8,}@[^\s]+"),
        (
            "Generic API Key",
            r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?key)\s*[=:]\s*[A-Za-z0-9_\-\.]{16,}",
        ),
        (
            "Env File Secret",
            r"(?i)^(ANTHROPIC_API_KEY|OPENAI_API_KEY|OPENAI_KEY|GEMINI_API_KEY|DATABASE_URL|DB_PASSWORD|SECRET_KEY|AUTH_SECRET|JWT_SECRET|GITHUB_TOKEN|STRIPE_SECRET|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|TWILIO_AUTH_TOKEN|SENDGRID_API_KEY|CLOUDINARY_SECRET)\s*=\s*\S{8,}",
        ),
    ];

    defs.iter()
        .filter_map(|(name, pattern)| match Regex::new(pattern) {
            Ok(regex) => Some(CompiledPattern { name, regex }),
            Err(e) => {
                eprintln!("[sandspy] failed to compile pattern '{name}': {e}");
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_key_detected() {
        let text = "ANTHROPIC_API_KEY=sk-ant-api01-abcdefghijklmnopqrstuvwxyz0123456789";
        let matches = scan_text(text);
        assert!(
            !matches.is_empty(),
            "should detect Anthropic key, got: {:?}",
            matches
        );
    }

    #[test]
    fn openai_key_detected() {
        let text = "OPENAI_API_KEY=sk-proj-abc1234567890abcdefghijklmnopqrstuvwxyz0123";
        let matches = scan_text(text);
        assert!(
            !matches.is_empty(),
            "should detect OpenAI key, got: {:?}",
            matches
        );
    }

    #[test]
    fn aws_key_detected() {
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let matches = scan_text(text);
        assert!(!matches.is_empty(), "should detect AWS key");
    }

    #[test]
    fn private_key_detected() {
        let text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...";
        let matches = scan_text(text);
        assert!(!matches.is_empty(), "should detect private key header");
    }

    #[test]
    fn stripe_live_key_detected() {
        let text = "STRIPE_SECRET=sk_live_abcdefghijklmnopqrstuvwxyz";
        let matches = scan_text(text);
        assert!(!matches.is_empty(), "should detect Stripe live key");
    }

    #[test]
    fn env_file_secret_match() {
        let text = "DATABASE_URL=postgres://user:password@host:5432/db";
        let matches = scan_text(text);
        assert!(!matches.is_empty(), "should detect DATABASE_URL");
    }

    #[test]
    fn jwt_detected() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let matches = scan_text(text);
        assert!(!matches.is_empty(), "should detect JWT");
    }

    #[test]
    fn no_false_positive_on_normal_text() {
        let text = "Hello world, this is a normal README file with no secrets.";
        let matches = scan_text(text);
        assert!(
            matches.is_empty(),
            "should not flag normal text: {:?}",
            matches
        );
    }
}
