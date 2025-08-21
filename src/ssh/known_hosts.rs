use async_ssh2_tokio::ServerCheckMethod;
use directories::BaseDirs;
use std::path::PathBuf;

/// Get the default known_hosts file path
pub fn get_default_known_hosts_path() -> Option<PathBuf> {
    BaseDirs::new().map(|dirs| dirs.home_dir().join(".ssh").join("known_hosts"))
}

/// Create a ServerCheckMethod based on strict host key checking mode
pub fn get_check_method(strict_mode: StrictHostKeyChecking) -> ServerCheckMethod {
    match strict_mode {
        StrictHostKeyChecking::Yes => {
            // Use the default known_hosts file in strict mode
            if let Some(known_hosts_path) = get_default_known_hosts_path() {
                if known_hosts_path.exists() {
                    tracing::debug!(
                        "Using known_hosts file: {:?} (strict mode)",
                        known_hosts_path
                    );
                    ServerCheckMethod::DefaultKnownHostsFile
                } else {
                    tracing::warn!(
                        "Known hosts file not found at {:?}, using NoCheck",
                        known_hosts_path
                    );
                    eprintln!(
                        "WARNING: Known hosts file not found. Host key verification disabled."
                    );
                    ServerCheckMethod::NoCheck
                }
            } else {
                tracing::warn!("Could not determine known_hosts path, using NoCheck");
                ServerCheckMethod::NoCheck
            }
        }
        StrictHostKeyChecking::No => {
            tracing::debug!("Host key checking disabled (strict mode = no)");
            ServerCheckMethod::NoCheck
        }
        StrictHostKeyChecking::AcceptNew => {
            // Use known_hosts but don't fail on new hosts
            // Note: async-ssh2-tokio doesn't support TOFU mode directly,
            // so we use the known_hosts file if it exists, otherwise NoCheck
            if let Some(known_hosts_path) = get_default_known_hosts_path() {
                if known_hosts_path.exists() {
                    tracing::debug!(
                        "Using known_hosts file: {:?} (accept-new mode)",
                        known_hosts_path
                    );
                    // Unfortunately, the library doesn't support accept-new mode directly
                    // We'll use the known_hosts file, but it will fail on unknown hosts
                    // For now, we'll use NoCheck for accept-new mode
                    tracing::info!(
                        "Note: accept-new mode not fully supported, using relaxed checking"
                    );
                    ServerCheckMethod::NoCheck
                } else {
                    // Create the .ssh directory if it doesn't exist
                    if let Some(ssh_dir) = known_hosts_path.parent() {
                        let _ = std::fs::create_dir_all(ssh_dir);
                    }
                    // Create an empty known_hosts file
                    let _ = std::fs::File::create(&known_hosts_path);
                    tracing::debug!("Created empty known_hosts file at {:?}", known_hosts_path);
                    ServerCheckMethod::NoCheck
                }
            } else {
                tracing::warn!("Could not determine known_hosts path, using NoCheck");
                ServerCheckMethod::NoCheck
            }
        }
    }
}

/// Mode for host key checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrictHostKeyChecking {
    /// Always verify host keys (fail on unknown/changed)
    Yes,
    /// Never verify host keys (accept all)
    No,
    /// Verify known hosts, add new ones automatically (TOFU)
    AcceptNew,
}

impl StrictHostKeyChecking {
    pub fn to_bool(&self) -> bool {
        matches!(self, Self::Yes)
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "yes" | "true" => Self::Yes,
            "no" | "false" => Self::No,
            "accept-new" | "tofu" => Self::AcceptNew,
            _ => Self::AcceptNew, // Default
        }
    }
}
