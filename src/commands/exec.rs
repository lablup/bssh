// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::Result;
use std::path::Path;

use crate::executor::{ExitCodeStrategy, ParallelExecutor, RankDetector};
use crate::forwarding::ForwardingType;
use crate::node::Node;
use crate::ssh::known_hosts::StrictHostKeyChecking;
use crate::ui::OutputFormatter;
use crate::utils::output::save_outputs_to_files;

pub struct ExecuteCommandParams<'a> {
    pub nodes: Vec<Node>,
    pub command: &'a str,
    pub max_parallel: usize,
    pub key_path: Option<&'a Path>,
    pub verbose: bool,
    pub strict_mode: StrictHostKeyChecking,
    pub use_agent: bool,
    pub use_password: bool,
    #[cfg(target_os = "macos")]
    pub use_keychain: bool,
    pub output_dir: Option<&'a Path>,
    pub timeout: Option<u64>,
    pub jump_hosts: Option<&'a str>,
    pub port_forwards: Option<Vec<ForwardingType>>,
    pub require_all_success: bool,
    pub check_all_nodes: bool,
}

pub async fn execute_command(params: ExecuteCommandParams<'_>) -> Result<()> {
    // Display command header
    println!(
        "{}",
        OutputFormatter::format_command_header(params.command, params.nodes.len())
    );

    // Handle port forwarding if specified
    if let Some(ref forwards) = params.port_forwards {
        if !forwards.is_empty() {
            return execute_command_with_forwarding(params).await;
        }
    }

    // Execute command without port forwarding (original behavior)
    execute_command_without_forwarding(params).await
}

/// Execute command with port forwarding active
async fn execute_command_with_forwarding(params: ExecuteCommandParams<'_>) -> Result<()> {
    use crate::forwarding::{ForwardingConfig, ForwardingManager};
    use std::sync::Arc;

    // Note: This is a simplified implementation for SSH compatibility
    // For full multi-node forwarding, we would need to handle forwarding per node

    println!("Setting up port forwarding...");

    let forwards = params.port_forwards.as_ref().unwrap();
    let node = &params.nodes[0]; // Use first node for SSH compatibility mode

    // Display forwarding information
    for forward in forwards {
        println!("  {forward}");
    }

    // Create forwarding manager
    let forwarding_config = ForwardingConfig::default();
    let mut manager = ForwardingManager::new(forwarding_config);

    // Create SSH client for forwarding
    use crate::ssh::known_hosts::StrictHostKeyChecking;
    use crate::ssh::tokio_client::{AuthMethod, Client, ServerCheckMethod};

    // Determine authentication method
    let auth_method = if params.use_agent {
        #[cfg(not(target_os = "windows"))]
        {
            AuthMethod::with_agent()
        }
        #[cfg(target_os = "windows")]
        {
            return Err(anyhow::anyhow!("SSH agent not supported on Windows"));
        }
    } else if params.use_password {
        // For password auth, we'd need to prompt - for now return error
        return Err(anyhow::anyhow!(
            "Password authentication not yet supported with port forwarding"
        ));
    } else {
        // Use default key file authentication
        let key_path = params
            .key_path
            .map(|p| p.to_path_buf())
            .or_else(|| {
                // Try default SSH key locations
                let home = std::env::var("HOME").ok()?;
                let ed25519_path = std::path::PathBuf::from(&home)
                    .join(".ssh")
                    .join("id_ed25519");
                let rsa_path = std::path::PathBuf::from(&home).join(".ssh").join("id_rsa");

                if ed25519_path.exists() {
                    Some(ed25519_path)
                } else if rsa_path.exists() {
                    Some(rsa_path)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("No SSH key found for port forwarding"))?;

        AuthMethod::with_key_file(key_path, None)
    };

    // Determine server check method
    let server_check = match params.strict_mode {
        StrictHostKeyChecking::Yes => ServerCheckMethod::DefaultKnownHostsFile,
        StrictHostKeyChecking::No => ServerCheckMethod::NoCheck,
        StrictHostKeyChecking::AcceptNew => ServerCheckMethod::DefaultKnownHostsFile, // Could be enhanced
    };

    // Create SSH client
    let ssh_client = Arc::new(
        Client::connect(
            (node.host.as_str(), node.port),
            &node.username,
            auth_method,
            server_check,
        )
        .await?,
    );

    println!(
        "SSH connection established to {}@{}",
        node.username, node.host
    );

    // Start port forwarding
    let mut forwarding_ids = Vec::new();

    for forward in forwards {
        // Add forwarding specification
        let id = manager.add_forwarding(forward.clone()).await?;
        forwarding_ids.push(id);

        // Start the forwarding
        manager
            .start_forwarding(id, Arc::clone(&ssh_client))
            .await?;
    }

    println!("Port forwarding active. Executing command...");

    // Execute the actual command
    let result = execute_command_without_forwarding(ExecuteCommandParams {
        port_forwards: None, // Remove forwarding from params to avoid recursion
        ..params
    })
    .await;

    // Cleanup: stop forwarding
    println!("Stopping port forwarding...");
    for id in forwarding_ids {
        if let Err(e) = manager.stop_forwarding(id).await {
            eprintln!("Warning: Failed to stop forwarding {id}: {e}");
        }
    }

    // Give forwarding a moment to clean up
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    result
}

/// Execute command without port forwarding (original implementation)
async fn execute_command_without_forwarding(params: ExecuteCommandParams<'_>) -> Result<()> {
    // Save nodes for later use (before moving into executor)
    let nodes_for_rank_detection = params.nodes.clone();

    let key_path = params.key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new_with_all_options(
        params.nodes,
        params.max_parallel,
        key_path,
        params.strict_mode,
        params.use_agent,
        params.use_password,
    )
    .with_timeout(params.timeout)
    .with_jump_hosts(params.jump_hosts.map(|s| s.to_string()));

    // Set keychain usage if on macOS
    #[cfg(target_os = "macos")]
    let executor = executor.with_keychain(params.use_keychain);

    let results = executor.execute(params.command).await?;

    // Save outputs to files if output_dir is specified
    if let Some(dir) = params.output_dir {
        save_outputs_to_files(&results, dir, params.command).await?;
    }

    // Print results
    for result in &results {
        result.print_output(params.verbose);
    }

    // Print summary
    let success_count = results.iter().filter(|r| r.is_success()).count();
    let failed_count = results.len() - success_count;

    println!(
        "{}",
        OutputFormatter::format_summary(results.len(), success_count, failed_count)
    );

    // Determine exit code strategy from CLI flags
    let strategy = if params.require_all_success {
        ExitCodeStrategy::RequireAllSuccess
    } else if params.check_all_nodes {
        ExitCodeStrategy::MainRankWithFailureCheck
    } else {
        ExitCodeStrategy::MainRank // Default in v1.2.0+
    };

    // Identify main rank
    let main_idx = RankDetector::identify_main_rank(&nodes_for_rank_detection);

    // Calculate exit code using the strategy
    let exit_code = strategy.calculate(&results, main_idx);

    // Exit with the calculated exit code
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
