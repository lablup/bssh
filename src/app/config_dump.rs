// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Side-effect-free resolved SSH configuration output.

use std::io::Write as _;

use anyhow::{Context, Result};
use bssh::cli::SshDumpInvocation;
use bssh::ssh::ssh_config::{SshConfig, render_resolved_config};

/// Resolve and print ssh_config without initializing any connection services.
pub async fn handle_config_dump(invocation: &SshDumpInvocation) -> Result<()> {
    let mut config = match invocation.config_file.as_deref() {
        Some(path) if path.as_os_str() == "none" => SshConfig::new(),
        Some(path) => SshConfig::load_explicit_for_config_dump_with_options(
            path,
            &invocation.destination,
            &invocation.overrides,
        )
        .await
        .with_context(|| format!("Failed to load SSH config from {path:?}"))?,
        None => {
            SshConfig::load_default_for_config_dump_with_options(
                &invocation.destination,
                &invocation.overrides,
            )
            .await?
        }
    };
    if invocation
        .config_file
        .as_deref()
        .is_some_and(|path| path.as_os_str() == "none")
    {
        config
            .apply_cli_options(&invocation.overrides)
            .context("Failed to apply command-line SSH options")?;
    }
    if let Some(keyword) = config
        .hosts
        .iter()
        .flat_map(|host| host.unknown_options.keys())
        .next()
    {
        anyhow::bail!("Unknown SSH config option '{keyword}'");
    }
    let mut resolved = config.find_host_config(&invocation.destination);
    if invocation.stdio_forward {
        resolved.clear_all_forwardings.get_or_insert(true);
        resolved.exit_on_forward_failure.get_or_insert(true);
    }
    let rendered = render_resolved_config(&invocation.destination, &resolved)?;
    std::io::stdout()
        .write_all(rendered.as_bytes())
        .context("Failed to write resolved SSH configuration")
}
