// Copyright 2025 Lablup Inc. and Jeongkyu Shin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Side-effect-free resolved SSH configuration output.

use std::io::Write as _;

use anyhow::{Context, Result};
use bssh::cli::{Cli, SshDumpInvocation};
use bssh::ssh::ssh_config::{SshConfig, render_resolved_config};

/// Resolve and print ssh_config without initializing any connection services.
pub async fn handle_config_dump(cli: &Cli, args: &[String]) -> Result<()> {
    let destination = cli
        .destination
        .as_deref()
        .context("-G requires a destination")?;
    let invocation = SshDumpInvocation::from_argv(args, destination)?;
    let mut config = match invocation.config_file.as_deref() {
        Some(path) if path.as_os_str() == "none" => SshConfig::new(),
        Some(path) => SshConfig::load_from_file_for_host(path, &invocation.destination)
            .await
            .with_context(|| format!("Failed to load SSH config from {path:?}"))?,
        None => SshConfig::load_default_for_host(&invocation.destination).await?,
    };
    config
        .apply_cli_options(&invocation.overrides)
        .context("Failed to apply command-line SSH options")?;
    if let Some(keyword) = config
        .hosts
        .iter()
        .flat_map(|host| host.unknown_options.keys())
        .next()
    {
        anyhow::bail!("Unknown SSH config option '{keyword}'");
    }
    let resolved = config.find_host_config(&invocation.destination);
    let rendered = render_resolved_config(&invocation.destination, &resolved)?;
    std::io::stdout()
        .write_all(rendered.as_bytes())
        .context("Failed to write resolved SSH configuration")
}
