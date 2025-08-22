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

use crate::executor::ParallelExecutor;
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
    pub output_dir: Option<&'a Path>,
}

pub async fn execute_command(params: ExecuteCommandParams<'_>) -> Result<()> {
    println!(
        "{}",
        OutputFormatter::format_command_header(params.command, params.nodes.len())
    );

    let key_path = params.key_path.map(|p| p.to_string_lossy().to_string());
    let executor = ParallelExecutor::new_with_all_options(
        params.nodes,
        params.max_parallel,
        key_path,
        params.strict_mode,
        params.use_agent,
        params.use_password,
    );

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

    if failed_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}
