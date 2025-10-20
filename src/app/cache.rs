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

//! Cache statistics and management functionality

use bssh::ssh::GLOBAL_CACHE;
use owo_colors::OwoColorize;

/// Handle cache statistics command
pub async fn handle_cache_stats(detailed: bool, clear: bool, maintain: bool) {
    if clear {
        if let Err(e) = GLOBAL_CACHE.clear() {
            eprintln!("Failed to clear cache: {e}");
            return;
        }
        println!("{}", "Cache cleared".green());
    }

    if maintain {
        match GLOBAL_CACHE.maintain().await {
            Ok(removed) => println!(
                "{}: Removed {} expired/stale entries",
                "Cache maintenance".yellow(),
                removed
            ),
            Err(e) => {
                eprintln!("Failed to maintain cache: {e}");
                return;
            }
        }
    }

    let stats = match GLOBAL_CACHE.stats() {
        Ok(stats) => stats,
        Err(e) => {
            eprintln!("Failed to get cache stats: {e}");
            return;
        }
    };
    let config = GLOBAL_CACHE.config();

    println!("\n{}", "SSH Configuration Cache Statistics".cyan().bold());
    println!("=====================================");

    // Basic statistics
    println!("\n{}", "Cache Configuration:".bright_blue());
    println!(
        "  Enabled: {}",
        if config.enabled {
            format!("{}", "Yes".green())
        } else {
            format!("{}", "No".red())
        }
    );
    println!("  Max Entries: {}", config.max_entries.to_string().cyan());
    println!("  TTL: {}", format!("{:?}", config.ttl).cyan());

    println!("\n{}", "Cache Statistics:".bright_blue());
    println!(
        "  Current Entries: {}/{}",
        stats.current_entries.to_string().cyan(),
        stats.max_entries.to_string().yellow()
    );

    let total_requests = stats.hits + stats.misses;
    if total_requests > 0 {
        println!(
            "  Hit Rate: {:.1}% ({}/{} requests)",
            (stats.hit_rate() * 100.0).to_string().green(),
            stats.hits.to_string().green(),
            total_requests.to_string().cyan()
        );
        println!(
            "  Miss Rate: {:.1}% ({} misses)",
            (stats.miss_rate() * 100.0).to_string().yellow(),
            stats.misses.to_string().yellow()
        );
    } else {
        println!("  No cache requests yet");
    }

    println!("\n{}", "Eviction Statistics:".bright_blue());
    println!(
        "  TTL Evictions: {}",
        stats.ttl_evictions.to_string().yellow()
    );
    println!(
        "  Stale Evictions: {}",
        stats.stale_evictions.to_string().yellow()
    );
    println!(
        "  LRU Evictions: {}",
        stats.lru_evictions.to_string().yellow()
    );

    if detailed && stats.current_entries > 0 {
        println!("\n{}", "Detailed Entry Information:".bright_blue());
        match GLOBAL_CACHE.debug_info() {
            Ok(debug_info) => {
                for (path, info) in debug_info {
                    println!("  {}: {}", path.display().to_string().cyan(), info);
                }
            }
            Err(e) => {
                eprintln!("Failed to get debug info: {e}");
            }
        }
    }

    if !config.enabled {
        println!("\n{}", "Note: Caching is currently disabled".red());
        println!("Set BSSH_CACHE_ENABLED=true to enable caching");
    } else if stats.current_entries == 0 && total_requests == 0 {
        println!("\n{}", "Note: No SSH configs have been loaded yet".yellow());
        println!("Try running some bssh commands to populate the cache");
    }

    println!("\n{}", "Environment Variables:".bright_blue());
    println!(
        "  BSSH_CACHE_ENABLED={}",
        std::env::var("BSSH_CACHE_ENABLED").unwrap_or_else(|_| "true (default)".to_string())
    );
    println!(
        "  BSSH_CACHE_SIZE={}",
        std::env::var("BSSH_CACHE_SIZE").unwrap_or_else(|_| "100 (default)".to_string())
    );
    println!(
        "  BSSH_CACHE_TTL={}",
        std::env::var("BSSH_CACHE_TTL").unwrap_or_else(|_| "300 (default)".to_string())
    );
}
