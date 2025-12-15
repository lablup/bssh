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

//! Performance Benchmarks for Large Output Handling
//!
//! This module benchmarks:
//! - Large output handling (>10MB)
//! - RollingBuffer overflow behavior
//! - Memory usage under load
//! - Concurrent multi-node streaming

use bssh::executor::{MultiNodeStreamManager, NodeStream};
use bssh::node::Node;
use bssh::ssh::tokio_client::CommandOutput;
use bssh::ui::tui::app::TuiApp;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use russh::CryptoVec;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

/// Create a test runtime for async benchmarks
fn create_runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ============================================================================
// Large Output Benchmarks
// ============================================================================

/// Benchmark NodeStream with large output data
fn bench_large_output_single_stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_output");

    // Test different output sizes: 1KB, 100KB, 1MB, 10MB
    for size in [1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("single_stream", format!("{size} bytes")),
            size,
            |b, &size| {
                let rt = create_runtime();
                b.iter(|| {
                    rt.block_on(async {
                        let node = Node::new("localhost".to_string(), 22, "user".to_string());
                        let (tx, rx) = mpsc::channel::<CommandOutput>(1000);
                        let mut stream = NodeStream::new(node, rx);

                        // Send data in 32KB chunks (typical SSH packet size)
                        let chunk_size = 32 * 1024;
                        let chunk = CryptoVec::from(vec![b'x'; chunk_size.min(size)]);
                        let num_chunks = size.div_ceil(chunk_size);

                        for _ in 0..num_chunks {
                            let _ = tx.send(CommandOutput::StdOut(chunk.clone())).await;
                        }
                        drop(tx);

                        // Poll all data
                        while stream.poll() {
                            // Continue polling
                        }

                        black_box(stream.stdout().len())
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark RollingBuffer with overflow (exceeding 10MB limit)
fn bench_rolling_buffer_overflow(c: &mut Criterion) {
    let mut group = c.benchmark_group("rolling_buffer_overflow");

    // Test writing more than 10MB to trigger overflow
    for overflow_factor in [1.5_f64, 2.0_f64, 3.0_f64].iter() {
        let total_size = (10.0 * 1024.0 * 1024.0 * overflow_factor) as usize;
        group.throughput(Throughput::Bytes(total_size as u64));

        group.bench_with_input(
            BenchmarkId::new("overflow", format!("{overflow_factor}x")),
            &total_size,
            |b, &total_size| {
                let rt = create_runtime();
                b.iter(|| {
                    rt.block_on(async {
                        let node = Node::new("localhost".to_string(), 22, "user".to_string());
                        let (tx, rx) = mpsc::channel::<CommandOutput>(1000);
                        let mut stream = NodeStream::new(node, rx);

                        // Send data in chunks to exceed buffer limit
                        let chunk_size = 64 * 1024; // 64KB chunks
                        let chunk = CryptoVec::from(vec![b'x'; chunk_size]);
                        let num_chunks = total_size / chunk_size;

                        for _ in 0..num_chunks {
                            let _ = tx.send(CommandOutput::StdOut(chunk.clone())).await;
                            // Poll periodically to simulate real usage
                            stream.poll();
                        }
                        drop(tx);

                        while stream.poll() {}

                        // Buffer should be limited to 10MB
                        black_box(stream.stdout().len())
                    })
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Multi-Node Streaming Benchmarks
// ============================================================================

/// Benchmark concurrent multi-node streaming
fn bench_concurrent_multi_node(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_multi_node");

    for num_nodes in [4, 16, 64].iter() {
        group.bench_with_input(
            BenchmarkId::new("nodes", num_nodes),
            num_nodes,
            |b, &num_nodes| {
                let rt = create_runtime();
                b.iter(|| {
                    rt.block_on(async {
                        let mut manager = MultiNodeStreamManager::new();
                        let mut senders = Vec::new();

                        // Create all node streams
                        for i in 0..num_nodes {
                            let node = Node::new(format!("host{i}"), 22, "user".to_string());
                            let (tx, rx) = mpsc::channel::<CommandOutput>(100);
                            manager.add_stream(node, rx);
                            senders.push(tx);
                        }

                        // Send data to all nodes
                        let data_per_node = 100 * 1024; // 100KB per node
                        let chunk = CryptoVec::from(vec![b'x'; 1024]);
                        let chunks_per_node = data_per_node / 1024;

                        for _ in 0..chunks_per_node {
                            for tx in &senders {
                                let _ = tx.send(CommandOutput::StdOut(chunk.clone())).await;
                            }
                            manager.poll_all();
                        }

                        // Close all channels
                        for tx in senders {
                            drop(tx);
                        }

                        while manager.poll_all() {}

                        black_box(manager.completed_count())
                    })
                });
            },
        );
    }

    group.finish();
}

/// Benchmark manager poll_all with varying data rates
fn bench_poll_all_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("poll_all_throughput");

    for chunk_size in [256, 1024, 8192, 32768].iter() {
        group.throughput(Throughput::Bytes(*chunk_size as u64 * 10));

        group.bench_with_input(
            BenchmarkId::new("chunk_size", chunk_size),
            chunk_size,
            |b, &chunk_size| {
                let rt = create_runtime();
                b.iter(|| {
                    rt.block_on(async {
                        let mut manager = MultiNodeStreamManager::new();
                        let mut senders = Vec::new();

                        // Create 10 node streams
                        for i in 0..10 {
                            let node = Node::new(format!("host{i}"), 22, "user".to_string());
                            let (tx, rx) = mpsc::channel::<CommandOutput>(100);
                            manager.add_stream(node, rx);
                            senders.push(tx);
                        }

                        let chunk = CryptoVec::from(vec![b'x'; chunk_size]);

                        // Send one chunk to each node and poll
                        for tx in &senders {
                            let _ = tx.send(CommandOutput::StdOut(chunk.clone())).await;
                        }

                        black_box(manager.poll_all())
                    })
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// TUI Rendering Benchmarks
// ============================================================================

/// Benchmark TUI rendering with many nodes
fn bench_tui_render_summary(c: &mut Criterion) {
    let mut group = c.benchmark_group("tui_render_summary");

    for num_nodes in [5, 20, 50].iter() {
        group.bench_with_input(
            BenchmarkId::new("nodes", num_nodes),
            num_nodes,
            |b, &num_nodes| {
                let mut manager = MultiNodeStreamManager::new();
                for i in 0..num_nodes {
                    let node = Node::new(format!("host{i}.example.com"), 22, format!("user{i}"));
                    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
                    manager.add_stream(node, rx);
                }

                let backend = TestBackend::new(120, 40);
                let mut terminal = Terminal::new(backend).unwrap();

                b.iter(|| {
                    terminal
                        .draw(|f| {
                            bssh::ui::tui::views::summary::render(
                                f,
                                &manager,
                                "benchmark-cluster",
                                "echo test",
                                false,
                            );
                        })
                        .unwrap();
                    black_box(())
                });
            },
        );
    }

    group.finish();
}

/// Benchmark TUI rendering with output data
fn bench_tui_render_detail(c: &mut Criterion) {
    let mut group = c.benchmark_group("tui_render_detail");

    for output_lines in [100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("lines", output_lines),
            output_lines,
            |b, &output_lines| {
                let rt = create_runtime();

                // Pre-create the stream with output data
                let node = Node::new(
                    "benchmark-host.example.com".to_string(),
                    22,
                    "user".to_string(),
                );
                let (tx, rx) = mpsc::channel::<CommandOutput>(100);
                let mut stream = NodeStream::new(node, rx);

                // Generate output
                let mut output = String::new();
                for i in 0..output_lines {
                    output.push_str(&format!(
                        "Line {i}: This is a test line with some content\n"
                    ));
                }

                rt.block_on(async {
                    tx.send(CommandOutput::StdOut(CryptoVec::from(
                        output.as_bytes().to_vec(),
                    )))
                    .await
                    .unwrap();
                    drop(tx);
                });
                stream.poll();

                let backend = TestBackend::new(120, 40);
                let mut terminal = Terminal::new(backend).unwrap();

                b.iter(|| {
                    terminal
                        .draw(|f| {
                            bssh::ui::tui::views::detail::render(f, &stream, 0, 0, false, false);
                        })
                        .unwrap();
                    black_box(())
                });
            },
        );
    }

    group.finish();
}

// ============================================================================
// Data Change Detection Benchmarks
// ============================================================================

/// Benchmark TuiApp data change detection
fn bench_data_change_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_change_detection");

    for num_nodes in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("nodes", num_nodes),
            num_nodes,
            |b, &num_nodes| {
                let mut manager = MultiNodeStreamManager::new();
                for i in 0..num_nodes {
                    let node = Node::new(format!("host{i}"), 22, "user".to_string());
                    let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
                    manager.add_stream(node, rx);
                }

                let mut app = TuiApp::new();
                // Initial detection
                app.check_data_changes(manager.streams());

                b.iter(|| black_box(app.check_data_changes(manager.streams())));
            },
        );
    }

    group.finish();
}

// ============================================================================
// Memory Usage Benchmarks
// ============================================================================

/// Benchmark memory allocation patterns
fn bench_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocation");
    group.sample_size(50); // Reduce sample size for memory tests

    group.bench_function("create_100_streams", |b| {
        b.iter(|| {
            let mut manager = MultiNodeStreamManager::new();
            for i in 0..100 {
                let node = Node::new(format!("host{i}"), 22, "user".to_string());
                let (_tx, rx) = mpsc::channel::<CommandOutput>(100);
                manager.add_stream(node, rx);
            }
            black_box(manager.total_count())
        });
    });

    group.bench_function("create_tui_app", |b| {
        b.iter(|| {
            let app = TuiApp::new();
            black_box(app)
        });
    });

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    bench_large_output_single_stream,
    bench_rolling_buffer_overflow,
    bench_concurrent_multi_node,
    bench_poll_all_throughput,
    bench_tui_render_summary,
    bench_tui_render_detail,
    bench_data_change_detection,
    bench_memory_allocation,
);

criterion_main!(benches);
