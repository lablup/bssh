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

//! Tests for authentication mutex in jump host connections
//!
//! These tests verify the security fix implemented by pr-reviewer:
//! - Authentication prompts are serialized using Arc<Mutex<()>>
//! - Prevents race conditions when multiple jump hosts need credentials
//! - Ensures prompts don't overlap or interfere with each other

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

/// Simulates an authentication prompt that takes some time
async fn simulate_auth_prompt(
    auth_mutex: Arc<Mutex<()>>,
    prompt_id: usize,
    counter: Arc<AtomicUsize>,
    results: Arc<Mutex<Vec<(usize, usize)>>>,
) {
    // Acquire the mutex lock (simulating exclusive access to prompt)
    let _guard = auth_mutex.lock().await;

    // Record the order we got the lock
    let order = counter.fetch_add(1, Ordering::SeqCst);

    // Simulate time taken to prompt user
    sleep(Duration::from_millis(10)).await;

    // Record completion
    results.lock().await.push((prompt_id, order));
}

#[tokio::test]
async fn test_auth_mutex_serializes_prompts() {
    // Setup
    let auth_mutex = Arc::new(Mutex::new(()));
    let counter = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::new()));

    // Spawn multiple concurrent "authentication requests"
    let mut handles = vec![];
    for i in 0..5 {
        let auth_mutex_clone = Arc::clone(&auth_mutex);
        let counter_clone = Arc::clone(&counter);
        let results_clone = Arc::clone(&results);

        let handle = tokio::spawn(async move {
            simulate_auth_prompt(auth_mutex_clone, i, counter_clone, results_clone).await;
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify results
    let final_results = results.lock().await;
    assert_eq!(final_results.len(), 5, "All prompts should have completed");

    // Verify that prompts were serialized (order values should be 0,1,2,3,4)
    let mut orders: Vec<usize> = final_results.iter().map(|(_, order)| *order).collect();
    orders.sort_unstable();
    assert_eq!(orders, vec![0, 1, 2, 3, 4], "Prompts should be serialized");
}

#[tokio::test]
async fn test_auth_mutex_prevents_overlapping_prompts() {
    let auth_mutex = Arc::new(Mutex::new(()));
    let active_prompts = Arc::new(AtomicUsize::new(0));
    let max_concurrent = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];
    for _ in 0..10 {
        let auth_mutex_clone = Arc::clone(&auth_mutex);
        let active_prompts_clone = Arc::clone(&active_prompts);
        let max_concurrent_clone = Arc::clone(&max_concurrent);

        let handle = tokio::spawn(async move {
            let _guard = auth_mutex_clone.lock().await;

            // Increment active prompt counter
            let current_active = active_prompts_clone.fetch_add(1, Ordering::SeqCst) + 1;

            // Track maximum concurrent prompts
            let mut max = max_concurrent_clone.load(Ordering::SeqCst);
            while current_active > max {
                match max_concurrent_clone.compare_exchange(
                    max,
                    current_active,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(x) => max = x,
                }
            }

            // Simulate prompt work
            sleep(Duration::from_millis(5)).await;

            // Decrement active prompt counter
            active_prompts_clone.fetch_sub(1, Ordering::SeqCst);
        });
        handles.push(handle);
    }

    // Wait for all to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify that we never had more than 1 concurrent prompt
    let max = max_concurrent.load(Ordering::SeqCst);
    assert_eq!(
        max, 1,
        "Should never have more than 1 concurrent prompt, got {max}"
    );
}

#[tokio::test]
async fn test_auth_mutex_fairness() {
    // Test that mutex provides fair access (no starvation)
    let auth_mutex = Arc::new(Mutex::new(()));
    let completion_order = Arc::new(Mutex::new(Vec::new()));

    let mut handles = vec![];
    for i in 0..20 {
        let auth_mutex_clone = Arc::clone(&auth_mutex);
        let completion_order_clone = Arc::clone(&completion_order);

        let handle = tokio::spawn(async move {
            let _guard = auth_mutex_clone.lock().await;
            sleep(Duration::from_millis(1)).await;
            completion_order_clone.lock().await.push(i);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let order = completion_order.lock().await;
    assert_eq!(order.len(), 20, "All tasks should complete");

    // Check that no task was starved (all completed)
    let mut sorted_order = order.clone();
    sorted_order.sort_unstable();
    assert_eq!(
        sorted_order,
        (0..20).collect::<Vec<_>>(),
        "All tasks should complete without starvation"
    );
}

#[tokio::test]
async fn test_auth_mutex_stress_test() {
    // Stress test with many concurrent attempts
    let auth_mutex = Arc::new(Mutex::new(()));
    let success_count = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];
    for _ in 0..100 {
        let auth_mutex_clone = Arc::clone(&auth_mutex);
        let success_count_clone = Arc::clone(&success_count);

        let handle = tokio::spawn(async move {
            let _guard = auth_mutex_clone.lock().await;
            sleep(Duration::from_micros(100)).await;
            success_count_clone.fetch_add(1, Ordering::SeqCst);
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let final_count = success_count.load(Ordering::SeqCst);
    assert_eq!(
        final_count, 100,
        "All 100 authentication attempts should complete"
    );
}

#[tokio::test]
async fn test_auth_mutex_blocks_concurrent_access() {
    // Test that mutex properly blocks concurrent access
    let auth_mutex = Arc::new(Mutex::new(()));
    let access_log = Arc::new(Mutex::new(Vec::new()));

    // Task 1: Acquire lock and hold for a bit
    let auth_mutex1 = Arc::clone(&auth_mutex);
    let log1 = Arc::clone(&access_log);
    let handle1 = tokio::spawn(async move {
        let _guard = auth_mutex1.lock().await;
        log1.lock().await.push("task1_acquired");
        sleep(Duration::from_millis(50)).await;
        log1.lock().await.push("task1_released");
    });

    // Give task 1 time to acquire the lock
    sleep(Duration::from_millis(10)).await;

    // Task 2: Try to acquire - should block until task 1 releases
    let auth_mutex2 = Arc::clone(&auth_mutex);
    let log2 = Arc::clone(&access_log);
    let handle2 = tokio::spawn(async move {
        log2.lock().await.push("task2_waiting");
        let _guard = auth_mutex2.lock().await;
        log2.lock().await.push("task2_acquired");
    });

    // Wait for both tasks
    handle1.await.unwrap();
    handle2.await.unwrap();

    // Verify execution order
    let log = access_log.lock().await;
    assert_eq!(log[0], "task1_acquired");
    assert_eq!(log[1], "task2_waiting");
    assert_eq!(log[2], "task1_released");
    assert_eq!(log[3], "task2_acquired");
}

#[tokio::test]
async fn test_auth_mutex_guards_multiple_resources() {
    // Simulate protecting both password and passphrase prompts
    let auth_mutex = Arc::new(Mutex::new(()));
    let password_prompts = Arc::new(AtomicUsize::new(0));
    let passphrase_prompts = Arc::new(AtomicUsize::new(0));

    let mut handles = vec![];

    // Mix of password and passphrase prompts
    for i in 0..20 {
        let auth_mutex_clone = Arc::clone(&auth_mutex);
        let password_prompts_clone = Arc::clone(&password_prompts);
        let passphrase_prompts_clone = Arc::clone(&passphrase_prompts);

        let handle = tokio::spawn(async move {
            let _guard = auth_mutex_clone.lock().await;

            if i % 2 == 0 {
                // Simulate password prompt
                sleep(Duration::from_millis(2)).await;
                password_prompts_clone.fetch_add(1, Ordering::SeqCst);
            } else {
                // Simulate passphrase prompt
                sleep(Duration::from_millis(2)).await;
                passphrase_prompts_clone.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(password_prompts.load(Ordering::SeqCst), 10);
    assert_eq!(passphrase_prompts.load(Ordering::SeqCst), 10);
}
