/// Common test utilities and helpers for e2e tests

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

/// Test environment manager that captures and restores env vars
pub struct TestEnv {
    original_vars: HashMap<String, Option<String>>,
    keys_to_track: Vec<String>,
}

impl TestEnv {
    /// Create a new test environment manager
    pub fn new() -> Self {
        Self {
            original_vars: HashMap::new(),
            keys_to_track: Vec::new(),
        }
    }

    /// Set an environment variable and track it for cleanup
    ///
    /// # Safety
    /// This modifies environment variables which is inherently unsafe in multi-threaded
    /// contexts. Only use in single-threaded test scenarios.
    pub fn set(&mut self, key: &str, value: &str) -> &mut Self {
        // Save original value if not already tracked
        if !self.keys_to_track.contains(&key.to_string()) {
            let original = env::var(key).ok();
            self.original_vars.insert(key.to_string(), original);
            self.keys_to_track.push(key.to_string());
        }

        // SAFETY: Tests are run with --test-threads=1 or this is called before spawning threads
        unsafe { env::set_var(key, value) };
        self
    }

    /// Remove an environment variable and track it for cleanup
    ///
    /// # Safety
    /// This modifies environment variables which is inherently unsafe in multi-threaded
    /// contexts. Only use in single-threaded test scenarios.
    pub fn remove(&mut self, key: &str) -> &mut Self {
        // Save original value if not already tracked
        if !self.keys_to_track.contains(&key.to_string()) {
            let original = env::var(key).ok();
            self.original_vars.insert(key.to_string(), original);
            self.keys_to_track.push(key.to_string());
        }

        // SAFETY: Tests are run with --test-threads=1 or this is called before spawning threads
        unsafe { env::remove_var(key) };
        self
    }

    /// Restore all tracked environment variables to their original state
    pub fn restore(&self) {
        for key in &self.keys_to_track {
            if let Some(original) = self.original_vars.get(key) {
                // SAFETY: Called during test cleanup
                unsafe {
                    match original {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Shared test state for coordination between tests
#[derive(Default)]
pub struct TestState {
    pub kms_calls: Arc<Mutex<Vec<String>>>,
}

impl TestState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_kms_call(&self, key_id: &str) {
        self.kms_calls.lock().unwrap().push(key_id.to_string());
    }

    pub fn get_kms_calls(&self) -> Vec<String> {
        self.kms_calls.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.kms_calls.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_set_and_restore() {
        let original = env::var("TEST_VAR").ok();

        {
            let mut test_env = TestEnv::new();
            test_env.set("TEST_VAR", "test_value");
            assert_eq!(env::var("TEST_VAR").unwrap(), "test_value");
        }

        // After drop, should be restored
        assert_eq!(env::var("TEST_VAR").ok(), original);
    }

    #[test]
    fn test_env_remove_and_restore() {
        // SAFETY: Test environment, single-threaded
        unsafe { env::set_var("TEST_VAR_REMOVE", "initial") };

        {
            let mut test_env = TestEnv::new();
            test_env.remove("TEST_VAR_REMOVE");
            assert!(env::var("TEST_VAR_REMOVE").is_err());
        }

        // After drop, should be restored
        assert_eq!(env::var("TEST_VAR_REMOVE").unwrap(), "initial");

        // Cleanup
        // SAFETY: Test environment, single-threaded
        unsafe { env::remove_var("TEST_VAR_REMOVE") };
    }
}
