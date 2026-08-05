//! The `codesign` tests that cannot share a process with the rest of the suite.
//!
//! Each submodule mutates one kind of process-global state — the working
//! directory, `PATH` — that every other test deliberately leaves alone. Cargo
//! runs each integration target as its own process, so keeping them here
//! isolates them from the main suite; [`serialised`] then keeps the submodules
//! from running alongside *each other*, since tests within one binary still
//! share threads.

#![cfg(target_os = "macos")]

#[path = "../support/mod.rs"]
mod support;

mod executable_path;
mod working_directory;

use std::sync::{Mutex, MutexGuard, PoisonError};

static PROCESS: Mutex<()> = Mutex::new(());

/// Held for the duration of a test that mutates process state, so the other
/// submodule's test cannot run at the same time and see it mid-mutation.
#[must_use = "the lock releases as soon as this is dropped"]
fn serialised() -> MutexGuard<'static, ()> {
    PROCESS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A runtime built inside the test body, so the process state each test sets up
/// is already in place before tokio exists.
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("could not build a tokio runtime")
}
