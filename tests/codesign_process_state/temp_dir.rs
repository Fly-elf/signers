//! Tests that need `TMPDIR` pointed at a directory of their own, to watch the
//! scratch directory `extract_certificates` reads `codesign`'s files from.

use signers::codesign::extract_certificates;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::future::IntoFuture;
use std::path::{Path, PathBuf};

use signers::Error;

use crate::support::fixture::Workspace;

const PLATFORM_BINARY: &str = "/bin/ls";

fn entries(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("could not list {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect()
}

#[test]
fn nothing_is_left_behind_once_the_run_ends() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let tmp = workspace.dir("tmp");
    let adhoc = workspace.adhoc_signed("adhoc");
    let unsigned = workspace.unsigned("unsigned");
    let out = workspace.join("out");

    let (succeeded, failed) = {
        let _tmpdir = ScopedTmpdir::to(&tmp);
        let runtime = crate::runtime();
        let succeeded = runtime.block_on(
            extract_certificates(vec![PathBuf::from(PLATFORM_BINARY), adhoc])
                .save_to(&out)
                .into_future(),
        );
        let failed = runtime.block_on(
            extract_certificates(vec![PathBuf::from(PLATFORM_BINARY), unsigned]).into_future(),
        );
        (succeeded, failed)
    };

    succeeded.expect("the run failed");
    assert!(
        matches!(failed, Err(Error::Batch(_))),
        "the unsigned target did not fail: {failed:?}"
    );
    assert_eq!(entries(&tmp), Vec::<PathBuf>::new());
}

/// Dropping the future mid-run removes the scratch directory too.
#[test]
fn nothing_is_left_behind_by_a_cancelled_run() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let tmp = workspace.dir("tmp");

    let finished_first = {
        let _tmpdir = ScopedTmpdir::to(&tmp);
        crate::runtime().block_on(async {
            let run = extract_certificates(vec![PLATFORM_BINARY; 64]).into_future();
            tokio::pin!(run);
            // Polled side by side until the scratch directory shows up, then
            // dropped with its runs still in flight.
            tokio::select! {
                _ = &mut run => true,
                () = appears_in(&tmp) => false,
            }
        })
    };

    assert!(
        !finished_first,
        "the run ended before it could be cancelled"
    );
    assert_eq!(entries(&tmp), Vec::<PathBuf>::new());
}

async fn appears_in(dir: &Path) {
    while entries(dir).is_empty() {
        tokio::task::yield_now().await;
    }
}

#[test]
fn an_unusable_temporary_directory_is_an_io_error() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let missing = workspace.join("missing");

    let result = {
        let _tmpdir = ScopedTmpdir::to(&missing);
        crate::runtime().block_on(extract_certificates(PLATFORM_BINARY).into_future())
    };

    match result.unwrap_err() {
        Error::Io { path, source } => {
            assert_eq!(path, missing);
            assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
        }
        other => panic!("expected Io, got {other:?}"),
    }
}

struct ScopedTmpdir(Option<OsString>);

impl ScopedTmpdir {
    /// Points `TMPDIR` at `dir`.
    ///
    /// The caller must hold [`crate::serialised`]: mutating the environment is
    /// only sound while no other thread reads it, and every tokio runtime in
    /// this binary is built inside a test body, after this call.
    fn to(dir: &Path) -> Self {
        let previous = env::var_os("TMPDIR");
        // SAFETY: single-threaded with respect to the environment, as above.
        unsafe { env::set_var("TMPDIR", dir) };
        Self(previous)
    }
}

impl Drop for ScopedTmpdir {
    fn drop(&mut self) {
        // SAFETY: as in `to` — the runtime that read `TMPDIR` is gone by now.
        unsafe {
            match self.0.take() {
                Some(dir) => env::set_var("TMPDIR", dir),
                None => env::remove_var("TMPDIR"),
            }
        }
    }
}
