//! `.run()` brings its own runtime: it needs none around it, and refuses to
//! block a thread that is already driving one.

use std::fs::File;
use std::process::Command;
use std::{env, thread};

use signers::codesign::blocking::remove_signature;
use signers::codesign::blocking::{sign_adhoc, verify};
use signers::{Error, ProcessError};

use crate::support::fixture::Workspace;
use crate::support::inspect;

/// Each call has a runtime of its own, so calls from several threads at once
/// don't interfere, and a thread can run one call after another.
#[test]
fn runs_from_several_threads_at_once_and_one_after_another() {
    let workspace = Workspace::new();
    let targets: Vec<_> = (0..4)
        .map(|i| workspace.unsigned(format!("hello-{i}")))
        .collect();

    thread::scope(|scope| {
        for target in &targets {
            scope.spawn(move || {
                sign_adhoc(target).run().unwrap();
                verify(target).run().unwrap();
                remove_signature(target).run().unwrap();
            });
        }
    });

    for target in &targets {
        assert!(!inspect::is_signed(target), "{}", target.display());
    }
}

#[tokio::test]
#[should_panic(expected = "from within a runtime")]
async fn running_inside_an_async_runtime_panics() {
    let _ = verify("/bin/ls").run();
}

/// With every file descriptor taken, the runtime a call builds for itself
/// cannot open its event queue. That is a failure to start the tool whose cause
/// names the runtime and keeps the operating system's error and kind.
///
/// The descriptors are exhausted in a re-run of this test alone, under a low
/// limit, so neither this process nor the rest of the system runs short.
#[test]
fn a_runtime_that_cannot_be_built_is_a_spawn_failure_naming_the_runtime() {
    const CHILD: &str = "SIGNERS_TEST_DESCRIPTORS_EXHAUSTED";
    if env::var_os(CHILD).is_none() {
        let module = module_path!().split_once("::").unwrap().1;
        let name = format!(
            "{module}::a_runtime_that_cannot_be_built_is_a_spawn_failure_naming_the_runtime"
        );
        let output = Command::new("/bin/sh")
            .args(["-c", r#"ulimit -n 64 && exec "$0" "$@""#])
            .arg(env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let mut held = Vec::new();
    let exhausted = loop {
        match File::open("/dev/null") {
            Ok(file) => held.push(file),
            Err(error) => break error,
        }
    };
    let result = verify("/bin/ls").run();
    drop(held);

    let error = result.unwrap_err();
    assert_eq!(error.to_string(), "could not start `codesign`");
    match error {
        Error::Process(ProcessError::Spawn {
            program, source, ..
        }) => {
            assert_eq!(program, "codesign");
            assert_eq!(source.kind(), exhausted.kind());
            assert_eq!(
                source.to_string(),
                format!("could not build the Tokio runtime: {exhausted}")
            );
        }
        other => panic!("expected Spawn, got {other:?}"),
    }
}
