//! The events of runs that fail to start, die or print something specific, reached through a
//! stand-in `codesign` on `PATH`.

use signers::codesign::blocking::sign_adhoc;
use tracing::Level;

use crate::executable_path::{ScopedPath, fake_codesign, plain_targets};
use crate::support::events::{capture, messages, named};
use crate::support::fixture::Workspace;

#[test]
fn a_missing_program_reports_only_that_it_was_about_to_spawn() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let (result, events) = {
        let _path = ScopedPath::to(&workspace.dir("empty"));
        capture(|| sign_adhoc(&target).run())
    };

    result.unwrap_err();
    assert_eq!(messages(&events), ["spawning"], "{events:#?}");
    assert_eq!(events[0].level, Level::DEBUG);
    assert_eq!(events[0].field("program"), "codesign");
}

#[test]
fn a_program_that_cannot_be_executed_reports_only_that_it_was_about_to_spawn() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = workspace.dir("bin");
    workspace.write("bin/codesign", "#!/bin/sh\nexit 0\n"); // no execute bit

    let (result, events) = {
        let _path = ScopedPath::to(&bin);
        capture(|| sign_adhoc(&target).run())
    };

    result.unwrap_err();
    assert_eq!(messages(&events), ["spawning"], "{events:#?}");
}

#[test]
fn a_batch_that_cannot_start_reports_its_batch_and_never_an_exit() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let targets = plain_targets(&workspace, &["a.bin", "b.bin"]);

    let (result, events) = {
        let _path = ScopedPath::to(&workspace.dir("empty"));
        capture(|| sign_adhoc(targets).per_target(true).run())
    };

    result.unwrap_err();
    assert_eq!(named(&events, "batch").len(), 1, "{events:#?}");
    assert!(!named(&events, "spawning").is_empty());
    assert!(named(&events, "exited").is_empty(), "{events:#?}");
    assert!(named(&events, "output").is_empty(), "{events:#?}");
}

#[test]
fn a_process_killed_by_a_signal_still_reports_its_exit() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = fake_codesign(&workspace, "kill -9 $$");

    let (result, events) = {
        let _path = ScopedPath::to(&bin);
        capture(|| sign_adhoc(&target).run())
    };

    result.unwrap_err();
    assert_eq!(messages(&events), ["spawning", "exited", "output"]);
    assert!(
        events[1].field("status").starts_with("signal: 9"),
        "{:?}",
        events[1]
    );
}

#[test]
fn a_failing_exit_reports_its_code() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = fake_codesign(&workspace, "exit 3");

    let (_, events) = {
        let _path = ScopedPath::to(&bin);
        capture(|| sign_adhoc(&target).run())
    };

    assert_eq!(events[1].field("status"), "exit status: 3");
}

#[test]
fn output_carries_both_streams_decoded_and_trimmed() {
    let _serialised = crate::serialised();
    let workspace = Workspace::new();
    let target = workspace.write("target.bin", "irrelevant\n");
    let bin = fake_codesign(
        &workspace,
        "printf '\\n  to stdout \\377\\n\\n'; printf ' to stderr\\n\\n' >&2",
    );

    let (_, events) = {
        let _path = ScopedPath::to(&bin);
        capture(|| sign_adhoc(&target).run())
    };

    let output = &events[2];
    assert_eq!(output.level, Level::TRACE);
    assert_eq!(output.field("stdout"), "to stdout \u{FFFD}");
    assert_eq!(output.field("stderr"), "to stderr");
}
