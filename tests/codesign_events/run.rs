//! The events of one `codesign` process.

use signers::codesign::{self, blocking};
use tracing::Level;

use crate::support::events::{Event, capture, capture_async, messages, named};
use crate::support::fixture::Workspace;

fn assert_spans_one_run(events: &[Event]) {
    assert_eq!(
        messages(events),
        ["spawning", "exited", "output"],
        "{events:#?}"
    );
}

#[test]
fn an_async_run_reports_spawning_then_exited_then_output() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let (result, events) = capture_async(async { codesign::sign_adhoc(&target).await });

    result.unwrap();
    assert_spans_one_run(&events);
}

#[test]
fn a_blocking_run_reports_spawning_then_exited_then_output() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let (result, events) = capture(|| blocking::sign_adhoc(&target).run());

    result.unwrap();
    assert_spans_one_run(&events);
}

#[test]
fn the_levels_are_debug_for_spawning_and_exited_and_trace_for_output() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let (_, events) = capture(|| blocking::sign_adhoc(&target).run());

    let levels: Vec<_> = events.iter().map(|e| e.level).collect();
    assert_eq!(levels, [Level::DEBUG, Level::DEBUG, Level::TRACE]);
}

#[test]
fn every_event_has_the_target_signers_and_names_the_program() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let (_, events) = capture(|| blocking::sign_adhoc(&target).run());

    for event in &events {
        assert_eq!(event.target, "signers", "{event:?}");
        assert_eq!(event.field("program"), "codesign", "{event:?}");
    }
}

#[test]
fn spawning_lists_the_arguments_handed_to_the_tool() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let (_, events) = capture(|| blocking::sign_adhoc(&target).force(true).run());

    let args = events[0].field("args");
    assert!(args.starts_with('['), "args should be a list: {args}");
    assert!(args.contains("--force"), "no --force in {args}");
    assert!(
        args.contains(&target.display().to_string()),
        "no target in {args}"
    );
}

#[test]
fn exited_reports_the_status_and_how_long_the_run_took() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let (_, events) = capture(|| blocking::sign_adhoc(&target).run());

    let exited = &events[1];
    assert_eq!(exited.field("status"), "exit status: 0");
    let elapsed = exited.field("elapsed");
    let digits = elapsed.trim_end_matches(|c: char| c.is_alphabetic() || c == 'µ');
    assert!(
        digits.parse::<f64>().is_ok_and(|n| n >= 0.0) && digits.len() < elapsed.len(),
        "not a duration: {elapsed}"
    );
}

#[test]
fn a_run_codesign_rejects_still_reports_its_exit_and_output() {
    let workspace = Workspace::new();
    let signed = workspace.adhoc_signed("signed");

    let (result, events) = capture(|| blocking::sign_adhoc(&signed).run());

    result.unwrap_err();
    assert_spans_one_run(&events);
    assert_eq!(events[1].field("status"), "exit status: 1");
    assert!(
        events[2].field("stderr").contains("already signed"),
        "{:?}",
        events[2]
    );
}

#[test]
fn output_carries_the_streams_of_the_tool() {
    let workspace = Workspace::new();
    let signed = workspace.adhoc_signed("signed");

    let (result, events) = capture(|| blocking::display(&signed).run());

    let output = &named(&events, "output")[0];
    let printed = result.unwrap();
    assert!(
        output
            .field("stderr")
            .contains(&signed.display().to_string()),
        "{output:?} vs {printed:?}"
    );
    assert_eq!(output.field("stdout"), "");
}

#[test]
fn nothing_is_reported_above_debug_for_a_run() {
    let workspace = Workspace::new();
    let signed = workspace.adhoc_signed("signed");

    let (_, events) = capture(|| {
        let _ = blocking::sign_adhoc(&signed).run();
        let _ = blocking::verify(&signed).run();
    });

    assert!(!events.is_empty());
    assert!(
        events.iter().all(|e| e.level >= Level::DEBUG),
        "{events:#?}"
    );
}

#[test]
fn a_run_stopped_by_the_checks_reports_nothing() {
    let workspace = Workspace::new();

    let (result, events) = capture(|| blocking::sign_adhoc(workspace.join("absent")).run());

    result.unwrap_err();
    assert!(events.is_empty(), "{events:#?}");
}
