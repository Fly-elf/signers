//! The events of a run split into one process per target, and of the runs that are not.

use signers::codesign::{self, blocking};

use crate::support::events::{Event, capture, capture_async, messages, named};
use crate::support::fixture::Workspace;

fn three_unsigned(workspace: &Workspace) -> Vec<std::path::PathBuf> {
    ["a", "b", "c"].map(|name| workspace.unsigned(name)).into()
}

fn assert_one_batch_then_three_runs(events: &[Event]) {
    let batch = named(events, "batch");
    assert_eq!(batch.len(), 1, "{events:#?}");
    assert_eq!(batch[0].field("runs"), "3");
    assert_eq!(batch[0].field("program"), "codesign");
    assert_eq!(batch[0].target, "signers");
    assert_eq!(batch[0].level, tracing::Level::DEBUG);
    let concurrency: usize = batch[0].field("concurrency").parse().unwrap();
    assert!(concurrency >= 1);

    assert_eq!(events[0].message, "batch", "the batch comes first");
    assert_eq!(named(events, "spawning").len(), 3);
    assert_eq!(named(events, "exited").len(), 3);
    assert_eq!(named(events, "output").len(), 3);
}

#[test]
fn a_blocking_per_target_run_reports_one_batch_then_every_process() {
    let workspace = Workspace::new();
    let targets = three_unsigned(&workspace);

    let (result, events) = capture(|| blocking::sign_adhoc(targets).per_target(true).run());

    result.unwrap();
    assert_one_batch_then_three_runs(&events);
}

#[test]
fn an_async_per_target_run_reports_one_batch_then_every_process() {
    let workspace = Workspace::new();
    let targets = three_unsigned(&workspace);

    let (result, events) =
        capture_async(async { codesign::sign_adhoc(targets).per_target(true).await });

    result.unwrap();
    assert_one_batch_then_three_runs(&events);
}

#[test]
fn every_process_of_a_batch_exits_after_it_spawns() {
    let workspace = Workspace::new();
    let targets = three_unsigned(&workspace);

    let (_, events) = capture(|| blocking::sign_adhoc(targets).per_target(true).run());

    for kind in ["exited", "output"] {
        let first = events.iter().position(|e| e.message == kind).unwrap();
        let first_spawn = events.iter().position(|e| e.message == "spawning").unwrap();
        assert!(
            first_spawn < first,
            "{kind} before any spawning: {events:#?}"
        );
    }
    assert_eq!(
        events.iter().filter(|e| e.message == "spawning").count(),
        events.iter().filter(|e| e.message == "exited").count()
    );
}

#[test]
fn a_batch_with_a_failing_target_still_reports_every_process() {
    let workspace = Workspace::new();
    let targets = vec![
        workspace.unsigned("a"),
        workspace.adhoc_signed("b"),
        workspace.unsigned("c"),
    ];

    let (result, events) = capture(|| blocking::sign_adhoc(targets).per_target(true).run());

    result.unwrap_err();
    assert_one_batch_then_three_runs(&events);
}

#[test]
fn a_shared_run_over_many_targets_reports_one_process_and_no_batch() {
    let workspace = Workspace::new();
    let targets = three_unsigned(&workspace);

    let (result, events) = capture(|| blocking::sign_adhoc(targets).per_target(false).run());

    result.unwrap();
    assert_eq!(messages(&events), ["spawning", "exited", "output"]);
}

#[test]
fn a_single_target_reports_no_batch() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("a");

    let (_, events) = capture(|| blocking::sign_adhoc(&target).run());

    assert!(named(&events, "batch").is_empty());
}

#[test]
fn a_per_target_run_over_one_target_still_reports_its_batch_of_one() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("a");

    let (_, events) = capture(|| blocking::sign_adhoc(vec![target]).per_target(true).run());

    let batch = named(&events, "batch");
    assert_eq!(batch.len(), 1, "{events:#?}");
    assert_eq!(batch[0].field("runs"), "1");
    assert_eq!(named(&events, "spawning").len(), 1);
}

#[test]
fn a_batch_stopped_by_the_checks_reports_no_batch_and_no_process() {
    let workspace = Workspace::new();
    let targets = vec![workspace.unsigned("a"), workspace.join("absent")];

    let (result, events) = capture(|| blocking::sign_adhoc(targets).per_target(true).run());

    result.unwrap_err();
    assert!(events.is_empty(), "{events:#?}");
}
