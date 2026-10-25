use std::io;

use super::*;

type Runs = Vec<std::result::Result<Vec<u8>, RunError>>;

fn paths(count: usize) -> Vec<PathBuf> {
    (0..count).map(|i| PathBuf::from(format!("t{i}"))).collect()
}

fn unstarted(program: &'static str) -> RunError {
    RunError::Unstarted(Error::Process(ProcessError::NotFound { program }))
}

fn failed(program: &'static str) -> RunError {
    RunError::Failed(Error::Process(ProcessError::NotFound { program }))
}

fn program(error: &Error) -> &'static str {
    match error {
        Error::Process(ProcessError::NotFound { program }) => program,
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn all_runs_unstarted_report_the_first_error_alone() {
    let results: Runs = vec![
        Err(unstarted("first")),
        Err(unstarted("second")),
        Err(unstarted("third")),
    ];

    let error = collect(&paths(3), results).unwrap_err();

    assert_eq!(program(&error), "first");
}

#[test]
fn a_single_unstarted_run_reports_its_error_alone() {
    let error = collect::<u8>(&paths(1), vec![Err(unstarted("only"))]).unwrap_err();

    assert_eq!(program(&error), "only");
}

#[test]
fn unstarted_runs_next_to_ok_runs_are_collected_per_target() {
    let results: Runs = vec![
        Ok(vec![1]),
        Err(unstarted("a")),
        Ok(vec![2]),
        Err(unstarted("b")),
    ];
    let targets = paths(4);

    let Error::Batch(failures) = collect(&targets, results).unwrap_err() else {
        panic!("expected Batch");
    };

    let reported: Vec<(&PathBuf, &str)> = failures
        .iter()
        .map(|(target, error)| (target, program(error)))
        .collect();
    assert_eq!(reported, [(&targets[1], "a"), (&targets[3], "b")]);
}

#[test]
fn unstarted_and_failed_runs_are_all_collected_in_input_order() {
    let results: Runs = vec![
        Err(failed("a")),
        Ok(vec![1]),
        Err(unstarted("b")),
        Err(failed("c")),
        Err(unstarted("d")),
    ];
    let targets = paths(5);

    let Error::Batch(failures) = collect(&targets, results).unwrap_err() else {
        panic!("expected Batch");
    };

    let reported: Vec<(&PathBuf, &str)> = failures
        .iter()
        .map(|(target, error)| (target, program(error)))
        .collect();
    assert_eq!(
        reported,
        [
            (&targets[0], "a"),
            (&targets[2], "b"),
            (&targets[3], "c"),
            (&targets[4], "d"),
        ]
    );
}

#[test]
fn failed_runs_without_any_unstarted_one_are_collected_too() {
    let results: Runs = vec![Err(failed("a")), Err(failed("b"))];
    let targets = paths(2);

    let Error::Batch(failures) = collect(&targets, results).unwrap_err() else {
        panic!("expected Batch");
    };

    assert_eq!(failures.len(), 2);
    assert_eq!(failures[0].0, targets[0]);
    assert_eq!(failures[1].0, targets[1]);
}

#[test]
fn a_lone_failed_run_is_a_batch_of_one() {
    let targets = paths(1);

    let error = collect::<u8>(&targets, vec![Err(failed("a"))]).unwrap_err();

    assert!(matches!(&error, Error::Batch(failures) if failures.len() == 1));
}

#[test]
fn all_ok_runs_yield_their_outputs_in_order() {
    let results: Runs = vec![Ok(vec![1]), Ok(vec![2]), Ok(vec![3])];

    assert_eq!(collect(&paths(3), results).unwrap(), [1, 2, 3]);
}

#[test]
fn an_unstarted_run_keeps_its_own_error_inside_the_batch() {
    let source = io::Error::from(io::ErrorKind::PermissionDenied);
    let results: Runs = vec![
        Ok(vec![1]),
        Err(RunError::Unstarted(Error::Process(ProcessError::Spawn {
            program: "tool",
            source,
        }))),
    ];

    let Error::Batch(failures) = collect(&paths(2), results).unwrap_err() else {
        panic!("expected Batch");
    };

    assert!(matches!(
        &failures[0].1,
        Error::Process(ProcessError::Spawn { program: "tool", source })
            if source.kind() == io::ErrorKind::PermissionDenied
    ));
}
