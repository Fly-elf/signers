use std::os::unix::process::ExitStatusExt;

use super::*;
use crate::errors::testing::{exited, killed};

#[test]
fn not_found_maps_to_the_codesign_variant() {
    let error = Codesign::error(ProcessError::NotFound {
        program: "codesign",
    });

    assert!(matches!(error, Error::Codesign(CodesignError::NotFound)));
}

#[test]
fn spawn_and_run_keep_their_io_error() {
    let spawn = Codesign::error(ProcessError::Spawn {
        program: "codesign",
        source: std::io::Error::other("no fork"),
    });
    let run = Codesign::error(ProcessError::Run {
        program: "codesign",
        source: std::io::Error::other("no wait"),
    });

    match spawn {
        Error::Process(ProcessError::Spawn { program, source }) => {
            assert_eq!(program, "codesign");
            assert_eq!(source.to_string(), "no fork");
        }
        other => panic!("expected Spawn, got {other:?}"),
    }
    match run {
        Error::Process(ProcessError::Run { program, source }) => {
            assert_eq!(program, "codesign");
            assert_eq!(source.to_string(), "no wait");
        }
        other => panic!("expected Run, got {other:?}"),
    }
}

#[test]
fn failed_keeps_the_status_and_both_streams() {
    let error = Codesign::failed(exited("codesign", 3, "out", "err"));

    match error {
        Error::Process(ProcessError::Failed { output }) => {
            assert_eq!(output.program, "codesign");
            assert_eq!(output.status.code(), Some(3));
            assert_eq!(output.stdout, "out");
            assert_eq!(output.stderr, "err");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[test]
fn a_killed_run_is_failed_with_the_signal_in_its_status() {
    let error = Codesign::failed(killed("codesign", 9, "out", "err"));

    match &error {
        Error::Process(ProcessError::Failed { output }) => {
            assert_eq!(output.program, "codesign");
            assert_eq!(output.status.code(), None);
            assert_eq!(output.status.signal(), Some(9));
            assert_eq!(output.stdout, "out");
            assert_eq!(output.stderr, "err");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert_eq!(
        error.to_string(),
        "`codesign` was killed (signal: 9 (SIGKILL)): err"
    );
}

#[test]
fn unexpected_output_keeps_its_detail_and_the_run_output() {
    let error = Codesign::error(ProcessError::UnexpectedOutput {
        detail: "no plist".into(),
        output: exited("codesign", 0, "out", "err"),
    });

    match error {
        Error::Process(ProcessError::UnexpectedOutput { detail, output }) => {
            assert_eq!(detail, "no plist");
            assert_eq!(output.program, "codesign");
            assert!(output.status.success());
            assert_eq!(output.stdout, "out");
            assert_eq!(output.stderr, "err");
        }
        other => panic!("expected UnexpectedOutput, got {other:?}"),
    }
}

#[test]
fn the_mapped_errors_read_as_codesign_errors() {
    let error = Codesign::failed(exited("codesign", 1, "", "A.app: bad"));

    assert_eq!(
        error.to_string(),
        "`codesign` exited with code 1: A.app: bad"
    );
}

#[test]
fn the_not_found_message_keeps_the_usr_bin_hint() {
    let error = Codesign::error(ProcessError::NotFound {
        program: "codesign",
    });

    assert_eq!(
        error.to_string(),
        "`codesign` was not found on PATH; it ships with macOS in /usr/bin, \
         so check that PATH includes /usr/bin"
    );
}
