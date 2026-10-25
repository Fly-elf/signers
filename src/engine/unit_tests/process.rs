use std::os::unix::process::ExitStatusExt;

use super::super::tool::testing::{Missing, NotExecutable, Sh};
use super::*;

fn sh(script: &str) -> Vec<Cow<'_, OsStr>> {
    vec![
        Cow::Borrowed(OsStr::new("-c")),
        Cow::Borrowed(OsStr::new(script)),
    ]
}

fn exit(status: i32, stdout: &str, stderr: &str) -> Exit {
    Exit {
        status: ExitStatus::from_raw(status),
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

#[test]
fn decode_trims_surrounding_whitespace() {
    assert_eq!(
        decode(b" \n\tkeep  inner\n space \r\n".to_vec()),
        "keep  inner\n space"
    );
    assert_eq!(decode(b"plain".to_vec()), "plain");
}

#[test]
fn decode_of_nothing_or_only_whitespace_is_empty() {
    assert_eq!(decode(Vec::new()), "");
    assert_eq!(decode(b" \n\t\r\n".to_vec()), "");
}

#[test]
fn decode_replaces_invalid_utf8_with_the_replacement_character() {
    assert_eq!(decode(b"a\xFFb".to_vec()), "a\u{FFFD}b");
    assert_eq!(decode(vec![0xC3]), "\u{FFFD}");
    assert_eq!(decode("caf\u{E9}\n".as_bytes().to_vec()), "caf\u{E9}");
}

#[test]
fn success_hands_over_both_streams_without_calling_the_failure_hook() {
    let result = exit(0, "out", "err").success::<Sh>(|_, _, _| panic!("not a failure"));

    assert_eq!(result.unwrap(), ("out".to_owned(), "err".to_owned()));
}

#[test]
fn a_non_zero_code_goes_to_the_failure_hook_with_both_streams() {
    let error = exit(7 << 8, "out", "err")
        .success::<Sh>(|code, stdout, stderr| {
            Error::Process(ProcessError::UnexpectedOutput {
                program: "hook",
                detail: format!("{code}/{stdout}/{stderr}"),
                stdout: String::new(),
                stderr: String::new(),
            })
        })
        .unwrap_err();

    match error {
        Error::Process(ProcessError::UnexpectedOutput {
            program, detail, ..
        }) => {
            assert_eq!(program, "hook");
            assert_eq!(detail, "7/out/err");
        }
        other => panic!("expected the hook's error, got {other:?}"),
    }
}

#[test]
fn a_signal_death_is_terminated_and_never_reaches_the_failure_hook() {
    let error = exit(9, "out", "err")
        .success::<Sh>(|_, _, _| panic!("a killed process has no exit code"))
        .unwrap_err();

    match error {
        Error::Process(ProcessError::Terminated {
            program,
            status,
            stdout,
            stderr,
        }) => {
            assert_eq!(program, "sh");
            assert_eq!(status.signal(), Some(9));
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "err");
        }
        other => panic!("expected Terminated, got {other:?}"),
    }
}

#[test]
fn run_error_into_error_returns_either_side() {
    for run_error in [
        RunError::Unstarted(Error::NoTargets),
        RunError::Failed(Error::NoTargets),
    ] {
        assert!(matches!(run_error.into_error(), Error::NoTargets));
    }
}

/// Decoding happens once, here: both streams arrive trimmed and lossy-decoded.
#[tokio::test]
async fn spawn_decodes_both_streams() {
    let exit = spawn::<Sh>(&sh(r"printf '\n out\377\n'; printf '  err \n' >&2"))
        .await
        .ok()
        .expect("sh starts");

    assert!(exit.status.success());
    assert_eq!(exit.stdout, "out\u{FFFD}");
    assert_eq!(exit.stderr, "err");
}

#[tokio::test]
async fn a_failed_exit_keeps_its_code_and_decoded_streams() {
    let exit = spawn::<Sh>(&sh(r"printf 'out\n'; printf '\377err\n' >&2; exit 7"))
        .await
        .ok()
        .expect("sh starts");

    let error = exit.success::<Sh>(Sh::failed).unwrap_err();

    match error {
        Error::Process(ProcessError::Failed {
            program,
            code,
            stdout,
            stderr,
        }) => {
            assert_eq!(program, "sh");
            assert_eq!(code, 7);
            assert_eq!(stdout, "out");
            assert_eq!(stderr, "\u{FFFD}err");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

#[tokio::test]
async fn a_killed_process_comes_back_without_an_exit_code() {
    let exit = spawn::<Sh>(&sh("kill -9 $$"))
        .await
        .ok()
        .expect("sh starts");

    assert_eq!(exit.status.code(), None);
    assert!(matches!(
        exit.success::<Sh>(|_, _, _| panic!("no exit code")),
        Err(Error::Process(ProcessError::Terminated { .. }))
    ));
}

/// An inherited stdin would make `cat` wait for the test harness.
#[tokio::test]
async fn the_process_gets_no_stdin() {
    let exit = spawn::<Sh>(&sh("cat; echo done"))
        .await
        .ok()
        .expect("sh starts");

    assert_eq!(exit.stdout, "done");
}

#[tokio::test]
async fn arguments_reach_the_program_verbatim() {
    let mut args = sh(r#"printf '%s|' "$@""#);
    args.extend(["sh", "-n", "a b", ""].map(|a| Cow::Borrowed(OsStr::new(a))));

    let exit = spawn::<Sh>(&args).await.ok().expect("sh starts");

    assert_eq!(exit.stdout, "-n|a b||");
}

#[tokio::test]
async fn a_missing_program_is_unstarted_and_not_found() {
    match spawn::<Missing>(&[]).await {
        Err(RunError::Unstarted(Error::Process(ProcessError::NotFound { program }))) => {
            assert_eq!(program, "signers-no-such-program");
        }
        Err(other) => panic!("expected Unstarted(NotFound), got {:?}", other.into_error()),
        Ok(_) => panic!("a missing program started"),
    }
}

#[tokio::test]
async fn another_spawn_failure_is_unstarted_and_spawn() {
    match spawn::<NotExecutable>(&[]).await {
        Err(RunError::Unstarted(Error::Process(ProcessError::Spawn { program, source }))) => {
            assert_eq!(program, "/etc/hosts");
            assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
        }
        Err(other) => panic!("expected Unstarted(Spawn), got {:?}", other.into_error()),
        Ok(_) => panic!("a plain file started"),
    }
}
