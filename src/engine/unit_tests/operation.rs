use super::*;
use crate::engine::tool::testing::Sh;
use crate::errors::ProcessError;

/// Overrides nothing but the required items, so the defaults show.
struct Echo;

impl Operation for Echo {
    type Tool = Sh;
    type Output = (String, String);
    const BATCH: bool = false;

    fn to_args<'a>(&'a self, _targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        Vec::new()
    }

    fn output(
        &self,
        _targets: &[PathBuf],
        stdout: String,
        stderr: String,
    ) -> Result<Vec<Self::Output>> {
        Ok(vec![(stdout, stderr)])
    }
}

#[test]
fn the_defaults_validate_everything_and_share_no_output() {
    assert!(Echo.validate().is_ok());
    assert_eq!(Echo.shared_output(), None);
}

#[test]
fn the_default_failure_is_the_tool_s_failed_error() {
    match Echo.failure(2, "printed".into(), "bad".into()) {
        Error::Process(ProcessError::Failed {
            program,
            code,
            stdout,
            stderr,
        }) => {
            assert_eq!(program, "sh");
            assert_eq!(code, 2);
            assert_eq!(stdout, "printed");
            assert_eq!(stderr, "bad");
        }
        other => panic!("expected Process(Failed), got {other:?}"),
    }
}

#[test]
fn the_default_failure_keeps_stdout_apart_from_the_message() {
    let error = Echo.failure(2, "printed".into(), "bad".into());

    assert_eq!(error.to_string(), "`sh` exited with code 2: bad");
}

#[test]
fn push_args_renders_flags_options_built_values_and_targets_in_order() {
    let value = String::from("v");
    let targets = [PathBuf::from("-patched"), PathBuf::from("b")];
    let mut args: Vec<Cow<'_, OsStr>> = Vec::new();

    args.flag("--force");
    args.option("--sign", &value);
    args.built(format!("--n={}", 3));
    args.targets(&targets);

    let rendered: Vec<&OsStr> = args.iter().map(|a| a.as_ref()).collect();
    assert_eq!(
        rendered,
        ["--force", "--sign", "v", "--n=3", "--", "-patched", "b"].map(OsStr::new)
    );
    assert!(matches!(args[0], Cow::Borrowed(_)));
    assert!(matches!(args[2], Cow::Borrowed(_)));
    assert!(matches!(args[3], Cow::Owned(_)));
}
