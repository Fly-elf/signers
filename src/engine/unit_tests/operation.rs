use super::*;
use crate::engine::tool::testing::Sh;
use crate::errors::ProcessError;
use crate::errors::testing::exited;

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
        output: &Output,
    ) -> std::result::Result<Vec<Self::Output>, Rejection> {
        Ok(vec![(output.stdout.clone(), output.stderr.clone())])
    }
}

#[test]
fn the_defaults_validate_everything_and_share_no_output() {
    assert!(Echo.validate().is_ok());
    assert_eq!(Echo.shared_output(), None);
}

#[test]
fn the_default_failure_is_the_tool_s_failed_error() {
    match Echo.failure(2, exited("sh", 2, "printed", "bad")) {
        Error::Process(ProcessError::Failed { output }) => {
            assert_eq!(output.program, "sh");
            assert_eq!(output.status.code(), Some(2));
            assert_eq!(output.stdout, "printed");
            assert_eq!(output.stderr, "bad");
        }
        other => panic!("expected Process(Failed), got {other:?}"),
    }
}

#[test]
fn the_default_failure_keeps_stdout_apart_from_the_message() {
    let error = Echo.failure(2, exited("sh", 2, "printed", "bad"));

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
