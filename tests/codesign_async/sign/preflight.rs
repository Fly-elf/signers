//! What the builder rejects before it ever spawns `codesign`: the checks every
//! action shares, and option values this crate cannot honour (`file_list("-")`).

use signers::{Codesign, Error};

use crate::preflight::preflight_tests;
use crate::support::fixture::Workspace;
use crate::support::inspect;

preflight_tests!(Codesign::sign_adhoc);

#[tokio::test]
async fn a_file_list_of_standard_output_is_rejected() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = Codesign::sign(&target, "-")
        .file_list("-")
        .await
        .unwrap_err();

    assert!(matches!(error, Error::FileListToStdout), "got {error:?}");
    assert!(
        !inspect::is_signed(&target),
        "the target was signed despite the rejected option"
    );
}
