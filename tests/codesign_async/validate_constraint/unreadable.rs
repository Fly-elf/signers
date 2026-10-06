//! What `codesign` cannot read as a constraint at all: it exits 1 there,
//! unlike for a constraint it merely rejects, so the failure stays a plain
//! `codesign` failure.

use signers::codesign::validate_constraint;

use super::unreadable;
use crate::support::fixture::{Workspace, fixture};
use crate::support::inspect;

/// Each case is confirmed against the CLI first: exit 1, "Error reading".
#[tokio::test]
async fn a_file_that_is_not_a_dict_plist_fails_with_exit_one() {
    let workspace = Workspace::new();
    let cases = [
        ("garbage", workspace.write("garbage.plist", "garbage\n")),
        ("zero bytes", workspace.write("zero.plist", "")),
        ("array plist", fixture("constraint-array.plist")),
        ("directory", workspace.dir("dir.plist")),
    ];

    for (what, plist) in cases {
        let cli = inspect::codesign(&["--validate-constraint".as_ref(), plist.as_ref()]);
        assert!(!cli.success, "{what}: harness assumption");

        let (code, stderr) = unreadable(validate_constraint(&plist).await.unwrap_err());

        assert_eq!(code, 1, "{what}");
        assert!(
            stderr.contains("Error reading constraint"),
            "{what}: {stderr}"
        );
        assert!(
            stderr.contains(&plist.display().to_string()),
            "{what}: {stderr}"
        );
    }
}
