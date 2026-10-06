//! Several targets: always one `codesign` per target, since the requirements
//! of a shared run could not be told apart, and what a failing target does.

use std::path::PathBuf;

use signers::codesign::requirements;

use super::{lines_of, printed};
use crate::support::fixture::Workspace;

fn three_targets(workspace: &Workspace) -> Vec<PathBuf> {
    vec![
        workspace.presigned(
            "first",
            &["-r=designated => identifier \"com.example.first\""],
        ),
        workspace.presigned("second", &["-i", "com.example.second"]),
        PathBuf::from("/bin/ls"),
    ]
}

#[tokio::test]
async fn each_target_gets_its_own_requirements_in_input_order() {
    let workspace = Workspace::new();
    let mut targets = three_targets(&workspace);
    targets.reverse();

    let found = requirements(targets.clone()).await.unwrap();

    assert_eq!(found.len(), 3);
    for (requirements, target) in found.iter().zip(&targets) {
        assert_eq!(
            lines_of(requirements),
            printed(target),
            "{}",
            target.display()
        );
    }
}

#[tokio::test]
async fn an_array_of_targets_yields_an_array_of_lists() {
    let workspace = Workspace::new();
    let targets = three_targets(&workspace);

    let [first, second] = requirements([targets[0].clone(), targets[1].clone()])
        .await
        .unwrap();

    assert_eq!(lines_of(&first), printed(&targets[0]));
    assert_eq!(lines_of(&second), printed(&targets[1]));
}

#[tokio::test]
async fn a_single_target_given_as_a_collection_yields_a_one_item_list() {
    let found = requirements(vec!["/bin/ls"]).await.unwrap();

    assert_eq!(found.len(), 1);
    assert_eq!(
        lines_of(&found[0]),
        printed(std::path::Path::new("/bin/ls"))
    );
}

#[tokio::test]
async fn the_same_target_twice_is_read_twice() {
    let found = requirements(vec!["/bin/ls", "/bin/ls"]).await.unwrap();

    assert_eq!(found.len(), 2);
    assert_eq!(found[0], found[1]);
    assert!(!found[0].is_empty());
}

#[tokio::test]
async fn unsigned_targets_are_collected_in_input_order() {
    let workspace = Workspace::new();
    let first_unsigned = workspace.unsigned("first unsigned");
    let signed = workspace.adhoc_signed("signed");
    let second_unsigned = workspace.unsigned("second unsigned");

    let error = requirements(vec![
        first_unsigned.clone(),
        signed,
        second_unsigned.clone(),
    ])
    .await
    .unwrap_err();

    let failures = crate::batch_failures(error);
    let failed: Vec<&PathBuf> = failures.iter().map(|(path, _)| path).collect();
    assert_eq!(failed, [&first_unsigned, &second_unsigned]);
    for (path, error) in failures {
        let stderr = crate::codesign_error(error);
        assert!(
            stderr.contains("code object is not signed at all"),
            "{stderr}"
        );
        assert!(stderr.contains(&path.display().to_string()), "{stderr}");
    }
}

#[tokio::test]
async fn an_unsigned_single_target_fails_with_codesigns_diagnostics() {
    let workspace = Workspace::new();
    let target = workspace.unsigned("hello");

    let error = requirements(&target).await.unwrap_err();

    match error {
        signers::Error::Codesign(signers::CodesignError::Failed { code, stderr, .. }) => {
            assert_eq!(code, 1);
            assert!(
                stderr.contains("code object is not signed at all"),
                "{stderr}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}
