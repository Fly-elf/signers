//! The pre-flight checks every action runs before it spawns `codesign`, written
//! once and stamped into each action's suite by [`preflight_tests!`].

/// Expands to the shared pre-flight tests, driving `$constructor`: a
/// `Codesign<()>` constructor that takes only the targets.
///
/// ```ignore
/// preflight_tests!(Codesign::remove_signature);
/// ```
macro_rules! preflight_tests {
    ($constructor:path) => {
        #[tokio::test]
        async fn an_empty_target_is_rejected() {
            let error = $constructor("").await.unwrap_err();
            assert!(matches!(error, signers::Error::NoTargets), "got {error:?}");
        }

        #[tokio::test]
        async fn an_empty_target_list_is_rejected() {
            let error = $constructor(Vec::<std::path::PathBuf>::new())
                .await
                .unwrap_err();
            assert!(matches!(error, signers::Error::NoTargets), "got {error:?}");
        }

        #[tokio::test]
        async fn a_list_of_nothing_but_empty_targets_is_rejected() {
            let error = $constructor(vec!["", ""]).await.unwrap_err();
            assert!(matches!(error, signers::Error::NoTargets), "got {error:?}");
        }

        #[tokio::test]
        async fn a_missing_target_is_reported_with_its_path() {
            let workspace = crate::support::fixture::Workspace::new();
            let missing = workspace.join("nowhere.bin");

            let error = $constructor(missing.clone()).await.unwrap_err();

            match error {
                signers::Error::TargetNotFound(path) => assert_eq!(path, missing),
                other => panic!("expected TargetNotFound, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn a_failure_says_which_target_it_is_about() {
            let workspace = crate::support::fixture::Workspace::new();
            let missing = workspace.join("ghost.bin");

            let error = $constructor(missing.clone()).await.unwrap_err();

            assert!(
                error.to_string().contains(&missing.display().to_string()),
                "unhelpful message: {error}",
            );
        }

        #[tokio::test]
        async fn a_missing_target_aborts_the_whole_batch() {
            // Handed the same arguments, `codesign` would process the targets it
            // can and only then fail on the missing one. One unsigned and one
            // signed target, so whatever the action does, a half-applied batch
            // shows up as a changed file.
            let workspace = crate::support::fixture::Workspace::new();
            let present = [workspace.unsigned("unsigned"), workspace.adhoc_signed("signed")];
            let before = present.each_ref().map(|path| std::fs::read(path).unwrap());
            let missing = workspace.join("missing");

            let batch = vec![present[0].clone(), present[1].clone(), missing.clone()];
            let error = $constructor(batch).await.unwrap_err();

            assert!(
                matches!(&error, signers::Error::TargetNotFound(path) if *path == missing),
                "got {error:?}",
            );
            for (path, before) in present.iter().zip(before) {
                assert_eq!(
                    std::fs::read(path).unwrap(),
                    before,
                    "{} changed although the batch was refused",
                    path.display(),
                );
            }
        }

        #[tokio::test]
        async fn an_unreadable_parent_directory_is_an_access_error() {
            use std::os::unix::fs::PermissionsExt;

            if crate::support::running_as_root() {
                crate::support::skip!("root is exempt from the permission bits this relies on");
            }
            let workspace = crate::support::fixture::Workspace::new();
            let locked = workspace.dir("locked");
            let target = workspace.join("locked/hidden.bin");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

            let error = $constructor(target.clone()).await.unwrap_err();

            // Reopen before asserting, so a failure still leaves a removable workspace.
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
            match error {
                signers::Error::TargetAccess { path, source } => {
                    assert_eq!(path, target);
                    assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied);
                }
                other => panic!("expected TargetAccess, got {other:?}"),
            }
        }
    };
}
pub(crate) use preflight_tests;
