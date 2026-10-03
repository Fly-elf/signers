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
        // Every check below is made once, before any process starts, whether the
        // run is one process for all targets or one per target. So
        // each is asserted in both modes, and always as a plain error: a
        // refused run has no per-target failures to collect.
        const MODES: [bool; 2] = [false, true];

        #[tokio::test]
        async fn an_empty_target_is_rejected() {
            let error = $constructor("").await.unwrap_err();
            assert!(
                matches!(error, signers::Error::EmptyTarget(0)),
                "got {error:?}",
            );

            for per_target in MODES {
                let error = $constructor(vec![""])
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, signers::Error::EmptyTarget(0)),
                    "per_target({per_target}): got {error:?}",
                );
            }
        }

        #[tokio::test]
        async fn an_empty_target_list_is_rejected() {
            for per_target in MODES {
                let error = $constructor(Vec::<std::path::PathBuf>::new())
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, signers::Error::NoTargets),
                    "per_target({per_target}): got {error:?}",
                );
            }
        }

        #[tokio::test]
        async fn an_empty_array_of_targets_is_rejected() {
            for per_target in MODES {
                let none: [std::path::PathBuf; 0] = [];
                let error = $constructor(none)
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, signers::Error::NoTargets),
                    "per_target({per_target}): got {error:?}",
                );
            }
        }

        #[tokio::test]
        async fn a_list_of_nothing_but_empty_targets_is_rejected() {
            for per_target in MODES {
                let error = $constructor(vec!["", ""])
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, signers::Error::EmptyTarget(0)),
                    "per_target({per_target}): got {error:?}",
                );
            }
        }

        #[tokio::test]
        async fn an_empty_target_among_others_is_reported_by_its_position() {
            // The first empty path is the one named, and the targets around it
            // are left alone: an empty path refuses the run, it is not skipped.
            let workspace = crate::support::fixture::Workspace::new();
            let present = [workspace.unsigned("unsigned"), workspace.adhoc_signed("signed")];
            let before = present.each_ref().map(|path| std::fs::read(path).unwrap());
            let empty = std::path::PathBuf::new();

            for per_target in MODES {
                let batch = vec![
                    present[0].clone(),
                    present[1].clone(),
                    empty.clone(),
                    present[0].clone(),
                    empty.clone(),
                ];
                let error = $constructor(batch)
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, signers::Error::EmptyTarget(2)),
                    "per_target({per_target}): got {error:?}",
                );

                let batch = [empty.clone(), present[0].clone(), present[1].clone()];
                let error = $constructor(batch)
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, signers::Error::EmptyTarget(0)),
                    "per_target({per_target}): got {error:?}",
                );
            }

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
        async fn an_empty_target_is_reported_before_a_missing_one() {
            let workspace = crate::support::fixture::Workspace::new();
            let missing = workspace.join("nowhere.bin");

            for per_target in MODES {
                let batch = vec![missing.clone(), std::path::PathBuf::new()];
                let error = $constructor(batch)
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(error, signers::Error::EmptyTarget(1)),
                    "per_target({per_target}): got {error:?}",
                );
            }
        }

        #[tokio::test]
        async fn a_missing_target_is_reported_with_its_path() {
            let workspace = crate::support::fixture::Workspace::new();
            let missing = workspace.join("nowhere.bin");

            match $constructor(missing.clone()).await.unwrap_err() {
                signers::Error::TargetNotFound(path) => assert_eq!(path, missing),
                other => panic!("expected TargetNotFound, got {other:?}"),
            }

            for per_target in MODES {
                let error = $constructor(vec![missing.clone()])
                    .per_target(per_target)
                    .await
                    .unwrap_err();

                match error {
                    signers::Error::TargetNotFound(path) => assert_eq!(path, missing),
                    other => panic!("per_target({per_target}): expected TargetNotFound, got {other:?}"),
                }
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

            for per_target in MODES {
                let batch = vec![present[0].clone(), present[1].clone(), missing.clone()];
                let error = $constructor(batch)
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(&error, signers::Error::TargetNotFound(path) if *path == missing),
                    "per_target({per_target}): got {error:?}",
                );

                let batch = [present[0].clone(), missing.clone(), present[1].clone()];
                let error = $constructor(batch)
                    .per_target(per_target)
                    .await
                    .unwrap_err();
                assert!(
                    matches!(&error, signers::Error::TargetNotFound(path) if *path == missing),
                    "per_target({per_target}): got {error:?}",
                );
            }

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
