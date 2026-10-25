use super::*;
use crate::Error;
use crate::errors::testing::exited;

/// The remedy is the whole point of the variant: `codesign` ships with macOS, so the
/// fix is `PATH`, never the Command Line Tools.
#[test]
fn a_missing_binary_names_the_remedy() {
    let message = CodesignError::NotFound.to_string();
    assert_eq!(
        message,
        "`codesign` was not found on PATH; it ships with macOS in /usr/bin, \
         so check that PATH includes /usr/bin",
    );
    assert!(!message.contains("xcode-select"), "got {message}");
}

/// The outer `Error::Codesign` wrapper must forward `Display` unchanged, so callers who
/// only do `eprintln!("{error}")` see no difference from before the split.
#[test]
fn the_wrapper_variant_forwards_display_unchanged() {
    let error = Error::from(CodesignError::NotFound);
    assert_eq!(error.to_string(), CodesignError::NotFound.to_string());
}

#[test]
fn a_verification_failure_carries_its_diagnostics() {
    let error = CodesignError::VerificationFailed {
        output: exited(
            "codesign",
            1,
            "printed on stdout",
            "app: invalid signature (code or signature have been modified)",
        ),
        resources: Vec::new(),
    };
    assert_eq!(
        error.to_string(),
        "verification failed: app: invalid signature (code or signature have been modified)",
    );
}

#[test]
fn a_verification_failure_with_nothing_to_say_still_reads_as_a_sentence() {
    let silent = CodesignError::VerificationFailed {
        output: exited("codesign", 1, "printed on stdout", ""),
        resources: Vec::new(),
    };
    assert_eq!(silent.to_string(), "verification failed: no diagnostics");
}

fn resource(change: Change, path: &str) -> ResourceChange {
    ResourceChange {
        change,
        path: PathBuf::from(path),
    }
}

#[test]
fn a_verification_failure_lists_the_altered_resources_in_order() {
    let error = CodesignError::VerificationFailed {
        output: exited(
            "codesign",
            1,
            "printed on stdout",
            "A.app: a sealed resource is missing or invalid",
        ),
        resources: vec![
            resource(Change::Modified, "/x/A.app/Contents/Resources/r.txt"),
            resource(Change::Added, "/x/A.app/Contents/Resources/new.txt"),
            resource(Change::Missing, "/x/A.app/Contents/Resources/gone.txt"),
        ],
    };
    assert_eq!(
        error.to_string(),
        "verification failed: A.app: a sealed resource is missing or invalid \
         (modified: /x/A.app/Contents/Resources/r.txt; \
         added: /x/A.app/Contents/Resources/new.txt; \
         missing: /x/A.app/Contents/Resources/gone.txt)",
    );
}

#[test]
fn a_single_altered_resource_is_listed_without_a_separator() {
    let error = CodesignError::VerificationFailed {
        output: exited("codesign", 1, "printed on stdout", "A.app: bad"),
        resources: vec![resource(Change::Missing, "/x/r.txt")],
    };
    assert_eq!(
        error.to_string(),
        "verification failed: A.app: bad (missing: /x/r.txt)"
    );
}

#[test]
fn resources_are_listed_even_without_diagnostics() {
    let error = CodesignError::VerificationFailed {
        output: exited("codesign", 1, "printed on stdout", ""),
        resources: vec![resource(Change::Added, "/x/r.txt")],
    };
    assert_eq!(
        error.to_string(),
        "verification failed: no diagnostics (added: /x/r.txt)"
    );
}

#[cfg(unix)]
#[test]
fn a_resource_path_that_is_not_utf8_is_still_printable() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let path = PathBuf::from(OsString::from_vec(vec![b'/', 0xff, b'b']));
    let error = CodesignError::VerificationFailed {
        output: exited("codesign", 1, "printed on stdout", "bad"),
        resources: vec![ResourceChange {
            change: Change::Modified,
            path: path.clone(),
        }],
    };
    assert_eq!(
        error.to_string(),
        format!("verification failed: bad (modified: {})", path.display())
    );
}

#[test]
fn resource_changes_compare_by_value() {
    assert_eq!(resource(Change::Added, "/a"), resource(Change::Added, "/a"));
    assert_ne!(
        resource(Change::Added, "/a"),
        resource(Change::Modified, "/a")
    );
    assert_ne!(resource(Change::Added, "/a"), resource(Change::Added, "/b"));
}

#[test]
fn an_unsatisfied_requirement_says_the_signature_itself_is_fine() {
    let error = CodesignError::RequirementUnsatisfied {
        output: exited(
            "codesign",
            3,
            "printed on stdout",
            "test-requirement: code failed to satisfy specified code requirement(s)",
        ),
    };
    assert_eq!(
        error.to_string(),
        "validly signed, but the requirement isn't satisfied: \
         test-requirement: code failed to satisfy specified code requirement(s)",
    );
}

#[test]
fn an_unsatisfied_requirement_with_nothing_to_say_still_reads_as_a_sentence() {
    let silent = CodesignError::RequirementUnsatisfied {
        output: exited("codesign", 3, "printed on stdout", ""),
    };
    assert_eq!(
        silent.to_string(),
        "validly signed, but the requirement isn't satisfied: no diagnostics",
    );
}

#[test]
fn the_verification_variants_forward_display_through_the_wrapper() {
    let failed = CodesignError::VerificationFailed {
        output: exited("codesign", 1, "printed on stdout", "x"),
        resources: Vec::new(),
    };
    let unsatisfied = CodesignError::RequirementUnsatisfied {
        output: exited("codesign", 3, "printed on stdout", "y"),
    };
    for inner in [failed, unsatisfied] {
        let text = inner.to_string();
        assert_eq!(Error::from(inner).to_string(), text);
    }
}

fn verdicts() -> [CodesignError; 4] {
    [
        CodesignError::VerificationFailed {
            output: exited("codesign", 1, "verify out", "verify err"),
            resources: Vec::new(),
        },
        CodesignError::RequirementUnsatisfied {
            output: exited("codesign", 3, "requirement out", "requirement err"),
        },
        CodesignError::ConstraintInvalid {
            output: exited("codesign", 0, "constraint out", "constraint err"),
        },
        CodesignError::NoSignature {
            output: exited("codesign", 0, "slot out", "slot err"),
        },
    ]
}

#[test]
fn every_verdict_carries_the_output_of_its_run() {
    let expected = [
        (1, "verify out", "verify err"),
        (3, "requirement out", "requirement err"),
        (0, "constraint out", "constraint err"),
        (0, "slot out", "slot err"),
    ];
    for (error, (code, stdout, stderr)) in verdicts().into_iter().zip(expected) {
        let output = error.output().unwrap_or_else(|| panic!("{error:?}"));
        assert_eq!(output.program, "codesign", "{error:?}");
        assert_eq!(output.status.code(), Some(code), "{error:?}");
        assert_eq!(output.stdout, stdout, "{error:?}");
        assert_eq!(output.stderr, stderr, "{error:?}");
        assert_eq!(error.stdout(), Some(stdout), "{error:?}");
        assert_eq!(error.stderr(), Some(stderr), "{error:?}");
    }
}

#[test]
fn a_missing_binary_has_no_output() {
    let error = CodesignError::NotFound;
    assert!(error.output().is_none());
    assert_eq!(error.stdout(), None);
    assert_eq!(error.stderr(), None);
}

/// The wrapper reaches the verdict's output; the streams are not repeated in the message.
#[test]
fn the_wrapper_delegates_the_accessors_to_the_verdict() {
    for inner in verdicts() {
        let stdout = inner.stdout().map(str::to_owned);
        let stderr = inner.stderr().map(str::to_owned);
        let error = Error::from(inner);

        assert!(error.output().is_some(), "{error:?}");
        assert_eq!(error.stdout().map(str::to_owned), stdout);
        assert_eq!(error.stderr().map(str::to_owned), stderr);
    }
    let missing = Error::from(CodesignError::NotFound);
    assert!(missing.output().is_none());
    assert_eq!((missing.stdout(), missing.stderr()), (None, None));
}
