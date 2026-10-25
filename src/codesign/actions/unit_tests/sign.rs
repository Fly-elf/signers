use std::ffi::OsString;

use super::*;
use crate::codesign::{sign, sign_adhoc, sign_for_distribution};

fn os(strings: &[&str]) -> Vec<OsString> {
    strings.iter().map(OsString::from).collect()
}

/// Renders the arguments, taking ownership so assertions can compare them
/// against plain `OsString`s.
fn args_of<S>(builder: &Sign<S>) -> Vec<OsString> {
    builder
        .options
        .to_args(&builder.job.targets)
        .into_iter()
        .map(Cow::into_owned)
        .collect()
}

#[test]
fn bare_action_only_signs() {
    assert_eq!(
        args_of(&sign("app", "-")),
        os(&["--sign", "-", "--", "app"])
    );
}

#[test]
fn adhoc_signs_with_dash_identity() {
    assert_eq!(
        args_of(&sign_adhoc("app")),
        os(&["--sign", "-", "--", "app"])
    );
}

#[test]
fn for_distribution_enables_hardened_runtime_and_timestamp() {
    assert_eq!(
        args_of(&sign_for_distribution("app", "Developer ID")),
        os(&[
            "--sign",
            "Developer ID",
            "--options",
            "runtime",
            "--timestamp",
            "--",
            "app",
        ])
    );
}

#[test]
#[expect(deprecated, reason = "`--deep` is still rendered, deprecated or not")]
fn scalar_setters_are_forwarded() {
    let action = sign("app", "Developer ID")
        .identifier("com.example.app")
        .entitlements("app.entitlements")
        .force(true)
        .deep(true)
        .page_size(4096)
        .dry_run(true);
    assert_eq!(
        args_of(&action),
        os(&[
            "--sign",
            "Developer ID",
            "--identifier",
            "com.example.app",
            "--entitlements",
            "app.entitlements",
            "--force",
            "--deep",
            "--pagesize",
            "4096",
            "--dryrun",
            "--",
            "app",
        ]),
    );
}

/// Every option this action can render, so that adding one without
/// rendering it — or rendering it in the wrong form — fails here.
///
/// The focused tests below explain individual behaviours; this one exists
/// to be exhaustive, and covers the several options whose effect nothing
/// can observe from outside (`--detached-database` needs root).
#[test]
#[expect(deprecated, reason = "`--deep` is still rendered, deprecated or not")]
fn every_option_renders_exactly_once() {
    let action = sign("app", "Developer ID")
        .identifier("com.example.app")
        .requirements("=designated => anchor apple")
        .prefix("com.example.")
        .keychain("build.keychain")
        .entitlements("app.entitlements")
        .force_library_entitlements(true)
        .generate_entitlement_der(true)
        .options(SigningFlags::RUNTIME)
        .runtime_version("13.1")
        .launch_constraint_self("self.plist")
        .launch_constraint_parent("parent.plist")
        .launch_constraint_responsible("responsible.plist")
        .library_constraint("library.plist")
        .enforce_constraint_validity(true)
        .force(true)
        .deep(true)
        .preserve_metadata(PreserveMetadata::FLAGS)
        .page_size(4096)
        .timestamp(Timestamp::ServerUrl("http://ts.example".into()))
        .bundle_version("A")
        .strip_disallowed_xattrs(true)
        .single_threaded_signing(true)
        .dry_run(true)
        .detached("app.sig")
        .detached_database(true)
        .file_list("signed.txt");

    assert_eq!(
        args_of(&action),
        os(&[
            "--sign",
            "Developer ID",
            "--identifier",
            "com.example.app",
            "--requirements",
            "=designated => anchor apple",
            "--prefix",
            "com.example.",
            "--keychain",
            "build.keychain",
            "--entitlements",
            "app.entitlements",
            "--force-library-entitlements",
            "--generate-entitlement-der",
            "--options",
            "runtime",
            "--runtime-version",
            "13.1",
            "--launch-constraint-self",
            "self.plist",
            "--launch-constraint-parent",
            "parent.plist",
            "--launch-constraint-responsible",
            "responsible.plist",
            "--library-constraint",
            "library.plist",
            "--enforce-constraint-validity",
            "--force",
            "--deep",
            "--preserve-metadata=flags",
            "--pagesize",
            "4096",
            "--timestamp=http://ts.example",
            "--bundle-version",
            "A",
            "--strip-disallowed-xattrs",
            "--single-threaded-signing",
            "--dryrun",
            "--detached",
            "app.sig",
            "--detached-database",
            "--file-list",
            "signed.txt",
            "--",
            "app",
        ]),
    );
}

/// That these are the tokens `codesign` *accepts* is settled against the
/// real binary in `tests/codesign_async/sign/signing_flags.rs`; here they only have to
/// stay comma-joined, in declaration order, with no separators of any kind.
#[test]
fn flag_tokens_are_joined_in_declaration_order() {
    assert_eq!(
        joined(SigningFlags::all()),
        "host,hard,kill,expires,library,runtime,linker-signed"
    );
    assert_eq!(
        joined(PreserveMetadata::all()),
        "identifier,entitlements,requirements,flags,runtime,launch-constraints,library-constraints",
    );
}

#[test]
fn empty_flag_sets_render_no_argument_at_all() {
    // Not `--options ""`, which `codesign` rejects: the option is dropped.
    let action = sign("app", "-")
        .options(SigningFlags::empty())
        .preserve_metadata(PreserveMetadata::empty());
    assert_eq!(args_of(&action), os(&["--sign", "-", "--", "app"]));
}

#[test]
fn flag_sets_render_in_declaration_order() {
    let action = sign("app", "-")
        .options(SigningFlags::RUNTIME | SigningFlags::KILL)
        .preserve_metadata(PreserveMetadata::ENTITLEMENTS | PreserveMetadata::IDENTIFIER);
    assert_eq!(
        args_of(&action),
        os(&[
            "--sign",
            "-",
            "--options",
            "kill,runtime",
            "--preserve-metadata=identifier,entitlements",
            "--",
            "app",
        ]),
    );
}

#[test]
fn flag_sets_replace_rather_than_accumulate() {
    let action = sign("app", "-")
        .options(SigningFlags::RUNTIME)
        .options(SigningFlags::LIBRARY);
    assert_eq!(
        args_of(&action),
        os(&["--sign", "-", "--options", "library", "--", "app"])
    );
}

/// Each variant is a single argument: `--timestamp` takes its value only in
/// the `=` form, so a stray `--timestamp none` would be read as a timestamp
/// request followed by a target named `none`.
#[test]
fn timestamp_variants_each_render_as_one_argument() {
    let rendered = |timestamp| args_of(&sign("app", "-").timestamp(timestamp));
    assert_eq!(
        rendered(Timestamp::Enabled),
        os(&["--sign", "-", "--timestamp", "--", "app"]),
    );
    assert_eq!(
        rendered(Timestamp::Disabled),
        os(&["--sign", "-", "--timestamp=none", "--", "app"]),
    );
    assert_eq!(
        rendered(Timestamp::ServerUrl("http://ts.example".into())),
        os(&["--sign", "-", "--timestamp=http://ts.example", "--", "app"]),
    );
}

#[test]
fn every_constraint_kind_is_emitted() {
    let action = sign("app", "-")
        .library_constraint("library.plist")
        .launch_constraint_self("self.plist")
        .launch_constraint_parent("parent.plist")
        .launch_constraint_responsible("responsible.plist");
    assert_eq!(
        args_of(&action),
        os(&[
            "--sign",
            "-",
            "--launch-constraint-self",
            "self.plist",
            "--launch-constraint-parent",
            "parent.plist",
            "--launch-constraint-responsible",
            "responsible.plist",
            "--library-constraint",
            "library.plist",
            "--",
            "app",
        ]),
    );
}

#[test]
fn repeating_a_constraint_kind_keeps_the_last_path() {
    let action = sign("app", "-")
        .launch_constraint_self("first.plist")
        .launch_constraint_self("third.plist");
    assert_eq!(
        args_of(&action),
        os(&[
            "--sign",
            "-",
            "--launch-constraint-self",
            "third.plist",
            "--",
            "app"
        ]),
    );
}

#[test]
fn a_file_list_of_stdout_fails_validation() {
    let action = sign("app", "-").file_list("-");
    let error = action.options.validate().unwrap_err();
    assert!(
        matches!(error, crate::errors::Error::StdioPath("file_list")),
        "got {error:?}"
    );
}

#[test]
fn a_file_list_pointing_at_a_real_path_passes_validation() {
    let action = sign("app", "-").file_list("signed.txt");
    assert!(action.options.validate().is_ok());
}

#[test]
fn requirements_of_stdin_fail_validation() {
    let action = sign("app", "-").requirements("-");
    let error = action.options.validate().unwrap_err();
    assert!(
        matches!(error, crate::errors::Error::StdioPath("requirements")),
        "got {error:?}"
    );
}

/// Only the exact value `-` reads standard input: source text, a path that
/// merely starts or ends with a dash, and the empty string are all fine.
#[test]
fn requirements_other_than_a_lone_dash_pass_validation() {
    for value in ["=-", "= -", "-x", "--", "./-", "-/a.rqset", " -", "- ", ""] {
        let action = sign("app", "-").requirements(value);
        assert!(action.options.validate().is_ok(), "{value:?}");
    }
}

/// `codesign` reads these `-` as a plain file name, so they are not refused.
#[test]
fn a_dash_in_any_other_option_passes_validation() {
    let action = sign("app", "-")
        .entitlements("-")
        .detached("-")
        .keychain("-")
        .launch_constraint_self("-")
        .launch_constraint_parent("-")
        .launch_constraint_responsible("-")
        .library_constraint("-")
        .identifier("-")
        .prefix("-");
    assert!(action.options.validate().is_ok());
}

#[test]
fn requirements_source_text_is_one_argument_after_the_flag() {
    let action = sign("app", "-").requirements("=designated => anchor apple");
    assert_eq!(
        args_of(&action),
        os(&[
            "--sign",
            "-",
            "--requirements",
            "=designated => anchor apple",
            "--",
            "app"
        ])
    );
}

#[test]
fn targets_come_last() {
    let action = sign(vec!["a.app", "b.app"], "-").force(true);
    assert_eq!(
        args_of(&action),
        os(&["--sign", "-", "--force", "--", "a.app", "b.app"])
    );
}

#[test]
fn the_output_is_one_unit_per_target_whatever_codesign_printed() {
    let action = sign("app", "-").options;
    let targets = [PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];

    let silent: Vec<()> = action
        .output(&targets, String::new(), String::new())
        .unwrap();
    assert_eq!(silent.len(), 3);

    let noisy = action.output(&targets[..1], "noise".into(), "\u{FFFD}\u{FFFD}".into());
    assert_eq!(noisy.unwrap().len(), 1);

    let none = action.output(&[], "noise".into(), String::new());
    assert_eq!(none.unwrap().len(), 0);
}

/// Signing mutates its targets, so the batch stays one `codesign` process
/// unless the caller asks otherwise.
#[test]
fn every_constructor_defaults_to_one_process_for_all_targets() {
    const { assert!(!Options::BATCH) };

    assert!(!sign("app", "-").job.batch);
    assert!(!sign_adhoc(vec!["a.app", "b.app"]).job.batch);
    assert!(
        !sign_for_distribution(["a.app", "b.app"], "Developer ID")
            .job
            .batch
    );
}

#[test]
fn per_target_keeps_the_last_value_and_renders_no_argument() {
    let action = sign(vec!["app"], "-").per_target(true);
    assert!(action.job.batch);
    assert_eq!(args_of(&action), os(&["--sign", "-", "--", "app"]));

    let action = action.per_target(false);
    assert!(!action.job.batch);
    assert_eq!(args_of(&action), os(&["--sign", "-", "--", "app"]));
}

#[test]
fn only_options_writing_one_shared_file_are_reported_as_shared_output() {
    let shared = |builder: Sign| builder.options.shared_output();

    assert_eq!(shared(sign("app", "-")), None);
    assert_eq!(
        shared(sign("app", "-").file_list("signed.txt")),
        Some("file_list")
    );
    assert_eq!(
        shared(sign("app", "-").detached("app.sig")),
        Some("detached")
    );
    // The other options that take a path only read it.
    assert_eq!(
        shared(
            sign("app", "-")
                .entitlements("app.entitlements")
                .keychain("build.keychain")
                .detached_database(true)
                .force(true)
        ),
        None
    );
}

#[test]
fn the_file_list_is_the_shared_output_named_when_both_are_set() {
    for action in [
        sign("app", "-").file_list("signed.txt").detached("app.sig"),
        sign("app", "-").detached("app.sig").file_list("signed.txt"),
    ] {
        assert_eq!(action.options.shared_output(), Some("file_list"));
    }
}

/// `sign` has no exit code of its own to tell apart, so every one of them
/// stays the generic failure, whatever it printed on standard output.
#[test]
fn a_failed_run_is_reported_with_its_code_and_diagnostics() {
    let action = sign("app", "-").options;
    for code in [1, 2, 3] {
        match action.failure(
            code,
            "file modified: /x".into(),
            "app: no identity found".into(),
        ) {
            crate::errors::Error::Process(crate::errors::ProcessError::Failed {
                program,
                code: reported,
                stdout,
                stderr,
            }) => {
                assert_eq!(program, "codesign");
                assert_eq!(reported, code);
                assert_eq!(stdout, "file modified: /x");
                assert_eq!(stderr, "app: no identity found");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
