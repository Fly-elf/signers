use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use super::*;
use crate::codesign::SignatureKind;
use crate::codesign::display;
use crate::errors::testing::ran;

fn os(strings: &[&str]) -> Vec<OsString> {
    strings.iter().map(OsString::from).collect()
}

fn args_of<S>(builder: &Display<S>) -> Vec<OsString> {
    builder
        .options
        .to_args(&builder.job.targets)
        .into_iter()
        .map(Cow::into_owned)
        .collect()
}

/// A minimal report `codesign -dvvvv` could print for `executable`.
fn report(executable: &str, identifier: &str) -> String {
    format!(
        "Executable={executable}
Identifier={identifier}
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=292 flags=0x2(adhoc) hashes=3+2 location=embedded
Hash type=sha256 size=32
Executable Segment base=0
Executable Segment limit=16384
Executable Segment flags=0x1
CDHash=da0bf9309ef3710b135a2955182029a928202e55
Signature=adhoc
Info.plist=not bound
Total signatures=1
Chosen signature=1
"
    )
}

const ENTITLEMENTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/><key>com.apple.security.get-task-allow</key><true/></dict></plist>"#;

fn paths(names: &[&str]) -> Vec<PathBuf> {
    names.iter().map(PathBuf::from).collect()
}

fn unreadable(result: Result<Vec<Signature>, Rejection>) -> String {
    match result {
        Err(Rejection::Unreadable(detail)) => detail,
        other => panic!("expected Unreadable, got {other:?}"),
    }
}

#[test]
fn one_target_also_asks_for_its_entitlements() {
    let expected = os(&[
        "--display",
        "--verbose=4",
        "--entitlements",
        "-",
        "--xml",
        "--",
        "app",
    ]);

    assert_eq!(args_of(&display("app")), expected);
    assert_eq!(args_of(&display(vec!["app"])), expected);
    assert_eq!(args_of(&display(["app"])), expected);
}

#[test]
fn several_targets_in_one_run_do_not_ask_for_entitlements() {
    assert_eq!(
        args_of(&display(vec!["a", "b"])),
        os(&["--display", "--verbose=4", "--", "a", "b"])
    );
}

/// Every option this action can render, so that adding one without
/// rendering it, or rendering it in the wrong form, fails here.
#[test]
fn every_option_renders_exactly_once() {
    let builder = display("app")
        .architecture("x86_64")
        .bundle_version("B")
        .deep(true)
        .detached("app.sig")
        .signature_slot(SignatureSlot::Second);

    assert_eq!(
        args_of(&builder),
        os(&[
            "--display",
            "--verbose=4",
            "--architecture",
            "x86_64",
            "--bundle-version",
            "B",
            "--deep",
            "--detached",
            "app.sig",
            "--signature-slot",
            "2",
            "--entitlements",
            "-",
            "--xml",
            "--",
            "app",
        ])
    );
}

#[test]
fn repeating_an_option_keeps_the_last_value() {
    let builder = display(vec!["a", "b"])
        .architecture("x86_64")
        .architecture("arm64")
        .bundle_version("A")
        .bundle_version("B")
        .deep(true)
        .deep(false)
        .detached("first.sig")
        .detached("second.sig")
        .signature_slot(SignatureSlot::Second)
        .signature_slot(SignatureSlot::First);

    assert_eq!(
        args_of(&builder),
        os(&[
            "--display",
            "--verbose=4",
            "--architecture",
            "arm64",
            "--bundle-version",
            "B",
            "--detached",
            "second.sig",
            "--signature-slot",
            "1",
            "--",
            "a",
            "b",
        ])
    );
}

#[test]
fn a_target_with_a_leading_dash_stays_a_target() {
    assert_eq!(
        args_of(&display("-app")),
        os(&[
            "--display",
            "--verbose=4",
            "--entitlements",
            "-",
            "--xml",
            "--",
            "-app",
        ])
    );
}

#[test]
fn collections_default_to_one_run_per_target() {
    const { assert!(Options::BATCH) };

    assert!(display(vec!["a", "b"]).job.batch);
    assert!(display(["a", "b"]).job.batch);
}

/// The setter is typed on the shape, not on the length.
#[test]
fn a_one_element_collection_keeps_the_per_target_setter() {
    assert!(!display(vec!["a"]).per_target(false).job.batch);
    assert!(!display(["a"]).per_target(false).job.batch);
    assert!(
        display(vec!["a"])
            .per_target(false)
            .per_target(true)
            .job
            .batch
    );
}

#[test]
fn each_report_becomes_one_signature_in_order() {
    let stderr = format!("{}{}", report("/x/a", "first"), report("/x/b", "second"));

    let signatures = Options::default()
        .output(&paths(&["a", "b"]), &ran("", stderr))
        .unwrap();

    let identifiers: Vec<&str> = signatures.iter().map(|s| s.identifier.as_str()).collect();
    assert_eq!(identifiers, ["first", "second"]);
    assert_eq!(signatures[0].executable, PathBuf::from("/x/a"));
    assert_eq!(signatures[0].raw(), report("/x/a", "first").trim_end());
    assert_eq!(signatures[1].raw(), report("/x/b", "second").trim_end());
    assert!(signatures.iter().all(|s| s.raw() == s.raw().trim_end()));
    assert!(signatures.iter().all(|s| s.entitlements.is_none()));
}

#[test]
fn no_report_keeps_trailing_whitespace_whatever_the_run_printed() {
    let stderr = format!(
        "{}\n\n{}  \n",
        report("/x/a", "first"),
        report("/x/b", "second")
    );

    for blocks in [reports(&stderr), reports(&format!("{stderr}\n"))] {
        assert_eq!(blocks.len(), 2);
        assert!(blocks.iter().all(|b| *b == b.trim_end()), "{blocks:?}");
        assert!(blocks[0].ends_with("Chosen signature=1"));
    }
    let signatures = Options::default()
        .output(&paths(&["a", "b"]), &ran("", stderr))
        .unwrap();
    assert!(signatures.iter().all(|s| s.raw() == s.raw().trim_end()));
}

#[test]
fn lines_before_the_first_report_are_ignored() {
    let stderr = format!(
        "a warning\nwarning: Executable=no\n{}",
        report("/x/a", "first")
    );

    let signatures = Options::default()
        .output(&paths(&["a"]), &ran("", stderr))
        .unwrap();

    assert_eq!(signatures.len(), 1);
    assert_eq!(signatures[0].identifier, "first");
    assert!(signatures[0].raw().starts_with("Executable=/x/a\n"));
}

#[test]
fn a_report_count_other_than_the_target_count_is_rejected() {
    let one = report("/x/a", "first");
    let two = format!("{one}{}", report("/x/b", "second"));
    let cases = [
        (paths(&["a", "b"]), one.clone()),
        (paths(&["a"]), two),
        (paths(&["a"]), String::new()),
        (paths(&["a"]), "no report at all\n".to_owned()),
    ];

    for (targets, stderr) in cases {
        unreadable(Options::default().output(&targets, &ran("", stderr)));
    }
}

#[test]
fn an_unreadable_report_is_rejected() {
    let stderr = report("/x/a", "first").replace("Total signatures=1", "Total signatures=x");

    let detail = unreadable(Options::default().output(&paths(&["a"]), &ran("", stderr)));

    assert!(detail.contains("Total signatures"), "{detail}");
}

#[test]
fn a_single_target_reads_its_entitlements_from_stdout() {
    let signatures = Options::default()
        .output(
            &paths(&["a"]),
            &ran(ENTITLEMENTS.to_owned(), report("/x/a", "first")),
        )
        .unwrap();

    let entitlements = signatures[0]
        .entitlements
        .as_ref()
        .expect("no entitlements");
    let keys: Vec<&str> = entitlements.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "com.apple.security.cs.allow-jit",
            "com.apple.security.get-task-allow"
        ]
    );
    assert_eq!(
        entitlements.get("com.apple.security.get-task-allow"),
        Some(&plist::Value::Boolean(true))
    );
}

#[test]
fn a_single_target_with_nothing_on_stdout_has_no_entitlements() {
    let signatures = Options::default()
        .output(&paths(&["a"]), &ran("", report("/x/a", "first")))
        .unwrap();

    assert_eq!(signatures[0].entitlements, None);
}

#[test]
fn unreadable_entitlements_are_rejected() {
    for stdout in [
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><array/></plist>",
        "<?xml not a plist",
        "\t[Dict]\n<?xml version=\"1.0\"?><plist",
    ] {
        unreadable(Options::default().output(
            &paths(&["a"]),
            &ran(stdout.to_owned(), report("/x/a", "first")),
        ));
    }
}

const DUMP: &str = "\t[Dict]\n\t\t[Key] ccat\n\t\t[Value]\n\t\t\t[Int] 0\n";

fn entitlement_keys(stdout: String) -> Option<Vec<String>> {
    let signatures = Options::default()
        .output(&paths(&["a"]), &ran(stdout, report("/x/a", "first")))
        .unwrap();
    signatures[0]
        .entitlements
        .as_ref()
        .map(|e| e.keys().cloned().collect())
}

#[test]
fn a_constraint_dump_before_the_plist_is_skipped() {
    let keys = entitlement_keys(format!("{DUMP}{DUMP}{ENTITLEMENTS}"));

    assert_eq!(
        keys.unwrap(),
        [
            "com.apple.security.cs.allow-jit",
            "com.apple.security.get-task-allow"
        ]
    );
}

#[test]
fn a_constraint_dump_without_a_plist_has_no_entitlements() {
    assert_eq!(entitlement_keys(DUMP.to_owned()), None);
    assert_eq!(entitlement_keys(format!("{DUMP}  <?xml indented\n")), None);
}

#[test]
fn a_plist_marker_inside_a_dump_line_is_not_the_plist() {
    let keys = entitlement_keys(format!("\t[String] <?xml\n{ENTITLEMENTS}"));

    assert_eq!(keys.unwrap().len(), 2);
}

/// One process over several targets can't say whose entitlements stdout
/// holds, so none are attributed.
#[test]
fn several_targets_in_one_run_have_no_entitlements() {
    let stderr = format!("{}{}", report("/x/a", "first"), report("/x/b", "second"));

    let signatures = Options::default()
        .output(&paths(&["a", "b"]), &ran(ENTITLEMENTS.to_owned(), stderr))
        .unwrap();

    assert!(signatures.iter().all(|s| s.entitlements.is_none()));
}

#[test]
fn streams_trimmed_by_the_process_run_parse_as_they_are() {
    let stderr = report("/x/a", "first");

    let signatures = Options::default()
        .output(
            &paths(&["a"]),
            &ran(ENTITLEMENTS.trim().to_owned(), stderr.trim().to_owned()),
        )
        .unwrap();

    assert_eq!(signatures[0].identifier, "first");
    assert_eq!(signatures[0].raw(), report("/x/a", "first").trim_end());
    assert_eq!(signatures[0].entitlements.as_ref().unwrap().len(), 2);
}

#[test]
fn a_non_utf8_executable_path_is_decoded_lossily() {
    let mut stderr = b"Executable=/x/caf".to_vec();
    stderr.push(0xE9);
    stderr.extend_from_slice(
        report("", "first")
            .strip_prefix("Executable=")
            .unwrap()
            .as_bytes(),
    );

    let signatures = Options::default()
        .output(
            &[PathBuf::from(OsStr::from_bytes(b"caf\xE9"))],
            &ran("", String::from_utf8_lossy(&stderr).into_owned()),
        )
        .unwrap();

    assert_eq!(signatures[0].executable, PathBuf::from("/x/caf\u{FFFD}"));
}

fn without_signature(executable: &str) -> String {
    report(executable, "first").replace(
        "Signature=adhoc\n",
        &format!("{executable}: no signature\n"),
    )
}

fn no_signature(result: Result<Vec<Signature>, Rejection>) -> (String, String) {
    match result {
        Err(Rejection::Error(crate::Error::Codesign(CodesignError::NoSignature { output }))) => {
            assert_eq!(output.program, "codesign");
            assert!(output.status.success());
            (output.stdout, output.stderr)
        }
        other => panic!("expected NoSignature, got {other:?}"),
    }
}

#[test]
fn a_report_that_says_no_signature_in_place_of_the_signature_line_is_no_signature() {
    let stderr = without_signature("/x/a");

    let (out, err) = no_signature(Options::default().output(
        &paths(&["a"]),
        &ran(ENTITLEMENTS.to_owned(), stderr.clone()),
    ));

    assert_eq!(out, ENTITLEMENTS);
    assert_eq!(err, stderr);
}

#[test]
fn one_target_without_a_signature_fails_the_whole_run_with_both_streams() {
    let stderr = format!("{}{}", report("/x/a", "first"), without_signature("/x/b"));

    let (out, err) = no_signature(
        Options::default().output(&paths(&["a", "b"]), &ran("out".to_owned(), stderr.clone())),
    );

    assert_eq!(out, "out");
    assert_eq!(err, stderr);
}

#[test]
fn a_missing_signature_line_without_the_no_signature_note_is_unreadable() {
    let stderr = report("/x/a", "first").replace("Signature=adhoc\n", "");

    let detail = unreadable(Options::default().output(&paths(&["a"]), &ran("", stderr)));

    assert!(detail.contains("Signature"), "{detail}");
}

#[test]
fn the_no_signature_note_beside_a_signature_line_is_not_an_error() {
    let stderr = report("/x/a", "first").replace(
        "Info.plist=not bound\n",
        "/x/a: no signature\nInfo.plist=not bound\n",
    );

    let signatures = Options::default()
        .output(&paths(&["a"]), &ran("", stderr))
        .unwrap();

    assert_eq!(signatures[0].signature, SignatureKind::AdHoc);
}

#[test]
fn a_line_that_only_mentions_no_signature_is_not_the_note() {
    let stderr = report("/x/a", "first").replace("Signature=adhoc\n", "no signature at all\n");

    unreadable(Options::default().output(&paths(&["a"]), &ran("", stderr)));
}

#[test]
fn the_signature_slot_renders_one_or_two() {
    for (slot, number) in [(SignatureSlot::First, "1"), (SignatureSlot::Second, "2")] {
        assert_eq!(
            args_of(&display(vec!["a", "b"]).signature_slot(slot)),
            os(&[
                "--display",
                "--verbose=4",
                "--signature-slot",
                number,
                "--",
                "a",
                "b"
            ])
        );
    }
}
