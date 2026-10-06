use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::action::PushArgs;
use crate::codesign::action::action;
use crate::codesign::action::sealed::{SharedRun, ToArgs};
use crate::codesign::types::parse_report;
use crate::codesign::{Signature, SignatureSlot};
use crate::errors::{CodesignError, Result};

action! {
    /// Options of the display action: the `A` in `Codesign<Display>`.
    ///
    /// [`Codesign::display`](crate::Codesign#method.display) creates it. You set its options with [the
    /// display setters](crate::Codesign#impl-Runner%3CDisplay,+S,+R%3E). An option you never set keeps
    /// `codesign`'s default.
    ///
    /// # Examples
    ///
    /// List the code nested in a bundle:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let signature = Codesign::display("MyApp.app").deep(true).await?;
    /// for path in &signature.nested {
    ///     println!("{path}");
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// Read one slice of a universal binary:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    /// use signers::codesign::Format;
    ///
    /// let signature = Codesign::display("/bin/ls").architecture("arm64e").await?;
    /// assert_eq!(signature.format, Format::MachOThin("arm64e".into()));
    /// # Ok(()) }
    /// ```
    Display => Signature {
    }
    setters {
        /// Reads this slice of a universal binary, e.g. `arm64` or `x86_64` (`--architecture`).
        ///
        /// Without it a universal binary is reported whole, as
        /// [`Format::MachOUniversal`](crate::codesign::Format::MachOUniversal). A slice the binary
        /// doesn't have fails with [`CodesignError::Failed`].
        architecture: Option<impl Into<String>>,
        /// Reads this version of a versioned bundle instead of `Current` (`--bundle-version`).
        ///
        /// A version the bundle doesn't have fails with [`CodesignError::Failed`].
        bundle_version: Option<impl Into<String>>,
        /// Lists the code nested in a bundle, in [`Signature::nested`] (`--deep`).
        ///
        /// Only the items directly inside the bundle are listed, and their own signatures aren't read.
        deep: bool,
        /// Reads the signature from a detached signature file instead of from the code (`--detached`).
        detached: Option<impl Into<PathBuf>>,
        /// Reads this signature when the code carries two (`--signature-slot`).
        ///
        /// Code with one signature has only [`SignatureSlot::First`]. Asking for the second fails with
        /// [`CodesignError::NoSignature`].
        signature_slot: Option<SignatureSlot>,
    }
}

impl<S, R> SharedRun for Display<S, R> {}

impl ToArgs for Options {
    type Output = Signature;
    const PER_TARGET: bool = true;

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();

        args.flag("--display");
        args.flag("--verbose=4");

        if let Some(architecture) = &self.architecture {
            args.option("--architecture", architecture);
        }
        if let Some(bundle_version) = &self.bundle_version {
            args.option("--bundle-version", bundle_version);
        }
        if self.deep {
            args.flag("--deep");
        }
        if let Some(detached) = &self.detached {
            args.option("--detached", detached);
        }
        if let Some(slot) = self.signature_slot {
            args.option("--signature-slot", slot.as_str());
        }

        // Over several targets `codesign` prints one plist per target that
        // has entitlements and nothing for the others, so they can't be
        // matched back to their targets.
        if targets.len() == 1 {
            args.flag("--entitlements");
            args.flag("-");
            args.flag("--xml");
        }

        args.targets(targets);
        args
    }

    /// Splits stderr into one report per target, each starting at its `Executable=` line, and
    /// parses them in order.
    ///
    /// A report with a `: no signature` line and no `Signature=` line (exit 0, from a
    /// `signature_slot` the code has no signature in) fails the whole run with
    /// [`CodesignError::NoSignature`]. Entitlements come from the plist on stdout, which only a
    /// single-target run asks for.
    fn output(
        &self,
        targets: &[PathBuf],
        stdout: String,
        stderr: String,
    ) -> Result<Vec<Signature>> {
        let reports = reports(&stderr);
        if reports.len() != targets.len() {
            return Err(CodesignError::UnexpectedOutput {
                detail: format!("{} reports for {} targets", reports.len(), targets.len()),
            }
            .into());
        }

        // `--signature-slot` past the last signature exits 0 and prints
        // `<path>: no signature` in place of the `Signature=` line.
        if reports.iter().any(|report| {
            !report.lines().any(|line| line.starts_with("Signature="))
                && report.lines().any(|line| line.ends_with(": no signature"))
        }) {
            return Err(CodesignError::NoSignature { stdout, stderr }.into());
        }

        let mut signatures = reports
            .into_iter()
            .map(parse_report)
            .collect::<Result<Vec<_>>>()?;

        if let [signature] = signatures.as_mut_slice()
            && let Some(plist) = plist_start(&stdout)
        {
            let entitlements = plist::from_bytes(&stdout.as_bytes()[plist..]).map_err(|error| {
                CodesignError::UnexpectedOutput {
                    detail: format!("unreadable entitlements: {error}"),
                }
            })?;
            signature.entitlements = Some(entitlements);
        }

        Ok(signatures)
    }
}

// `--verbose=4` prints a text dump of the constraint dictionaries before the
// plist, which always starts on its own line.
fn plist_start(stdout: &str) -> Option<usize> {
    const MARKER: &str = "<?xml";
    let bytes = stdout.as_bytes();
    (0..stdout.len())
        .filter(|&i| i == 0 || bytes[i - 1] == b'\n')
        .find(|&i| stdout[i..].starts_with(MARKER))
}

// Each report starts at its `Executable=` line; anything before the first
// one belongs to no target.
fn reports(stderr: &str) -> Vec<&str> {
    let mut starts = Vec::new();
    let mut offset = 0;
    for line in stderr.split_inclusive('\n') {
        if line.starts_with("Executable=") {
            starts.push(offset);
        }
        offset += line.len();
    }
    starts.push(stderr.len());
    starts
        .windows(2)
        .map(|bounds| stderr[bounds[0]..bounds[1]].trim_end())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStrExt;

    use super::*;
    use crate::codesign::SignatureKind;
    use crate::codesign::display;

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    fn args_of<S>(builder: &Display<S>) -> Vec<OsString> {
        builder
            .options
            .to_args(&builder.core.targets)
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

    fn unexpected_output(result: Result<Vec<Signature>>) -> String {
        match result {
            Err(crate::Error::Codesign(CodesignError::UnexpectedOutput { detail })) => detail,
            other => panic!("expected UnexpectedOutput, got {other:?}"),
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
        assert!(display(vec!["a", "b"]).core.per_target);
        assert!(display(["a", "b"]).core.per_target);
    }

    /// The setter is typed on the shape, not on the length.
    #[test]
    fn a_one_element_collection_keeps_the_per_target_setter() {
        assert!(!display(vec!["a"]).per_target(false).core.per_target);
        assert!(!display(["a"]).per_target(false).core.per_target);
        assert!(
            display(vec!["a"])
                .per_target(false)
                .per_target(true)
                .core
                .per_target
        );
    }

    #[test]
    fn each_report_becomes_one_signature_in_order() {
        let stderr = format!("{}{}", report("/x/a", "first"), report("/x/b", "second"));

        let signatures = Options::default()
            .output(&paths(&["a", "b"]), String::new(), stderr)
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
            .output(&paths(&["a", "b"]), String::new(), stderr)
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
            .output(&paths(&["a"]), String::new(), stderr)
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
            unexpected_output(Options::default().output(&targets, String::new(), stderr));
        }
    }

    #[test]
    fn an_unreadable_report_is_rejected() {
        let stderr = report("/x/a", "first").replace("Total signatures=1", "Total signatures=x");

        let detail =
            unexpected_output(Options::default().output(&paths(&["a"]), String::new(), stderr));

        assert!(detail.contains("Total signatures"), "{detail}");
    }

    #[test]
    fn a_single_target_reads_its_entitlements_from_stdout() {
        let signatures = Options::default()
            .output(
                &paths(&["a"]),
                ENTITLEMENTS.to_owned(),
                report("/x/a", "first"),
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
            .output(&paths(&["a"]), String::new(), report("/x/a", "first"))
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
            unexpected_output(Options::default().output(
                &paths(&["a"]),
                stdout.to_owned(),
                report("/x/a", "first"),
            ));
        }
    }

    const DUMP: &str = "\t[Dict]\n\t\t[Key] ccat\n\t\t[Value]\n\t\t\t[Int] 0\n";

    fn entitlement_keys(stdout: String) -> Option<Vec<String>> {
        let signatures = Options::default()
            .output(&paths(&["a"]), stdout, report("/x/a", "first"))
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
            .output(&paths(&["a", "b"]), ENTITLEMENTS.to_owned(), stderr)
            .unwrap();

        assert!(signatures.iter().all(|s| s.entitlements.is_none()));
    }

    #[test]
    fn whitespace_around_either_stream_does_not_matter() {
        let stdout = format!("\n\n{ENTITLEMENTS}\n\n");
        let stderr = format!("\n{}\n\n", report("/x/a", "first"));

        let signatures = Options::default()
            .output_bytes(&paths(&["a"]), stdout.into_bytes(), stderr.into_bytes())
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
            .output_bytes(
                &[PathBuf::from(OsStr::from_bytes(b"caf\xE9"))],
                Vec::new(),
                stderr,
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

    fn no_signature(result: Result<Vec<Signature>>) -> (String, String) {
        match result {
            Err(crate::Error::Codesign(CodesignError::NoSignature { stdout, stderr })) => {
                (stdout, stderr)
            }
            other => panic!("expected NoSignature, got {other:?}"),
        }
    }

    #[test]
    fn a_report_that_says_no_signature_in_place_of_the_signature_line_is_no_signature() {
        let stderr = without_signature("/x/a");

        let (out, err) = no_signature(Options::default().output(
            &paths(&["a"]),
            ENTITLEMENTS.to_owned(),
            stderr.clone(),
        ));

        assert_eq!(out, ENTITLEMENTS);
        assert_eq!(err, stderr);
    }

    #[test]
    fn one_target_without_a_signature_fails_the_whole_run_with_both_streams() {
        let stderr = format!("{}{}", report("/x/a", "first"), without_signature("/x/b"));

        let (out, err) = no_signature(Options::default().output(
            &paths(&["a", "b"]),
            "out".to_owned(),
            stderr.clone(),
        ));

        assert_eq!(out, "out");
        assert_eq!(err, stderr);
    }

    #[test]
    fn a_missing_signature_line_without_the_no_signature_note_is_unexpected_output() {
        let stderr = report("/x/a", "first").replace("Signature=adhoc\n", "");

        let detail =
            unexpected_output(Options::default().output(&paths(&["a"]), String::new(), stderr));

        assert!(detail.contains("Signature"), "{detail}");
    }

    #[test]
    fn the_no_signature_note_beside_a_signature_line_is_not_an_error() {
        let stderr = report("/x/a", "first").replace(
            "Info.plist=not bound\n",
            "/x/a: no signature\nInfo.plist=not bound\n",
        );

        let signatures = Options::default()
            .output(&paths(&["a"]), String::new(), stderr)
            .unwrap();

        assert_eq!(signatures[0].signature, SignatureKind::AdHoc);
    }

    #[test]
    fn a_line_that_only_mentions_no_signature_is_not_the_note() {
        let stderr = report("/x/a", "first").replace("Signature=adhoc\n", "no signature at all\n");

        unexpected_output(Options::default().output(&paths(&["a"]), String::new(), stderr));
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
}
