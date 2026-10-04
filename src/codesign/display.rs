//! The display action and the [`Signature`] it returns (`--display`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::sealed::ToArgs;
use super::actions::{PushArgs, SignatureSlot};
use crate::codesign::Codesign;
use crate::errors::{CodesignError, Result};
use crate::target::Shape;

mod signature;

pub use signature::*;

/// Options of the display action: the `A` in `Codesign<Display>`.
///
/// [`Codesign::display`] creates it. You set its options with
/// [the display setters](Codesign#impl-Codesign%3CDisplay,+S%3E). An option you never set keeps
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
/// use signers::codesign::display::Format;
///
/// let signature = Codesign::display("/bin/ls").architecture("arm64e").await?;
/// assert_eq!(signature.format, Format::MachOThin("arm64e".into()));
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Default)]
pub struct Display {
    architecture: Option<String>,
    bundle_version: Option<String>,
    deep: bool,
    detached: Option<PathBuf>,
    signature_slot: Option<SignatureSlot>,
}

/// Options for [`display`](Codesign::display).
///
/// Each setter maps to one `codesign` flag. A later call replaces an earlier one, and `false`
/// leaves a flag out.
impl<S: Shape> Codesign<Display, S> {
    /// Reads this slice of a universal binary, e.g. `arm64` or `x86_64` (`--architecture`).
    ///
    /// Without it a universal binary is reported whole, as [`Format::MachOUniversal`]. A slice the
    /// binary doesn't have fails with [`CodesignError::Failed`].
    pub fn architecture(mut self, arch: impl Into<String>) -> Self {
        self.action.architecture = Some(arch.into());
        self
    }

    /// Reads this version of a versioned bundle instead of `Current` (`--bundle-version`).
    ///
    /// A version the bundle doesn't have fails with [`CodesignError::Failed`].
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }

    /// Lists the code nested in a bundle, in [`Signature::nested`] (`--deep`).
    ///
    /// Only the items directly inside the bundle are listed, and their own signatures aren't read.
    pub fn deep(mut self, deep: bool) -> Self {
        self.action.deep = deep;
        self
    }

    /// Reads the signature from a detached signature file instead of from the code (`--detached`).
    pub fn detached(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.detached = Some(path.into());
        self
    }

    pub fn signature_slot(mut self, slot: SignatureSlot) -> Self {
        self.action.signature_slot = Some(slot);
        self
    }
}

impl ToArgs for Display {
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
        // has entitlements and nothing for the others, and all requirement
        // lines after the last report, so neither can be matched back to its
        // target.
        if targets.len() == 1 {
            args.flag("-r-");
            args.flag("--entitlements");
            args.flag("-");
            args.flag("--xml");
        }

        args.targets(targets);
        args
    }

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

        let mut signatures = reports
            .into_iter()
            .map(parse_report)
            .collect::<Result<Vec<_>>>()?;

        if let [signature] = signatures.as_mut_slice() {
            let plist = plist_start(&stdout);
            signature.requirements = Some(requirements(&stdout[..plist.unwrap_or(stdout.len())])?);
            if let Some(plist) = plist {
                let entitlements =
                    plist::from_bytes(&stdout.as_bytes()[plist..]).map_err(|error| {
                        CodesignError::UnexpectedOutput {
                            detail: format!("unreadable entitlements: {error}"),
                        }
                    })?;
                signature.entitlements = Some(entitlements);
            }
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

// What precedes the plist is the constraint dump and then one line per
// requirement. Dump lines are tab-indented `[Tag]` lines, but the stream is
// trimmed, which takes the tab off the first one.
fn requirements(stdout: &str) -> Result<Vec<Requirement>> {
    stdout
        .lines()
        .filter(|line| !line.starts_with(['\t', '[']) && !line.trim().is_empty())
        .map(Requirement::parse)
        .collect()
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

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    fn args_of<S>(builder: &Codesign<Display, S>) -> Vec<OsString> {
        builder
            .action
            .to_args(&builder.targets)
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

        assert_eq!(args_of(&Codesign::display("app")), expected);
        assert_eq!(args_of(&Codesign::display(vec!["app"])), expected);
        assert_eq!(args_of(&Codesign::display(["app"])), expected);
    }

    #[test]
    fn several_targets_in_one_run_do_not_ask_for_entitlements() {
        assert_eq!(
            args_of(&Codesign::display(vec!["a", "b"])),
            os(&["--display", "--verbose=4", "--", "a", "b"])
        );
    }

    /// Every option this action can render, so that adding one without
    /// rendering it, or rendering it in the wrong form, fails here.
    #[test]
    fn every_option_renders_exactly_once() {
        let builder = Codesign::display("app")
            .architecture("x86_64")
            .bundle_version("B")
            .deep(true)
            .detached("app.sig");

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
        let builder = Codesign::display(vec!["a", "b"])
            .architecture("x86_64")
            .architecture("arm64")
            .bundle_version("A")
            .bundle_version("B")
            .deep(true)
            .deep(false)
            .detached("first.sig")
            .detached("second.sig");

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
                "--",
                "a",
                "b",
            ])
        );
    }

    #[test]
    fn a_target_with_a_leading_dash_stays_a_target() {
        assert_eq!(
            args_of(&Codesign::display("-app")),
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
        assert!(Codesign::display(vec!["a", "b"]).per_target);
        assert!(Codesign::display(["a", "b"]).per_target);
    }

    #[test]
    fn each_report_becomes_one_signature_in_order() {
        let stderr = format!("{}{}", report("/x/a", "first"), report("/x/b", "second"));

        let signatures = Display::default()
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
        let signatures = Display::default()
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

        let signatures = Display::default()
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
            unexpected_output(Display::default().output(&targets, String::new(), stderr));
        }
    }

    #[test]
    fn an_unreadable_report_is_rejected() {
        let stderr = report("/x/a", "first").replace("Total signatures=1", "Total signatures=x");

        let detail =
            unexpected_output(Display::default().output(&paths(&["a"]), String::new(), stderr));

        assert!(detail.contains("Total signatures"), "{detail}");
    }

    #[test]
    fn a_single_target_reads_its_entitlements_from_stdout() {
        let signatures = Display::default()
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
        let signatures = Display::default()
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
            unexpected_output(Display::default().output(
                &paths(&["a"]),
                stdout.to_owned(),
                report("/x/a", "first"),
            ));
        }
    }

    const DUMP: &str = "\t[Dict]\n\t\t[Key] ccat\n\t\t[Value]\n\t\t\t[Int] 0\n";

    fn entitlement_keys(stdout: String) -> Option<Vec<String>> {
        let signatures = Display::default()
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

        let signatures = Display::default()
            .output(&paths(&["a", "b"]), ENTITLEMENTS.to_owned(), stderr)
            .unwrap();

        assert!(signatures.iter().all(|s| s.entitlements.is_none()));
    }

    #[test]
    fn whitespace_around_either_stream_does_not_matter() {
        let stdout = format!("\n\n{ENTITLEMENTS}\n\n");
        let stderr = format!("\n{}\n\n", report("/x/a", "first"));

        let signatures = Display::default()
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

        let signatures = Display::default()
            .output_bytes(
                &[PathBuf::from(OsStr::from_bytes(b"caf\xE9"))],
                Vec::new(),
                stderr,
            )
            .unwrap();

        assert_eq!(signatures[0].executable, PathBuf::from("/x/caf\u{FFFD}"));
    }
}
