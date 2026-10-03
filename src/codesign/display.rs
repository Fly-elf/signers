use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::codesign::Codesign;
use crate::errors::{CodesignError, Result};
use crate::target::Shape;

mod signature;

pub use signature::*;

#[derive(Debug, Clone, Default)]
pub struct Display {
    architecture: Option<String>,
    bundle_version: Option<String>,
    deep: bool,
    detached: Option<PathBuf>,
}

impl<S: Shape> Codesign<Display, S> {
    pub fn architecture(mut self, arch: impl Into<String>) -> Self {
        self.action.architecture = Some(arch.into());
        self
    }

    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }

    pub fn deep(mut self, deep: bool) -> Self {
        self.action.deep = deep;
        self
    }

    pub fn detached(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.detached = Some(path.into());
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

    fn output(
        &self,
        targets: &[PathBuf],
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<Vec<Signature>> {
        let stderr = String::from_utf8_lossy(&stderr);
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

        if let [signature] = signatures.as_mut_slice()
            && let Some(plist) = plist_start(&stdout)
        {
            let entitlements = plist::from_bytes(&stdout[plist..]).map_err(|error| {
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
fn plist_start(stdout: &[u8]) -> Option<usize> {
    const MARKER: &[u8] = b"<?xml";
    (0..stdout.len())
        .filter(|&i| i == 0 || stdout[i - 1] == b'\n')
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
        .map(|bounds| &stderr[bounds[0]..bounds[1]])
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
            .output(&paths(&["a", "b"]), Vec::new(), stderr.into_bytes())
            .unwrap();

        let identifiers: Vec<&str> = signatures.iter().map(|s| s.identifier.as_str()).collect();
        assert_eq!(identifiers, ["first", "second"]);
        assert_eq!(signatures[0].executable, PathBuf::from("/x/a"));
        assert_eq!(signatures[0].raw(), report("/x/a", "first"));
        assert_eq!(signatures[1].raw(), report("/x/b", "second"));
        assert!(signatures.iter().all(|s| s.entitlements.is_none()));
    }

    #[test]
    fn lines_before_the_first_report_are_ignored() {
        let stderr = format!(
            "a warning\nwarning: Executable=no\n{}",
            report("/x/a", "first")
        );

        let signatures = Display::default()
            .output(&paths(&["a"]), Vec::new(), stderr.into_bytes())
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
            unexpected_output(Display::default().output(&targets, Vec::new(), stderr.into_bytes()));
        }
    }

    #[test]
    fn an_unreadable_report_is_rejected() {
        let stderr = report("/x/a", "first").replace("Total signatures=1", "Total signatures=x");

        let detail = unexpected_output(Display::default().output(
            &paths(&["a"]),
            Vec::new(),
            stderr.into_bytes(),
        ));

        assert!(detail.contains("Total signatures"), "{detail}");
    }

    #[test]
    fn a_single_target_reads_its_entitlements_from_stdout() {
        let signatures = Display::default()
            .output(
                &paths(&["a"]),
                ENTITLEMENTS.as_bytes().to_vec(),
                report("/x/a", "first").into_bytes(),
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
            .output(
                &paths(&["a"]),
                Vec::new(),
                report("/x/a", "first").into_bytes(),
            )
            .unwrap();

        assert_eq!(signatures[0].entitlements, None);
    }

    #[test]
    fn unreadable_entitlements_are_rejected() {
        for stdout in ["not a plist", "<plist version=\"1.0\"><array/></plist>"] {
            unexpected_output(Display::default().output(
                &paths(&["a"]),
                stdout.as_bytes().to_vec(),
                report("/x/a", "first").into_bytes(),
            ));
        }
    }

    /// One process over several targets can't say whose entitlements stdout
    /// holds, so none are attributed.
    #[test]
    fn several_targets_in_one_run_have_no_entitlements() {
        let stderr = format!("{}{}", report("/x/a", "first"), report("/x/b", "second"));

        let signatures = Display::default()
            .output(
                &paths(&["a", "b"]),
                ENTITLEMENTS.as_bytes().to_vec(),
                stderr.into_bytes(),
            )
            .unwrap();

        assert!(signatures.iter().all(|s| s.entitlements.is_none()));
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
            .output(
                &[PathBuf::from(OsStr::from_bytes(b"caf\xE9"))],
                Vec::new(),
                stderr,
            )
            .unwrap();

        assert_eq!(signatures[0].executable, PathBuf::from("/x/caf\u{FFFD}"));
    }
}
