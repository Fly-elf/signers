//! The verification oracle: the macOS `codesign` CLI itself.
//!
//! Tests check what `signers` produced by asking `codesign` to read it back, so
//! a bug in the library can never validate its own output. Every accessor here
//! parses output shapes confirmed against a real `codesign` on macOS.

use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

/// A finished `codesign` invocation.
///
/// Both streams are kept because `codesign` splits its output: the `-d` report
/// and all diagnostics go to stderr, while payloads it is asked to *print*
/// (entitlements, requirements) go to stdout.
pub struct Run {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Run {
    /// Unwraps a run that is expected to succeed, e.g. while setting a fixture
    /// up — a broken harness must be distinguishable from a failed assertion.
    pub fn expect_success(self, doing: &str) -> Self {
        assert!(
            self.success,
            "the test harness could not {doing}: {}",
            self.stderr.trim()
        );
        self
    }
}

/// Runs the real `codesign` binary with `args`.
///
/// ```ignore
/// let run = codesign(&["--remove-signature".as_ref(), path.as_ref()]);
/// ```
pub fn codesign(args: &[&OsStr]) -> Run {
    let output = Command::new("codesign").args(args).output().expect(
        "could not run `codesign`; the integration suite needs the Xcode Command Line Tools",
    );

    Run {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Whether `path` carries a signature, panicking rather than guessing if
/// `codesign` fails for some other reason (a missing or unreadable file).
pub fn is_signed(path: &Path) -> bool {
    let run = codesign(&["-d".as_ref(), path.as_ref()]);
    if run.success {
        return true;
    }
    assert!(
        run.stderr.contains("code object is not signed at all"),
        "could not tell whether {} is signed: {}",
        path.display(),
        run.stderr.trim(),
    );
    false
}

/// Validates the signature on `path` (`--verify --strict --deep`), returning
/// `codesign`'s complaint if it is not valid.
pub fn verify(path: &Path) -> Result<(), String> {
    let run = codesign(&[
        "--verify".as_ref(),
        "--strict".as_ref(),
        "--deep".as_ref(),
        "-vvv".as_ref(),
        path.as_ref(),
    ]);
    if run.success {
        Ok(())
    } else {
        Err(run.stderr.trim().to_string())
    }
}

/// [`verify`] as an assertion, for the many tests whose point is just "and the
/// result is a valid signature".
pub fn assert_valid(path: &Path) {
    if let Err(why) = verify(path) {
        panic!("{} carries no valid signature: {why}", path.display());
    }
}

/// Validates `path` against a detached signature file.
pub fn verify_detached(signature: &Path, path: &Path) -> Result<(), String> {
    let run = codesign(&[
        "-v".as_ref(),
        "--detached".as_ref(),
        signature.as_ref(),
        path.as_ref(),
    ]);
    if run.success {
        Ok(())
    } else {
        Err(run.stderr.trim().to_string())
    }
}

/// The entitlements embedded in `path`, as XML — empty when there are none.
pub fn entitlements(path: &Path) -> String {
    codesign(&[
        "-d".as_ref(),
        "--entitlements".as_ref(),
        "-".as_ref(),
        "--xml".as_ref(),
        path.as_ref(),
    ])
    .expect_success("read back entitlements")
    .stdout
}

/// The designated requirement embedded in `path`.
pub fn designated_requirement(path: &Path) -> String {
    codesign(&["-d".as_ref(), "-r-".as_ref(), path.as_ref()])
        .expect_success("read back the designated requirement")
        .stdout
        .trim()
        .to_string()
}

/// The `codesign -dvvvv` report for a signed target.
pub struct Signature {
    raw: String,
}

impl Signature {
    /// Reads the signature of `path`, panicking if there is none — a test that
    /// expects an unsigned target asserts on [`is_signed`] instead.
    pub fn of(path: &Path) -> Self {
        let run = codesign(&["-dvvvv".as_ref(), path.as_ref()])
            .expect_success(&format!("read the signature of {}", path.display()));
        Self { raw: run.stderr }
    }

    /// The signature on one slice of a universal binary, which carries its own
    /// CodeDirectory independent of the others.
    pub fn of_arch(path: &Path, arch: &str) -> Self {
        let run = codesign(&[
            "-dvvvv".as_ref(),
            "--arch".as_ref(),
            arch.as_ref(),
            path.as_ref(),
        ])
        .expect_success(&format!("read the {arch} slice of {}", path.display()));
        Self { raw: run.stderr }
    }

    /// The full report, for the occasional assertion with no accessor of its own.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The value of a `Key=value` line, e.g. `Identifier` or `Page size`.
    pub fn field(&self, key: &str) -> Option<&str> {
        self.raw.lines().find_map(|line| {
            let (name, value) = line.split_once('=')?;
            (name == key).then_some(value)
        })
    }

    /// The value of a `Key=value` line that must be present.
    fn required(&self, key: &str) -> &str {
        self.field(key)
            .unwrap_or_else(|| panic!("no `{key}` in the report:\n{}", self.raw))
    }

    /// What follows `prefix` on the line that starts with it.
    ///
    /// A few entries are not plain `Key=value`: `codesign` writes
    /// `Sealed Resources=none` for a bare executable but
    /// `Sealed Resources version=2 rules=13 files=0` for a bundle.
    fn after(&self, prefix: &str) -> &str {
        self.raw
            .lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("no `{prefix}` in the report:\n{}", self.raw))[prefix.len()..]
            .trim_start_matches(['=', ' '])
    }

    pub fn identifier(&self) -> &str {
        self.required("Identifier")
    }

    /// `Mach-O thin (arm64)` for an executable, `generic` for anything else.
    pub fn format(&self) -> &str {
        self.required("Format")
    }

    /// `adhoc` for an ad-hoc signature, otherwise the signer's name.
    pub fn signature(&self) -> &str {
        self.required("Signature")
    }

    /// Identifies the signed bytes: unchanged between two signings of identical
    /// input, so tests use it to tell "re-signed" from "left alone".
    pub fn cd_hash(&self) -> &str {
        self.required("CDHash")
    }

    /// `none` when nothing is sealed, `version=2 rules=13 files=0` for a bundle.
    pub fn sealed_resources(&self) -> &str {
        self.after("Sealed Resources")
    }

    /// `not bound` outside a bundle, `entries=5` for a bundle whose
    /// `Info.plist` the signature covers.
    pub fn info_plist(&self) -> &str {
        self.after("Info.plist")
    }

    pub fn runtime_version(&self) -> Option<&str> {
        self.field("Runtime Version")
    }

    /// The signing granularity in bytes (16384 unless asked otherwise), or
    /// `None` when the code was sealed as a single page (`Page size=none`).
    pub fn page_size(&self) -> Option<u32> {
        let size = self.required("Page size");
        (size != "none").then(|| {
            size.parse()
                .unwrap_or_else(|_| panic!("unparsable page size `{size}`"))
        })
    }

    pub fn has_self_launch_constraints(&self) -> bool {
        self.raw.contains("Has Self Launch Constraints")
    }

    /// The CodeDirectory line, which packs several values into one line:
    /// `CodeDirectory v=20400 size=382 flags=0x20002(adhoc,linker-signed) hashes=9+0 ...`
    fn code_directory(&self) -> &str {
        self.raw
            .lines()
            .find(|line| line.starts_with("CodeDirectory "))
            .unwrap_or_else(|| panic!("no CodeDirectory in the report:\n{}", self.raw))
    }

    /// The CodeDirectory option flags sealed into the signature — the same
    /// bitmask `signers::codesign::SigningFlags` mirrors, plus the bits
    /// `codesign` sets itself (`0x2` for an ad-hoc signature).
    pub fn flags(&self) -> u32 {
        let flags = token(self.code_directory(), "flags").expect("no flags in the CodeDirectory");
        let digits = flags
            .strip_prefix("0x")
            .unwrap_or_else(|| panic!("flags `{flags}` are not hexadecimal"));
        // `0x10202(adhoc,kill,runtime)`: the names that follow are not hex.
        let digits = digits.split_once('(').map_or(digits, |(digits, _)| digits);
        u32::from_str_radix(digits, 16).unwrap_or_else(|_| panic!("unparsable flags `{flags}`"))
    }

    /// The names `codesign` prints for the flags it sealed in, e.g.
    /// `["adhoc", "kill", "runtime"]`. Empty when no flags are set.
    pub fn flag_names(&self) -> Vec<&str> {
        let flags = token(self.code_directory(), "flags").expect("no flags in the CodeDirectory");
        let names = flags
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(names, _)| names)
            .unwrap_or_default();

        // A flagless CodeDirectory prints `flags=0x0(none)`.
        names
            .split(',')
            .filter(|n| !n.is_empty() && *n != "none")
            .collect()
    }

    /// How many code hashes the CodeDirectory holds (`hashes=9+2` → 9), i.e.
    /// how many pages the signed code was split into.
    pub fn code_hashes(&self) -> u32 {
        let hashes =
            token(self.code_directory(), "hashes").expect("no hashes in the CodeDirectory");
        let count = hashes.split_once('+').map_or(hashes, |(code, _)| code);
        count
            .parse()
            .unwrap_or_else(|_| panic!("unparsable hash count `{hashes}`"))
    }
}

/// The value of a whitespace-separated `key=value` token inside `line`.
fn token<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key)?.strip_prefix('='))
}
