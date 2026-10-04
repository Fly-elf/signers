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
    let output = Command::new("codesign")
        .args(args)
        .output()
        .expect("could not run `codesign`; it ships with macOS in /usr/bin, so check PATH");

    Run {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Whether `path` carries a signature.
pub fn is_signed(path: &Path) -> bool {
    reports_a_signature(codesign(&["-d".as_ref(), path.as_ref()]), path)
}

/// Whether one slice of a universal binary carries a signature.
///
/// Plain [`is_signed`] reports on the host's native architecture alone, so it
/// cannot see a signature left behind on another slice.
pub fn is_signed_arch(path: &Path, arch: &str) -> bool {
    let run = codesign(&[
        "-d".as_ref(),
        "--arch".as_ref(),
        arch.as_ref(),
        path.as_ref(),
    ]);
    reports_a_signature(run, path)
}

/// Whether one `version` of a versioned bundle carries a signature.
///
/// `codesign -d` reports on a single version at a time, which is what tells a
/// version-selective operation apart from a bundle-wide one.
pub fn is_signed_version(path: &Path, version: &str) -> bool {
    let run = codesign(&[
        "-d".as_ref(),
        "--bundle-version".as_ref(),
        version.as_ref(),
        path.as_ref(),
    ]);
    reports_a_signature(run, path)
}

/// Reads a `codesign -d` run as a yes/no, panicking rather than guessing if it
/// failed for some other reason (a missing or unreadable file).
fn reports_a_signature(run: Run, path: &Path) -> bool {
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
        Self {
            raw: run.stderr.trim().to_owned(),
        }
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
        Self {
            raw: run.stderr.trim().to_owned(),
        }
    }

    /// The full report without its surrounding whitespace, for the occasional assertion with no
    /// accessor of its own.
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

    /// `adhoc` for an ad hoc signature. A certificate signature has no such
    /// line: see [`authority`](Self::authority).
    pub fn signature(&self) -> &str {
        self.required("Signature")
    }

    /// The common name of the signing certificate, or `None` when signed ad hoc.
    pub fn authority(&self) -> Option<&str> {
        self.field("Authority")
    }

    /// When the timestamp server countersigned, or `None` without a timestamp.
    pub fn timestamp(&self) -> Option<&str> {
        self.field("Timestamp")
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

    /// Whether the signature carries a constraint of this kind.
    pub fn has_constraint(&self, constraint: Constraint) -> bool {
        let line = match constraint {
            Constraint::LaunchSelf => "Has Self Launch Constraints",
            Constraint::LaunchParent => "Has Parent Launch Constraints",
            Constraint::LaunchResponsible => "Has Responsible Launch Constraints",
            Constraint::Library => "Has Library Load Constraints",
        };
        self.raw.lines().any(|l| l.trim() == line)
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

/// The kinds of constraint a signature can carry, one per `Codesign<Sign>` setter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Constraint {
    LaunchSelf,
    LaunchParent,
    LaunchResponsible,
    Library,
}

impl Constraint {
    pub const ALL: [Self; 4] = [
        Self::LaunchSelf,
        Self::LaunchParent,
        Self::LaunchResponsible,
        Self::Library,
    ];
}

/// The names of the extended attributes on `path`, through the `xattr` tool.
pub fn xattrs(path: &Path) -> Vec<String> {
    let run = Command::new("xattr")
        .arg(path)
        .output()
        .unwrap_or_else(|e| panic!("could not run `xattr`: {e}"));
    assert!(
        run.status.success(),
        "could not list the xattrs of {}: {}",
        path.display(),
        String::from_utf8_lossy(&run.stderr).trim(),
    );
    String::from_utf8_lossy(&run.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The certificate chain embedded in `path`, as the DER files
/// `codesign -d --extract-certificates` writes: leaf first, empty for ad hoc.
pub fn certificates(path: &Path) -> Vec<Vec<u8>> {
    let dir = tempfile::TempDir::new().expect("could not create a temporary directory");
    let prefix = dir.path().join("cert");
    let mut flag = std::ffi::OsString::from("--extract-certificates=");
    flag.push(&prefix);
    codesign(&["-d".as_ref(), flag.as_ref(), path.as_ref()])
        .expect_success(&format!("extract the certificates of {}", path.display()));

    (0..)
        .map_while(|n| std::fs::read(dir.path().join(format!("cert{n}"))).ok())
        .collect()
}

/// `der` as PEM, exactly as the system `openssl` writes a certificate.
pub fn pem(der: &[u8]) -> String {
    openssl(&["x509", "-inform", "der", "-outform", "pem"], der)
}

/// The DER bytes of a single PEM certificate, through the system `openssl`.
pub fn der(pem: &str) -> Vec<u8> {
    openssl_run(
        &["x509", "-inform", "pem", "-outform", "der"],
        pem.as_bytes(),
    )
}

/// The subject and issuer `openssl` reads from a DER certificate.
pub fn subject_and_issuer(der: &[u8]) -> (String, String) {
    let text = openssl(
        &["x509", "-inform", "der", "-noout", "-subject", "-issuer"],
        der,
    );
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap_or_else(|| panic!("no `{key}` in openssl's output: {text}"))
            .trim()
            .to_owned()
    };
    (field("subject="), field("issuer="))
}

fn openssl(args: &[&str], input: &[u8]) -> String {
    String::from_utf8(openssl_run(args, input)).expect("openssl printed non-UTF-8 text")
}

/// Runs the system LibreSSL, so the result does not depend on which `openssl`
/// comes first on PATH, feeding `input` on stdin.
fn openssl_run(args: &[&str], input: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = Command::new("/usr/bin/openssl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("could not run /usr/bin/openssl");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input)
        .expect("could not feed openssl");
    let output = child
        .wait_with_output()
        .expect("could not wait for openssl");
    assert!(
        output.status.success(),
        "openssl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim(),
    );
    output.stdout
}

/// The value of a whitespace-separated `key=value` token inside `line`.
fn token<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key)?.strip_prefix('='))
}
