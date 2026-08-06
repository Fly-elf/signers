//! The Mach-O fixture, and the throwaway workspace each test copies it into.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use tempfile::TempDir;

use super::inspect::codesign;

/// Absolute path of a file under `tests/fixtures/`.
pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// [`fixture`] as a `&str`, for building raw `codesign` argument lists.
pub fn fixture_str(name: &str) -> String {
    fixture(name)
        .into_os_string()
        .into_string()
        .expect("the fixture path is not valid UTF-8")
}

/// Compiles `tests/fixtures/hello.c` once per test binary, returning the
/// executable that every test works from.
///
/// The binary is built rather than checked in, so it always matches the
/// architecture the tests run on. Mind its starting state: on Apple Silicon the
/// linker *always* emits an ad-hoc, linker-signed signature, so this file
/// arrives already signed — [`Workspace`] exposes each starting state that
/// matters under its own name.
pub fn pristine_hello() -> &'static Path {
    static HELLO: OnceLock<PathBuf> = OnceLock::new();
    HELLO.get_or_init(|| compile_hello("hello", &[]))
}

/// The same fixture as a universal binary, or `None` on a toolchain that has
/// only one architecture's SDK installed.
///
/// Built on demand, since most tests have no use for a second slice.
pub fn pristine_universal_hello() -> Option<&'static Path> {
    static UNIVERSAL: OnceLock<Option<PathBuf>> = OnceLock::new();
    UNIVERSAL
        .get_or_init(|| {
            let args = ["-arch", "arm64", "-arch", "x86_64"];
            compile("hello-universal", &args).ok()
        })
        .as_deref()
}

fn compile_hello(name: &str, args: &[&str]) -> PathBuf {
    compile(name, args).unwrap_or_else(|why| panic!("{why}"))
}

fn compile(name: &str, args: &[&str]) -> Result<PathBuf, String> {
    // `CARGO_TARGET_TMPDIR` is cargo's scratch directory for integration tests,
    // so the fixture is cleaned up by `cargo clean` like any other build output.
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fixtures");
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("could not create {}: {e}", dir.display()));

    // Test binaries can run concurrently, so build under a private name and
    // move it into place: `rename` is atomic, leaving readers with either the
    // complete old file or the complete new one.
    let source = fixture("hello.c");
    let staged = dir.join(format!("{name}-{}", std::process::id()));
    let built = Command::new("cc")
        .args(args)
        .arg("-o")
        .arg(&staged)
        .arg(&source)
        .output()
        .unwrap_or_else(|e| {
            // Anyone who can build these tests has `cc`: on macOS `rustc` links
            // through it, so cargo could not have produced this binary without.
            panic!("could not run `cc` to build the test fixture: {e}")
        });
    if !built.status.success() {
        return Err(format!(
            "`cc{}` could not build {}: {}",
            args.iter().map(|a| format!(" {a}")).collect::<String>(),
            source.display(),
            String::from_utf8_lossy(&built.stderr).trim(),
        ));
    }

    let hello = dir.join(name);
    fs::rename(&staged, &hello).map_err(|e| format!("could not stage {}: {e}", hello.display()))?;
    Ok(hello)
}

/// Runs `path` and returns what it printed, proving a signed binary still
/// works — on Apple Silicon the kernel refuses to run a broken signature, so
/// this is a real end-to-end check.
pub fn output_of(path: &Path) -> String {
    let run = Command::new(path)
        .output()
        .unwrap_or_else(|e| panic!("could not run {}: {e}", path.display()));
    assert!(
        run.status.success(),
        "{} exited unsuccessfully ({}): {}",
        path.display(),
        run.status,
        String::from_utf8_lossy(&run.stderr).trim(),
    );
    String::from_utf8_lossy(&run.stdout).trim().to_string()
}

/// A throwaway directory holding one test's copies of the fixture.
///
/// Every test builds its own, so the suite runs in parallel and a test that
/// mangles a target cannot affect any other. The directory is removed when the
/// workspace is dropped, which means it has to outlive the paths taken from it.
pub struct Workspace {
    dir: TempDir,
}

impl Workspace {
    pub fn new() -> Self {
        Self {
            dir: TempDir::new().expect("could not create a temporary directory"),
        }
    }

    /// The workspace root.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// `<workspace>/<name>`, which need not exist.
    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.dir.path().join(name)
    }

    /// A copy of the fixture exactly as the linker produced it: on Apple
    /// Silicon an ad-hoc *linker-signed* binary, which `codesign` is willing to
    /// replace without `--force`.
    pub fn linker_signed(&self, name: impl AsRef<Path>) -> PathBuf {
        let target = self.join(name);
        fs::copy(pristine_hello(), &target)
            .unwrap_or_else(|e| panic!("could not copy the fixture to {}: {e}", target.display()));
        target
    }

    /// A copy carrying no signature at all.
    pub fn unsigned(&self, name: impl AsRef<Path>) -> PathBuf {
        let target = self.linker_signed(name);
        codesign(&["--remove-signature".as_ref(), target.as_ref()])
            .expect_success("strip the fixture's linker signature");
        target
    }

    /// An unsigned copy of the *universal* fixture, or `None` when this
    /// toolchain cannot build one.
    pub fn unsigned_universal(&self, name: impl AsRef<Path>) -> Option<PathBuf> {
        let source = pristine_universal_hello()?;
        let target = self.join(name);
        fs::copy(source, &target)
            .unwrap_or_else(|e| panic!("could not copy the fixture to {}: {e}", target.display()));
        codesign(&["--remove-signature".as_ref(), target.as_ref()])
            .expect_success("strip the fixture's linker signature");
        Some(target)
    }

    /// A copy carrying a real ad-hoc signature — the state in which `codesign`
    /// demands `--force` before it will sign again.
    pub fn adhoc_signed(&self, name: impl AsRef<Path>) -> PathBuf {
        self.presigned(name, &[])
    }

    /// A copy pre-signed ad-hoc by the `codesign` CLI with `args` (inserted
    /// before the target), for tests that need a specific starting signature.
    ///
    /// ```ignore
    /// let target = workspace.presigned("app", &["-i", "com.example.original"]);
    /// ```
    pub fn presigned(&self, name: impl AsRef<Path>, args: &[&str]) -> PathBuf {
        let target = self.unsigned(name);
        let mut argv: Vec<&OsStr> = vec!["--sign".as_ref(), "-".as_ref()];
        argv.extend(args.iter().map(OsStr::new));
        argv.push(target.as_ref());
        codesign(&argv).expect_success("pre-sign the fixture");
        target
    }

    /// A minimal unsigned `<name>.app` around the fixture, declaring
    /// `com.example.<name>` as its bundle identifier.
    pub fn app_bundle(&self, name: &str) -> PathBuf {
        let bundle = self.join(format!("{name}.app"));
        let executables = bundle.join("Contents/MacOS");
        fs::create_dir_all(&executables)
            .unwrap_or_else(|e| panic!("could not create {}: {e}", executables.display()));
        fs::copy(pristine_hello(), executables.join(name))
            .unwrap_or_else(|e| panic!("could not populate {}: {e}", bundle.display()));
        self.write(
            bundle.join("Contents/Info.plist"),
            &info_plist(name, &format!("com.example.{name}"), "APPL"),
        );
        bundle
    }

    /// A minimal unsigned `<name>.framework`, the *versioned* bundle layout —
    /// the only shape in which a version selector means anything.
    ///
    /// ```text
    /// <name>.framework/<name>      -> Versions/Current/<name>
    /// <name>.framework/Resources   -> Versions/Current/Resources
    /// <name>.framework/Versions/A/{<name>, Resources/Info.plist}
    /// <name>.framework/Versions/Current -> A
    /// ```
    pub fn framework(&self, name: &str) -> PathBuf {
        self.build_framework(self.path(), name, &["A"])
    }

    /// [`framework`](Self::framework) built under `parent` rather than at the
    /// workspace root, so a bundle can be planted inside another one's
    /// `Contents/Frameworks` — the shape in which nested code exists at all.
    ///
    /// Built in place because a framework is a tree of relative symlinks, which
    /// no ordinary recursive copy reproduces faithfully.
    pub fn framework_in(&self, parent: &Path, name: &str) -> PathBuf {
        self.build_framework(parent, name, &["A"])
    }

    /// [`framework`](Self::framework) carrying several versions, each with its
    /// own executable and `Info.plist`, `Current` pointing at the first.
    ///
    /// Every version is signed and stripped independently, so this is what makes
    /// a version selector observable: with only one version, selecting it and
    /// selecting nothing do the same thing.
    pub fn versioned_framework(&self, name: &str, versions: &[&str]) -> PathBuf {
        self.build_framework(self.path(), name, versions)
    }

    fn build_framework(&self, parent: &Path, name: &str, versions: &[&str]) -> PathBuf {
        let (current, _) = versions
            .split_first()
            .expect("a framework needs at least one version");
        let bundle = parent.join(format!("{name}.framework"));

        for version in versions {
            let version = bundle.join("Versions").join(version);
            fs::create_dir_all(version.join("Resources"))
                .unwrap_or_else(|e| panic!("could not create {}: {e}", version.display()));
            fs::copy(pristine_hello(), version.join(name))
                .unwrap_or_else(|e| panic!("could not populate {}: {e}", bundle.display()));
            self.write(
                version.join("Resources/Info.plist"),
                &info_plist(name, &format!("com.example.{name}"), "FMWK"),
            );
        }

        symlink(current, bundle.join("Versions/Current"));
        symlink(format!("Versions/Current/{name}"), bundle.join(name));
        symlink("Versions/Current/Resources", bundle.join("Resources"));
        bundle
    }

    /// Writes `contents` to `<workspace>/<name>`, returning the path.
    pub fn write(&self, name: impl AsRef<Path>, contents: &str) -> PathBuf {
        let path = self.join(name);
        fs::write(&path, contents)
            .unwrap_or_else(|e| panic!("could not write {}: {e}", path.display()));
        path
    }

    /// Creates the `<workspace>/<name>` directory, including any parents.
    pub fn dir(&self, name: impl AsRef<Path>) -> PathBuf {
        let path = self.join(name);
        fs::create_dir_all(&path)
            .unwrap_or_else(|e| panic!("could not create {}: {e}", path.display()));
        path
    }
}

impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

fn symlink(target: impl AsRef<Path>, link: PathBuf) {
    std::os::unix::fs::symlink(target, &link)
        .unwrap_or_else(|e| panic!("could not link {}: {e}", link.display()));
}

/// The smallest `Info.plist` `codesign` accepts for a bundle of the given
/// `CFBundlePackageType` (`APPL` for an app, `FMWK` for a framework).
fn info_plist(executable: &str, identifier: &str, package_type: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>{executable}</string>
	<key>CFBundleIdentifier</key>
	<string>{identifier}</string>
	<key>CFBundleName</key>
	<string>{executable}</string>
	<key>CFBundlePackageType</key>
	<string>{package_type}</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
</dict>
</plist>
"#
    )
}
