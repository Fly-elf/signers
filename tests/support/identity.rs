//! A throwaway signing identity, for the `#[ignore]`d tests that need a real
//! signer rather than an ad hoc signature.
//!
//! The certificate is self-signed and untrusted, which `codesign` accepts for
//! signing. It lives in a keychain of its own, and the keychain is deleted
//! when the identity is dropped.
//!
//! On macOS 27 `codesign` finds the identity through `--keychain`. On macOS 26
//! it ignores `--keychain` and finds the identity only if its keychain is on
//! the user's search list. Only where a first signature fails is the keychain
//! added to the list, for the identity's lifetime; elsewhere the list is left
//! alone.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tempfile::TempDir;

const PASSWORD: &str = "signers";

pub struct Identity {
    name: String,
    keychain: PathBuf,
    on_search_list: bool,
    // Removed after `Drop::drop` has deleted the keychain inside it.
    dir: TempDir,
}

impl Identity {
    /// Generates a code-signing certificate valid for a day and imports it,
    /// with its key, into a fresh unlocked keychain.
    ///
    /// ```ignore
    /// let identity = Identity::new();
    /// sign(&target, identity.name()).keychain(identity.keychain()).await?;
    /// ```
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            "signers-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let dir = TempDir::new().expect("could not create a temporary directory");
        let path = |file: &str| dir.path().join(file);

        fs::write(
            path("cert.cnf"),
            format!(
                "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n\
                 [dn]\nCN = {name}\n\
                 [ext]\nbasicConstraints = critical, CA:false\n\
                 keyUsage = critical, digitalSignature\n\
                 extendedKeyUsage = critical, codeSigning\n"
            ),
        )
        .expect("could not write the certificate config");

        // The system LibreSSL, so the result does not depend on which `openssl`
        // comes first on PATH.
        run("/usr/bin/openssl", |c| {
            c.args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            ])
            .arg("-config")
            .arg(path("cert.cnf"))
            .arg("-keyout")
            .arg(path("key.pem"))
            .arg("-out")
            .arg(path("cert.pem"))
        });
        run("/usr/bin/openssl", |c| {
            c.args(["pkcs12", "-export", "-passout"])
                .arg(format!("pass:{PASSWORD}"))
                .arg("-inkey")
                .arg(path("key.pem"))
                .arg("-in")
                .arg(path("cert.pem"))
                .arg("-out")
                .arg(path("identity.p12"))
        });

        let keychain = path(search_list::FILE_NAME);
        let mut identity = Self {
            name,
            keychain,
            on_search_list: false,
            dir,
        };
        let keychain = identity.keychain.as_path();
        run("security", |c| {
            c.args(["create-keychain", "-p", PASSWORD]).arg(keychain)
        });
        run("security", |c| {
            c.args(["unlock-keychain", "-p", PASSWORD]).arg(keychain)
        });
        // No auto-lock, so a slow run cannot find the keychain locked halfway.
        run("security", |c| c.arg("set-keychain-settings").arg(keychain));
        run("security", |c| {
            c.arg("import")
                .arg(identity.dir.path().join("identity.p12"))
                .arg("-k")
                .arg(keychain)
                .args(["-P", PASSWORD, "-T", "/usr/bin/codesign"])
        });
        // Without this, the first use of the key raises a GUI access prompt.
        run("security", |c| {
            c.args([
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:,codesign:",
            ])
            .args(["-s", "-k", PASSWORD])
            .arg(keychain)
        });

        if !identity.sign_probe().status.success() {
            // Canonical, as `security list-keychains` prints it.
            identity.keychain =
                fs::canonicalize(&identity.keychain).expect("could not resolve the keychain path");
            identity.on_search_list = true;
            search_list::add(&identity.keychain);
            let probe = identity.sign_probe();
            assert!(
                probe.status.success(),
                "the test harness could not sign with its identity, even with the keychain \
                 on the search list: {}\n{}",
                String::from_utf8_lossy(&probe.stderr).trim(),
                identity.find_identity(),
            );
        }
        identity
    }

    /// Signs a scratch file with the identity, as the tests will.
    fn sign_probe(&self) -> Output {
        let probe = self.dir.path().join("probe");
        fs::write(&probe, "probe\n").expect("could not write the probe file");
        Command::new("/usr/bin/codesign")
            .args(["--sign", &self.name, "--force", "--keychain"])
            .arg(&self.keychain)
            .arg("--")
            .arg(&probe)
            .output()
            .expect("could not run `codesign`")
    }

    /// What `security` sees in the keychain, to explain a failed probe.
    fn find_identity(&self) -> String {
        Command::new("security")
            .args(["find-identity", "-p", "codesigning"])
            .arg(&self.keychain)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    }

    /// The certificate's common name, which `codesign --sign` accepts.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The keychain holding the identity, for `--keychain`.
    pub fn keychain(&self) -> &Path {
        &self.keychain
    }
}

impl Drop for Identity {
    fn drop(&mut self) {
        // `delete-keychain` may rewrite the search list too, so it waits for its turn.
        let guard = search_list::lock();
        if self.on_search_list {
            search_list::remove(&self.keychain, &guard);
        }
        // Best effort: panicking in drop would abort a test already unwinding.
        let _ = Command::new("security")
            .arg("delete-keychain")
            .arg(&self.keychain)
            .output();
    }
}

/// The user's keychain search list, which is per user, not per process: every
/// change rereads it and edits only this harness's own entries, one thread at
/// a time, so identities of parallel tests and other entries are kept.
mod search_list {
    use super::*;

    static LOCK: Mutex<()> = Mutex::new(());

    /// The file name of every throwaway keychain, to spot one left behind by a
    /// killed run.
    pub(super) const FILE_NAME: &str = "signers-test.keychain-db";

    pub(super) fn lock() -> MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn add(keychain: &Path) {
        let guard = lock();
        let mut list = read(&guard).expect("could not read the keychain search list");
        list.retain(|p| !is_stale(p));
        list.push(keychain.to_owned());
        write(&list, &guard);
    }

    /// Takes `keychain` off the list, with any throwaway keychain whose file
    /// is gone. Best effort, as it runs in `Drop`.
    pub(super) fn remove(keychain: &Path, guard: &MutexGuard<'_, ()>) {
        let Some(list) = read(guard) else { return };
        let kept: Vec<_> = list
            .iter()
            .filter(|p| *p != keychain && !is_stale(p))
            .cloned()
            .collect();
        if kept.len() != list.len() {
            write(&kept, guard);
        }
    }

    fn is_stale(path: &Path) -> bool {
        path.file_name().is_some_and(|n| n == FILE_NAME) && !path.exists()
    }

    fn read(_: &MutexGuard<'_, ()>) -> Option<Vec<PathBuf>> {
        let output = Command::new("security")
            .args(["list-keychains", "-d", "user"])
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        let list = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| line.trim().trim_matches('"'))
            .filter(|line| !line.is_empty())
            .map(PathBuf::from)
            .collect();
        Some(list)
    }

    fn write(list: &[PathBuf], _: &MutexGuard<'_, ()>) {
        let _ = Command::new("security")
            .args(["list-keychains", "-d", "user", "-s"])
            .args(list)
            .output();
    }
}

fn run(program: &str, configure: impl FnOnce(&mut Command) -> &mut Command) {
    let mut command = Command::new(program);
    configure(&mut command);
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("could not run `{program}`: {e}"));
    assert!(
        output.status.success(),
        "the test harness could not set up an identity ({command:?}): {}",
        String::from_utf8_lossy(&output.stderr).trim(),
    );
}
