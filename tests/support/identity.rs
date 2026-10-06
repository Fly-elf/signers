//! A throwaway signing identity, for the `#[ignore]`d tests that need a real
//! signer rather than an ad hoc signature.
//!
//! The certificate is self-signed and untrusted, which `codesign` accepts for
//! signing. It lives in a keychain of its own that is never added to the
//! search list, so `codesign` only finds it through `--keychain`, and the
//! keychain is deleted when the identity is dropped.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use tempfile::TempDir;

const PASSWORD: &str = "signers";

pub struct Identity {
    name: String,
    keychain: PathBuf,
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

        let keychain = path("signers-test.keychain-db");
        let identity = Self {
            name,
            keychain,
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
        identity
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
        // Best effort: panicking in drop would abort a test already unwinding.
        let _ = Command::new("security")
            .arg("delete-keychain")
            .arg(&self.keychain)
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
