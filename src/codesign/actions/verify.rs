use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::action::action;
use crate::codesign::tool::Codesign;
use crate::codesign::{SignatureSlot, Strict};
use crate::engine::{Operation, PushArgs, SharedRun, Tool};
use crate::errors::{Change, CodesignError, Error, ResourceChange};

action! {
    /// Builder of a verification run, returned by [`verify`](crate::codesign::verify).
    ///
    /// Each setter maps to one `codesign` flag. A later call replaces an earlier one, `false`
    /// leaves the flag out, and an option you never set keeps `codesign`'s default.
    ///
    /// # Examples
    ///
    /// Check a bundle as strictly as possible, nested code included, and keep going to the end of the
    /// list:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Error;
    /// use signers::codesign::{self, Strict};
    ///
    /// let apps = vec!["A.app", "B.app"];
    /// match codesign::verify(apps).deep(true).strict(Strict::All).await {
    ///     Ok(_) => {}
    ///     Err(Error::Batch(failures)) => {
    ///         for (path, error) in &failures {
    ///             eprintln!("{}: {error}", path.display());
    ///         }
    ///     }
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// Check an unsigned file against the signature that was written for it separately:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// codesign::verify("mytool").detached("mytool.sig").await?;
    /// # Ok(()) }
    /// ```
    Verify => () {
        test_requirement: Option<TestRequirement>,
    }
    setters {
        /// Also verifies nested code on its own, not only through the bundle's seal (`--deep`).
        ///
        /// Without it, nested code is checked only against the hash the bundle sealed, so a byte
        /// changed inside a nested library can still pass.
        deep: bool,
        /// Applies stricter checks than the default (`--strict`).
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn run() -> signers::Result<()> {
        /// use signers::codesign::{self, Strict};
        ///
        /// // Reject a symbolic link that leaves the bundle.
        /// codesign::verify("MyApp.app").strict(Strict::Symlinks).await?;
        /// # Ok(()) }
        /// ```
        strict: Option<Strict>,
        /// Skips the bundle's resources (`--ignore-resources`).
        ///
        /// A bundle with corrupted or tampered resources passes, so weigh the result accordingly. On a
        /// large bundle it is much faster.
        ignore_resources: bool,
        /// Verifies only this slice of a universal binary, e.g. `arm64` or `x86_64`
        /// (`--architecture`).
        ///
        /// The default is every slice. A slice the binary doesn't have fails verification.
        architecture: Option<impl Into<String>>,
        /// Verifies this version of a versioned bundle instead of `Current` (`--bundle-version`).
        ///
        /// A version the bundle doesn't have fails verification.
        bundle_version: Option<impl Into<String>>,
        /// Also checks the code against its own designated requirement (`--verbose=1`).
        ///
        /// It also makes a failed verification list the altered files in
        /// [`VerificationFailed::resources`](CodesignError::VerificationFailed). Without it that list
        /// is always empty.
        check_designated_requirement: bool,
        /// Verifies this signature when the code carries two (`--signature-slot`).
        ///
        /// Without it `codesign` picks the slot itself. On code that carries only one signature,
        /// [`Second`](SignatureSlot::Second) can fail as [`CodesignError::VerificationFailed`].
        ///
        /// Needs macOS 27 or later; older `codesign` rejects the option and the run fails.
        signature_slot: Option<SignatureSlot>,
        /// Verifies an unsigned file against a detached signature written for it (`--detached`).
        detached: Option<impl Into<PathBuf>>,
        /// Forces an online check for a notarization ticket (`--check-notarization`).
        ///
        /// It contacts Apple's servers, so it needs network access. Don't rely on it to reject
        /// unnotarized code: `codesign` accepted an unnotarized ad hoc binary with it.
        check_notarization: bool,
    }
}

#[derive(Debug, Clone)]
enum TestRequirement {
    Text(String),
    File(PathBuf),
}

impl<S, R> Verify<S, R> {
    /// Requires the code to satisfy this requirement, written as text (`-R=`).
    ///
    /// A valid signature that doesn't satisfy it fails as
    /// [`CodesignError::RequirementUnsatisfied`], and text that doesn't compile as
    /// [`CodesignError::VerificationFailed`]. The text is never a file name, and `-` is not
    /// standard input.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// codesign::verify("MyApp.app")
    ///     .test_requirement("identifier \"com.example.myapp\" and anchor apple generic")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub fn test_requirement(mut self, requirement: impl Into<String>) -> Self {
        self.options.test_requirement = Some(TestRequirement::Text(requirement.into()));
        self
    }

    /// Requires the code to satisfy the requirement written in this file (`-R <path>`).
    ///
    /// Failures are the same as for [`test_requirement`](Self::test_requirement).
    /// It replaces any earlier requirement, text or file. A path of `-` would read standard input,
    /// so it makes `.await` fail with [`Error::StdioPath`] before anything runs.
    pub fn test_requirement_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.options.test_requirement = Some(TestRequirement::File(path.into()));
        self
    }
}

impl<S, R> SharedRun for Verify<S, R> {}

impl Operation for Options {
    type Tool = Codesign;
    type Output = ();
    const BATCH: bool = true;

    fn validate(&self) -> crate::errors::Result<()> {
        match &self.test_requirement {
            Some(TestRequirement::File(path)) if path.as_os_str() == "-" => {
                Err(Error::StdioPath("test_requirement_file"))
            }
            _ => Ok(()),
        }
    }

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();

        // `codesign` ignores options given before the operation.
        args.flag("--verify");

        if self.deep {
            args.flag("--deep");
        }
        match self.strict {
            Some(Strict::All) => args.flag("--strict"),
            Some(Strict::Symlinks) => args.flag("--strict=symlinks"),
            Some(Strict::Sideband) => args.flag("--strict=sideband"),
            None => {}
        }
        if self.ignore_resources {
            args.flag("--ignore-resources");
        }
        if let Some(architecture) = &self.architecture {
            args.option("--architecture", architecture);
        }
        if let Some(version) = &self.bundle_version {
            args.option("--bundle-version", version);
        }
        if self.check_designated_requirement {
            args.flag("--verbose=1");
        }
        match &self.test_requirement {
            // `-R` takes `=text` only in this single-argument form; a space would make it a file path.
            Some(TestRequirement::Text(text)) => args.built(format!("-R={text}")),
            Some(TestRequirement::File(path)) => args.option("-R", path),
            None => {}
        }
        if let Some(slot) = self.signature_slot {
            args.option("--signature-slot", slot.as_str());
        }
        if let Some(path) = &self.detached {
            args.option("--detached", path);
        }
        if self.check_notarization {
            args.flag("--check-notarization");
        }

        args.targets(targets);
        args
    }

    fn output(
        &self,
        targets: &[PathBuf],
        _stdout: String,
        _stderr: String,
    ) -> crate::errors::Result<Vec<()>> {
        Ok(vec![(); targets.len()])
    }

    fn failure(&self, code: i32, stdout: String, stderr: String) -> Error {
        match code {
            1 => {
                let resources = resource_changes(&stdout);
                CodesignError::VerificationFailed {
                    stdout,
                    stderr,
                    resources,
                }
                .into()
            }
            3 => CodesignError::RequirementUnsatisfied { stdout, stderr }.into(),
            _ => Codesign::failed(code, stdout, stderr),
        }
    }
}

/// Reads the `file added|modified|missing: <path>` lines `--verbose=1` prints, in order.
fn resource_changes(stdout: &str) -> Vec<ResourceChange> {
    const PREFIXES: [(&str, Change); 3] = [
        ("file added: ", Change::Added),
        ("file modified: ", Change::Modified),
        ("file missing: ", Change::Missing),
    ];
    stdout
        .lines()
        .filter_map(|line| {
            PREFIXES.iter().find_map(|&(prefix, change)| {
                line.strip_prefix(prefix).map(|rest| ResourceChange {
                    change,
                    path: PathBuf::from(rest),
                })
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "unit_tests/verify.rs"]
mod tests;
