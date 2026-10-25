use std::path::PathBuf;

use thiserror::Error;

use crate::errors::diagnostics;

/// What only `codesign` reports: a missing executable, and the verdicts of some actions.
///
/// Every other failure of its process is a [`ProcessError`] in [`Error::Process`].
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum CodesignError {
    /// No `codesign` was found on `PATH`.
    ///
    /// `codesign` ships with macOS in `/usr/bin`. This error usually means `PATH` leaves out
    /// `/usr/bin`, or the system isn't macOS.
    #[error(
        "`codesign` was not found on PATH; it ships with macOS in /usr/bin, \
         so check that PATH includes /usr/bin"
    )]
    NotFound,

    /// [`verify`](crate::codesign::verify) found the target's signature wanting.
    ///
    /// The signature is invalid or modified, the target is unsigned, or the requirement text of
    /// [`test_requirement`](crate::codesign::Verify::test_requirement) doesn't compile. `stderr`
    /// holds the diagnostics `codesign` printed on standard error and `stdout` what it printed on
    /// standard output, both trimmed. Only `stderr` is part of the message.
    ///
    /// `resources` names the sealed resources that were altered, in the order `codesign` printed
    /// them, which can differ from run to run. It is filled only with
    /// [`check_designated_requirement`](crate::codesign::Verify::check_designated_requirement), and
    /// stays empty when the damage is to nested code (see
    /// [`deep`](crate::codesign::Verify::deep)) or when nothing was altered. The message lists them
    /// after the diagnostics, as `(modified: /path; added: /path)`.
    #[error("verification failed: {}{}", diagnostics(.stderr), changes(.resources))]
    #[non_exhaustive]
    VerificationFailed {
        stdout: String,
        stderr: String,
        resources: Vec<ResourceChange>,
    },

    /// [`verify`](crate::codesign::verify) found a valid signature on code that doesn't meet
    /// the requirement it was given.
    ///
    /// That requirement is the text of
    /// [`test_requirement`](crate::codesign::Verify::test_requirement) or, with
    /// [`check_designated_requirement`](crate::codesign::Verify::check_designated_requirement), the
    /// code's own. `stderr` holds the diagnostics `codesign` printed on standard error and `stdout`
    /// what it printed on standard output, both trimmed. Only `stderr` is part of the message.
    #[error("validly signed, but the requirement isn't satisfied: {}", diagnostics(.stderr))]
    #[non_exhaustive]
    RequirementUnsatisfied { stdout: String, stderr: String },

    /// [`validate_constraint`](crate::codesign::validate_constraint) found a constraint that
    /// isn't valid.
    ///
    /// The plist has an unknown key or is empty. `stderr` holds the diagnostics `codesign`
    /// printed on standard error and `stdout` what it printed on standard output, both trimmed.
    /// Only `stderr` is part of the message.
    ///
    /// On macOS 27 `codesign` exits 0 and prints "Constraint validation failed" even for a valid
    /// plist, so the exit code says nothing here. A plist is rejected only when `codesign` also
    /// reports an error for it, and that report is what `stderr` keeps.
    #[error("invalid constraint: {}", diagnostics(.stderr))]
    #[non_exhaustive]
    ConstraintInvalid { stdout: String, stderr: String },

    /// [`display`](crate::codesign::display) found no signature in the
    /// [`signature_slot`](crate::codesign::Display::signature_slot) it was asked for.
    ///
    /// Code with one signature has nothing in the second slot. `codesign` exits 0 for it, and
    /// reports `no signature` in place of the signature, so this crate fails instead of returning
    /// one with nothing in it. Unsigned code is a different failure: [`ProcessError::Failed`].
    /// `stderr` and `stdout` hold what `codesign` printed on each stream during the whole run,
    /// trimmed, so with one run over several targets they also cover targets that read fine. Only
    /// `stderr` is part of the message.
    #[error("no signature: {}", diagnostics(.stderr))]
    #[non_exhaustive]
    NoSignature { stdout: String, stderr: String },
}

#[cfg(feature = "__test-constructors")]
impl CodesignError {
    #[doc(hidden)]
    pub fn verification_failed(
        stdout: String,
        stderr: String,
        resources: Vec<ResourceChange>,
    ) -> Self {
        Self::VerificationFailed {
            stdout,
            stderr,
            resources,
        }
    }

    #[doc(hidden)]
    pub fn requirement_unsatisfied(stdout: String, stderr: String) -> Self {
        Self::RequirementUnsatisfied { stdout, stderr }
    }

    #[doc(hidden)]
    pub fn constraint_invalid(stdout: String, stderr: String) -> Self {
        Self::ConstraintInvalid { stdout, stderr }
    }

    #[doc(hidden)]
    pub fn no_signature(stdout: String, stderr: String) -> Self {
        Self::NoSignature { stdout, stderr }
    }
}

/// A sealed resource that [`verify`](crate::codesign::verify) found altered.
///
/// It is found in [`CodesignError::VerificationFailed`].
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign::Change;
/// use signers::{CodesignError, Error, codesign};
///
/// let result = codesign::verify("MyApp.app").check_designated_requirement(true).await;
/// if let Err(Error::Codesign(CodesignError::VerificationFailed { resources, .. })) = result {
///     for resource in resources.iter().filter(|r| r.change == Change::Modified) {
///         println!("tampered: {}", resource.path.display());
///     }
/// }
/// # Ok(()) }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceChange {
    /// How the resource differs from what the signature sealed.
    pub change: Change,
    /// Absolute path, canonical: a temporary directory shows as `/private/var/...`.
    ///
    /// Read from `codesign`'s text output, so bytes that aren't valid UTF-8 become `U+FFFD`.
    pub path: PathBuf,
}

/// How a sealed resource differs from what the signature sealed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The bundle holds a file the signature doesn't cover.
    Added,
    /// The file's contents differ from what was sealed.
    Modified,
    /// A sealed file is gone.
    Missing,
}

impl Change {
    fn as_str(self) -> &'static str {
        match self {
            Change::Added => "added",
            Change::Modified => "modified",
            Change::Missing => "missing",
        }
    }
}

/// Renders `resources` as ` (modified: path; added: path)`, or nothing if there are none.
fn changes(resources: &[ResourceChange]) -> String {
    if resources.is_empty() {
        return String::new();
    }
    let list: Vec<String> = resources
        .iter()
        .map(|r| format!("{}: {}", r.change.as_str(), r.path.display()))
        .collect();
    format!(" ({})", list.join("; "))
}

#[cfg(test)]
#[path = "unit_tests/error.rs"]
mod tests;
