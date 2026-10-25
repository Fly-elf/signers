use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use crate::codesign::CodesignError;
use crate::codesign::action::action;
use crate::codesign::tool::Codesign;
use crate::codesign::types::parse_report;
use crate::codesign::{Signature, SignatureSlot};
use crate::engine::{Operation, PushArgs, Rejection, SharedRun};
use crate::errors::Output;

action! {
    /// Builder of a run that reads signatures, returned by [`display`](crate::codesign::display).
    ///
    /// Each setter maps to one `codesign` flag. A later call replaces an earlier one, `false`
    /// leaves the flag out, and an option you never set keeps `codesign`'s default.
    ///
    /// # Examples
    ///
    /// List the code nested in a bundle:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// let signature = codesign::display("MyApp.app").deep(true).await?;
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
    /// use signers::codesign::{self, Format};
    ///
    /// let signature = codesign::display("/bin/ls").architecture("arm64e").await?;
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
        /// doesn't have fails with [`ProcessError::Failed`](crate::ProcessError::Failed).
        architecture: Option<impl Into<String>>,
        /// Reads this version of a versioned bundle instead of `Current` (`--bundle-version`).
        ///
        /// A version the bundle doesn't have fails with [`ProcessError::Failed`](crate::ProcessError::Failed).
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
        ///
        /// Needs macOS 27 or later; older `codesign` rejects the option and the run fails.
        signature_slot: Option<SignatureSlot>,
    }
}

impl<S, R> SharedRun for Display<S, R> {}

impl Operation for Options {
    type Tool = Codesign;
    type Output = Signature;
    const BATCH: bool = true;

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
    fn output(&self, targets: &[PathBuf], output: &Output) -> Result<Vec<Signature>, Rejection> {
        let reports = reports(&output.stderr);
        if reports.len() != targets.len() {
            return Err(Rejection::Unreadable(format!(
                "{} reports for {} targets",
                reports.len(),
                targets.len()
            )));
        }

        // `--signature-slot` past the last signature exits 0 and prints
        // `<path>: no signature` in place of the `Signature=` line.
        if reports.iter().any(|report| {
            !report.lines().any(|line| line.starts_with("Signature="))
                && report.lines().any(|line| line.ends_with(": no signature"))
        }) {
            return Err(Rejection::Error(
                CodesignError::NoSignature {
                    output: output.clone(),
                }
                .into(),
            ));
        }

        let mut signatures = reports
            .into_iter()
            .map(parse_report)
            .collect::<Result<Vec<_>, _>>()?;

        if let [signature] = signatures.as_mut_slice()
            && let Some(plist) = plist_start(&output.stdout)
        {
            let entitlements =
                plist::from_bytes(&output.stdout.as_bytes()[plist..]).map_err(|error| {
                    Rejection::Unreadable(format!("unreadable entitlements: {error}"))
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
#[path = "unit_tests/display.rs"]
mod tests;
