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
            && !stdout.is_empty()
        {
            let entitlements =
                plist::from_bytes(&stdout).map_err(|error| CodesignError::UnexpectedOutput {
                    detail: format!("unreadable entitlements: {error}"),
                })?;
            signature.entitlements = Some(entitlements);
        }

        Ok(signatures)
    }
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
