//! The verification action and the types its options take (`--verify`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::codesign::Codesign;
use crate::errors::{CodesignError, Error};
use crate::target::Shape;

#[derive(Debug, Clone, Default)]
pub struct Verify {
    deep: bool,
    strict: Option<Strict>,
    ignore_resources: bool,
    architecture: Option<String>,
    bundle_version: Option<String>,
    check_designated_requirement: bool,
    test_requirement: Option<String>,
    detached: Option<PathBuf>,
    check_notarization: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strict {
    All,
    Symlinks,
    Sideband,
}

impl<S: Shape> Codesign<Verify, S> {
    pub fn deep(mut self, deep: bool) -> Self {
        self.action.deep = deep;
        self
    }

    pub fn strict(mut self, strict: Strict) -> Self {
        self.action.strict = Some(strict);
        self
    }

    pub fn ignore_resources(mut self, ignore_resources: bool) -> Self {
        self.action.ignore_resources = ignore_resources;
        self
    }

    pub fn architecture(mut self, architecture: impl Into<String>) -> Self {
        self.action.architecture = Some(architecture.into());
        self
    }

    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }

    pub fn check_designated_requirement(mut self, check: bool) -> Self {
        self.action.check_designated_requirement = check;
        self
    }

    pub fn test_requirement(mut self, requirement: impl Into<String>) -> Self {
        self.action.test_requirement = Some(requirement.into());
        self
    }

    pub fn detached(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.detached = Some(path.into());
        self
    }

    pub fn check_notarization(mut self, check: bool) -> Self {
        self.action.check_notarization = check;
        self
    }
}

impl ToArgs for Verify {
    type Output = ();
    const PER_TARGET: bool = true;

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
        if let Some(requirement) = &self.test_requirement {
            // `-R` takes `=text` only in this single-argument form; a space would make it a file path.
            args.built(format!("-R={requirement}"));
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
        _stdout: Vec<u8>,
        _stderr: Vec<u8>,
    ) -> crate::errors::Result<Vec<()>> {
        Ok(vec![(); targets.len()])
    }

    fn failure(&self, code: i32, stderr: String) -> Error {
        match code {
            1 => CodesignError::VerificationFailed { stderr },
            3 => CodesignError::RequirementUnsatisfied { stderr },
            _ => CodesignError::Failed { code, stderr },
        }
        .into()
    }
}
