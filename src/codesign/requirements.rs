use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::errors::{CodesignError, Result};

#[derive(Debug, Clone, Default)]
pub struct Requirements;

impl ToArgs for Requirements {
    type Output = Vec<Requirement>;
    const PER_TARGET: bool = true;

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();
        args.flag("--display");
        args.flag("-r-");
        args.targets(targets);
        args
    }

    // Constraint dump lines are tab-indented `[Tag]` lines, but the stream is
    // trimmed, which takes the tab off the first one.
    fn output(
        &self,
        _targets: &[PathBuf],
        stdout: String,
        _stderr: String,
    ) -> Result<Vec<Vec<Requirement>>> {
        let requirements = stdout
            .lines()
            .filter(|line| !line.starts_with(['\t', '[']) && !line.trim().is_empty())
            .map(Requirement::parse)
            .collect::<Result<Vec<_>>>()?;
        Ok(vec![requirements])
    }
}

/// A requirement embedded in a signature, as `codesign -r-` prints it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub kind: RequirementKind,
    pub expression: String,
    pub implicit: bool,
}

/// What a [`Requirement`] is for.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementKind {
    Designated,
    Host,
    Guest,
    Library,
    Plugin,
    Other(String),
}

impl Requirement {
    fn parse(line: &str) -> Result<Self> {
        let (line, implicit) = match line.strip_prefix("# ") {
            Some(rest) => (rest, true),
            None => (line, false),
        };
        let (kind, expression) =
            line.split_once(" => ")
                .ok_or_else(|| CodesignError::UnexpectedOutput {
                    detail: format!("unreadable requirement: {line}"),
                })?;
        let kind = match kind {
            "designated" => RequirementKind::Designated,
            "host" => RequirementKind::Host,
            "guest" => RequirementKind::Guest,
            "library" => RequirementKind::Library,
            "plugin" => RequirementKind::Plugin,
            other => RequirementKind::Other(other.to_owned()),
        };
        Ok(Self {
            kind,
            expression: expression.to_owned(),
            implicit,
        })
    }
}
