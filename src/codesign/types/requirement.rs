use crate::errors::{CodesignError, Result};

/// A code requirement of a signature: what it is for, and the expression to satisfy.
///
/// [`internal_requirements`](crate::Codesign::internal_requirements) returns them.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// What the requirement is for.
    pub kind: RequirementKind,
    /// The requirement as source text, e.g. `identifier "com.apple.ls" and anchor apple`. It isn't
    /// parsed: pass it to [`test_requirement`](crate::Codesign::test_requirement), for instance.
    pub expression: String,
    /// `true` when the signature doesn't embed this requirement and `codesign` shows the system's
    /// default instead, such as the designated requirement of an ad hoc signature, which names the
    /// code's hashes.
    pub implicit: bool,
}

/// What a [`Requirement`] is for (`codesign`'s requirement types).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementKind {
    /// What the code must satisfy to be considered the same code, across versions (`designated`).
    Designated,
    /// What the code that hosts this one must satisfy (`host`).
    Host,
    /// What the code hosted by this one, its guests, must satisfy (`guest`).
    Guest,
    /// What the libraries this code loads must satisfy (`library`).
    Library,
    /// What the plug-ins this code loads must satisfy (`plugin`).
    Plugin,
    /// A kind this crate doesn't know, with the word `codesign` printed for it.
    Other(String),
}

impl Requirement {
    pub(crate) fn parse(line: &str) -> Result<Self> {
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
