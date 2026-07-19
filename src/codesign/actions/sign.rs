//! The signing action (`codesign --sign`).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::PathBuf;

use super::Action;
use super::sealed::Sealed;
use crate::codesign::Codesign;

/// Timestamp policy embedded in the signature (`--timestamp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Timestamp {
    /// `--timestamp` — request a trusted timestamp from Apple's default server.
    Server,
    /// `--timestamp=<url>` — request a timestamp from a specific server.
    ServerUrl(String),
    /// `--timestamp=none` — do not contact any timestamp server.
    Disabled,
}

/// A CodeDirectory option flag (`--options`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SigningFlag {
    /// `runtime` — opt into the hardened runtime (required for notarization).
    Runtime,
    /// `library` — enforce library validation.
    Library,
    /// `kill` — kill the process if its signature ever becomes invalid.
    Kill,
    /// `hard` — refuse to load invalidly-signed pages into the process.
    Hard,
    /// `expires` — honour the signature's expiration.
    Expires,
    /// `restrict` — restrict what the signature permits (e.g. dyld environment).
    Restrict,
}

impl SigningFlag {
    fn token(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Library => "library",
            Self::Kill => "kill",
            Self::Hard => "hard",
            Self::Expires => "expires",
            Self::Restrict => "restrict",
        }
    }
}

/// Metadata to carry over from an existing signature when re-signing
/// (`--preserve-metadata`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Metadata {
    /// Keep the existing signing identifier.
    Identifier,
    /// Keep the existing entitlements.
    Entitlements,
    /// Keep the existing internal requirements.
    Requirements,
    /// Keep the existing option flags.
    Flags,
    /// Keep the existing hardened-runtime settings.
    Runtime,
}

impl Metadata {
    fn token(self) -> &'static str {
        match self {
            Self::Identifier => "identifier",
            Self::Entitlements => "entitlements",
            Self::Requirements => "requirements",
            Self::Flags => "flags",
            Self::Runtime => "runtime",
        }
    }
}

/// Digest (hash) algorithm sealed into the signature (`--digest-algorithm`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DigestAlgorithm {
    /// Legacy SHA-1 digest (compatibility with very old systems).
    Sha1,
    /// SHA-256 digest (the modern default).
    Sha256,
}

impl DigestAlgorithm {
    fn token(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }
}

/// Options for the signing action (`codesign --sign`).
///
/// Built through [`Codesign::sign`] and its chained setters; not constructible
/// directly.
#[derive(Debug, Clone)]
pub struct Sign {
    identity: String,
    force: bool,
    deep: bool,
    dry_run: bool,
    identifier: Option<String>,
    prefix: Option<String>,
    entitlements: Option<PathBuf>,
    requirements: Option<String>,
    keychain: Option<PathBuf>,
    runtime_version: Option<String>,
    timestamp: Option<Timestamp>,
    flags: BTreeSet<SigningFlag>,
    preserve_metadata: BTreeSet<Metadata>,
    digest_algorithms: BTreeSet<DigestAlgorithm>,
}

/// Defaults geared at re-signing patched binaries: ad-hoc identity (`-`),
/// replacing any existing signature, non-recursive, everything else unset.
impl Default for Sign {
    fn default() -> Self {
        Self {
            identity: String::from("-"),
            force: true,
            deep: false,
            dry_run: false,
            identifier: None,
            prefix: None,
            entitlements: None,
            requirements: None,
            keychain: None,
            runtime_version: None,
            timestamp: None,
            flags: BTreeSet::new(),
            preserve_metadata: BTreeSet::new(),
            digest_algorithms: BTreeSet::new(),
        }
    }
}

/// Comma-joins a set of tokens in its (deterministic) sorted order.
fn joined<T: Copy>(set: &BTreeSet<T>, token: fn(T) -> &'static str) -> String {
    set.iter().copied().map(token).collect::<Vec<_>>().join(",")
}

impl Sealed for Sign {
    fn args(&self, targets: &[PathBuf]) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();

        args.push("--sign".into());
        args.push(self.identity.as_str().into());

        if let Some(identifier) = &self.identifier {
            args.push("--identifier".into());
            args.push(identifier.into());
        }
        if let Some(prefix) = &self.prefix {
            args.push("--prefix".into());
            args.push(prefix.into());
        }
        if let Some(entitlements) = &self.entitlements {
            args.push("--entitlements".into());
            args.push(entitlements.as_os_str().to_os_string());
        }
        if let Some(requirements) = &self.requirements {
            args.push("--requirements".into());
            args.push(requirements.into());
        }
        if let Some(keychain) = &self.keychain {
            args.push("--keychain".into());
            args.push(keychain.as_os_str().to_os_string());
        }
        if let Some(runtime_version) = &self.runtime_version {
            args.push("--runtime-version".into());
            args.push(runtime_version.into());
        }
        if !self.flags.is_empty() {
            args.push("--options".into());
            args.push(joined(&self.flags, SigningFlag::token).into());
        }
        // `--preserve-metadata` / `--digest-algorithm` / `--timestamp` take an
        // optional argument, so getopt only accepts the `=` form.
        if !self.preserve_metadata.is_empty() {
            let list = joined(&self.preserve_metadata, Metadata::token);
            args.push(format!("--preserve-metadata={list}").into());
        }
        if !self.digest_algorithms.is_empty() {
            let list = joined(&self.digest_algorithms, DigestAlgorithm::token);
            args.push(format!("--digest-algorithm={list}").into());
        }
        match &self.timestamp {
            Some(Timestamp::Server) => args.push("--timestamp".into()),
            Some(Timestamp::ServerUrl(url)) => args.push(format!("--timestamp={url}").into()),
            Some(Timestamp::Disabled) => args.push("--timestamp=none".into()),
            None => {}
        }
        if self.force {
            args.push("--force".into());
        }
        if self.deep {
            args.push("--deep".into());
        }
        if self.dry_run {
            args.push("--dryrun".into());
        }

        args.extend(targets.iter().map(|t| t.as_os_str().to_os_string()));
        args
    }
}

impl Action for Sign {}

impl Codesign<Sign> {
    /// Signing identity: a keychain identity name/hash, or `-` for ad-hoc
    /// (the default).
    pub fn identity(mut self, identity: impl Into<String>) -> Self {
        self.action.identity = identity.into();
        self
    }

    /// Replace an existing signature rather than failing when one is present
    /// (default: `true`).
    pub fn force(mut self, force: bool) -> Self {
        self.action.force = force;
        self
    }

    /// Recursively sign nested code — frameworks, helpers, ... (default: `false`).
    pub fn deep(mut self, deep: bool) -> Self {
        self.action.deep = deep;
        self
    }

    /// Perform every step except writing the signature (`--dryrun`).
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.action.dry_run = dry_run;
        self
    }

    /// Explicit signing identifier, overriding the one inferred from the target
    /// (`--identifier`).
    pub fn identifier(mut self, identifier: impl Into<String>) -> Self {
        self.action.identifier = Some(identifier.into());
        self
    }

    /// Prefix used to form a signing identifier from the target's name
    /// (`--prefix`).
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.action.prefix = Some(prefix.into());
        self
    }

    /// Entitlements plist to embed in the signature (`--entitlements`).
    pub fn entitlements(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.entitlements = Some(path.into());
        self
    }

    /// Internal requirements, as a requirement string or `=file`/`@file`
    /// reference (`--requirements`).
    pub fn requirements(mut self, requirements: impl Into<String>) -> Self {
        self.action.requirements = Some(requirements.into());
        self
    }

    /// Keychain to search for the signing identity (`--keychain`).
    pub fn keychain(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.keychain = Some(path.into());
        self
    }

    /// Hardened-runtime version to target (`--runtime-version`).
    pub fn runtime_version(mut self, version: impl Into<String>) -> Self {
        self.action.runtime_version = Some(version.into());
        self
    }

    /// Timestamp policy for the signature (`--timestamp`).
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.action.timestamp = Some(timestamp);
        self
    }

    /// Add CodeDirectory option flags such as [`SigningFlag::Runtime`]
    /// (`--options`). Accumulates across calls.
    pub fn flags(mut self, flags: impl IntoIterator<Item = SigningFlag>) -> Self {
        self.action.flags.extend(flags);
        self
    }

    /// Metadata to preserve from an existing signature when re-signing
    /// (`--preserve-metadata`). Accumulates across calls.
    pub fn preserve_metadata(mut self, metadata: impl IntoIterator<Item = Metadata>) -> Self {
        self.action.preserve_metadata.extend(metadata);
        self
    }

    /// Digest algorithms to seal into the signature (`--digest-algorithm`).
    /// Accumulates across calls.
    pub fn digest_algorithms(
        mut self,
        algorithms: impl IntoIterator<Item = DigestAlgorithm>,
    ) -> Self {
        self.action.digest_algorithms.extend(algorithms);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(strs: &[&str]) -> Vec<OsString> {
        strs.iter().map(OsString::from).collect()
    }

    #[test]
    fn default_is_ad_hoc_and_forced() {
        let args = Sign::default().args(&[PathBuf::from("app")]);
        assert_eq!(args, os(&["--sign", "-", "--force", "app"]));
    }

    #[test]
    fn scalar_setters_are_forwarded() {
        let action = Codesign::sign("app")
            .identity("Developer ID")
            .force(false)
            .deep(true)
            .identifier("com.example.app")
            .entitlements("app.entitlements");
        assert_eq!(
            action.action.args(&action.targets),
            os(&[
                "--sign",
                "Developer ID",
                "--identifier",
                "com.example.app",
                "--entitlements",
                "app.entitlements",
                "--deep",
                "app",
            ]),
        );
    }

    #[test]
    fn set_options_use_equals_form_and_sorted_tokens() {
        let action = Codesign::sign("app")
            .force(false)
            .flags([SigningFlag::Library, SigningFlag::Runtime])
            .preserve_metadata([Metadata::Entitlements, Metadata::Identifier])
            .digest_algorithms([DigestAlgorithm::Sha256]);
        assert_eq!(
            action.action.args(&action.targets),
            os(&[
                "--sign",
                "-",
                "--options",
                "runtime,library",
                "--preserve-metadata=identifier,entitlements",
                "--digest-algorithm=sha256",
                "app",
            ]),
        );
    }

    #[test]
    fn timestamp_variants() {
        let base = || Codesign::sign("app").force(false);
        assert!(
            base()
                .timestamp(Timestamp::Server)
                .action
                .args(&[PathBuf::from("app")])
                .contains(&OsString::from("--timestamp"))
        );
        assert!(
            base()
                .timestamp(Timestamp::Disabled)
                .action
                .args(&[PathBuf::from("app")])
                .contains(&OsString::from("--timestamp=none"))
        );
        assert!(
            base()
                .timestamp(Timestamp::ServerUrl("http://ts.example".into()))
                .action
                .args(&[PathBuf::from("app")])
                .contains(&OsString::from("--timestamp=http://ts.example"))
        );
    }

    #[test]
    fn flags_accumulate_and_dedup() {
        let action = Codesign::sign("app")
            .force(false)
            .flags([SigningFlag::Runtime])
            .flags([SigningFlag::Runtime, SigningFlag::Kill]);
        assert_eq!(
            action.action.args(&action.targets),
            os(&["--sign", "-", "--options", "runtime,kill", "app"]),
        );
    }
}
