//! The signing action (`codesign --sign`).

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use bitflags::{Flags, bitflags};

use super::sealed::Sealed;
use crate::codesign::Codesign;

/// Options for the signing action (`codesign --sign`).
///
/// Built through [`Codesign::sign`] and its chained setters. Every option
/// defaults to `codesign`'s own default, so a builder with no setters applied
/// runs `codesign --sign <identity> <targets>`.
///
/// [`Default`] leaves the identity empty — it exists as the base the crate's
/// own constructors build on, filling the identity in.
#[derive(Debug, Clone, Default)]
pub struct Sign {
    identity: String,

    // Identity and requirements
    identifier: Option<String>,
    requirements: Option<String>,
    prefix: Option<String>,
    keychain: Option<PathBuf>,

    // Entitlements and security
    entitlements: Option<PathBuf>,
    force_library_entitlements: bool,
    generate_entitlement_der: bool,
    options: SigningFlags,
    runtime_version: Option<String>,
    launch_constraint_self: Option<PathBuf>,
    launch_constraint_parent: Option<PathBuf>,
    launch_constraint_responsible: Option<PathBuf>,
    library_constraint: Option<PathBuf>,
    enforce_constraint_validity: bool,

    // Signing behaviour
    force: bool,
    deep: bool,
    preserve_metadata: PreserveMetadata,
    page_size: Option<u32>,
    timestamp: Option<Timestamp>,
    bundle_version: Option<String>,
    strip_disallowed_xattrs: bool,
    single_threaded_signing: bool,
    dry_run: bool,

    // Output and collateral files
    detached: Option<PathBuf>,
    detached_database: bool,
    file_list: Option<PathBuf>,
}

impl Sign {
    /// Signing options for `identity`, everything else left at `codesign`'s
    /// defaults.
    pub(crate) fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            ..Self::default()
        }
    }
}

impl Codesign<Sign> {
    /// Explicit signing identifier, overriding the one derived from the
    /// target's `Info.plist` or filename (`--identifier`).
    pub fn identifier(mut self, identifier: impl Into<String>) -> Self {
        self.action.identifier = Some(identifier.into());
        self
    }

    /// Internal requirements to embed, as a path to a requirements file or a
    /// literal source string prefixed with `=` (`--requirements`).
    pub fn requirements(mut self, requirements: impl Into<String>) -> Self {
        self.action.requirements = Some(requirements.into());
        self
    }

    /// Prefix prepended to an implicitly derived identifier that contains no
    /// dot, e.g. `com.example.` (`--prefix`).
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.action.prefix = Some(prefix.into());
        self
    }

    /// Restrict the search for the signing identity to this keychain
    /// (`--keychain`).
    pub fn keychain(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.keychain = Some(path.into());
        self
    }

    /// Entitlements plist to embed in the signature (`--entitlements`).
    pub fn entitlements(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.entitlements = Some(path.into());
        self
    }

    /// Embed the entitlements in libraries too, not just in main executables
    /// (`--force-library-entitlements`).
    pub fn force_library_entitlements(mut self, force_library_entitlements: bool) -> Self {
        self.action.force_library_entitlements = force_library_entitlements;
        self
    }

    /// Embed the entitlements as both XML and DER
    /// (`--generate-entitlement-der`); already the default since macOS 12.
    pub fn generate_entitlement_der(mut self, generate_entitlement_der: bool) -> Self {
        self.action.generate_entitlement_der = generate_entitlement_der;
        self
    }

    /// CodeDirectory option flags to seal into the signature (`--options`),
    /// replacing any previously set flags.
    ///
    /// ```
    /// # use signers::codesign::{Codesign, SigningFlags};
    /// Codesign::sign("MyApp.app", "-").options(SigningFlags::RUNTIME | SigningFlags::KILL);
    /// ```
    pub fn options(mut self, options: SigningFlags) -> Self {
        self.action.options = options;
        self
    }

    /// Hardened-runtime version to store in the signature; only meaningful
    /// together with [`SigningFlags::RUNTIME`] (`--runtime-version`).
    pub fn runtime_version(mut self, version: impl Into<String>) -> Self {
        self.action.runtime_version = Some(version.into());
        self
    }

    /// Launch constraint plist for the executable itself
    /// (`--launch-constraint-self`).
    pub fn launch_constraint_self(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.launch_constraint_self = Some(path.into());
        self
    }

    /// Launch constraint plist for the executable's parent process
    /// (`--launch-constraint-parent`).
    pub fn launch_constraint_parent(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.launch_constraint_parent = Some(path.into());
        self
    }

    /// Launch constraint plist for the executable's responsible process
    /// (`--launch-constraint-responsible`).
    pub fn launch_constraint_responsible(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.launch_constraint_responsible = Some(path.into());
        self
    }

    /// Constraint plist restricting the libraries the executable may load
    /// (`--library-constraint`).
    pub fn library_constraint(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.library_constraint = Some(path.into());
        self
    }

    /// Require the supplied constraints to be structurally valid and to only
    /// use keys known to this macOS version (`--enforce-constraint-validity`).
    pub fn enforce_constraint_validity(mut self, enforce_constraint_validity: bool) -> Self {
        self.action.enforce_constraint_validity = enforce_constraint_validity;
        self
    }

    /// Replace an existing signature rather than failing when one is present
    /// (`--force`).
    pub fn force(mut self, force: bool) -> Self {
        self.action.force = force;
        self
    }

    /// Recursively sign nested code — frameworks, helpers, plug-ins (`--deep`).
    ///
    /// Deprecated by Apple for signing as of macOS 13: every option is applied
    /// to the nested content as well, which is rarely what you want.
    #[deprecated(
        since = "0.1.0",
        note = "Apple deprecated --deep for signing as of macOS 13.0; \
                sign nested bundle content explicitly instead"
    )]
    pub fn deep(mut self, deep: bool) -> Self {
        self.action.deep = deep;
        self
    }

    /// Metadata to reuse from the existing signature when re-signing
    /// (`--preserve-metadata`), replacing any previous selection.
    ///
    /// Requires [`force`](Codesign::force) to have any effect, and is ignored
    /// altogether when the previous signature is linker-signed.
    pub fn preserve_metadata(mut self, metadata: PreserveMetadata) -> Self {
        self.action.preserve_metadata = metadata;
        self
    }

    /// Granularity of code signing, in bytes (`--pagesize`).
    ///
    /// `codesign` requires a power of two; `0` signs the whole code as a single
    /// page. Applies to the main executable only.
    pub fn page_size(mut self, page_size: u32) -> Self {
        self.action.page_size = Some(page_size);
        self
    }

    /// Timestamp policy for the signature (`--timestamp`).
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.action.timestamp = Some(timestamp);
        self
    }

    /// Version to operate on inside a versioned bundle, i.e. a name under its
    /// `Versions` directory (`--bundle-version`).
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }

    /// Strip extended attributes that would otherwise break signing, such as
    /// `com.apple.FinderInfo` (`--strip-disallowed-xattrs`).
    pub fn strip_disallowed_xattrs(mut self, strip_disallowed_xattrs: bool) -> Self {
        self.action.strip_disallowed_xattrs = strip_disallowed_xattrs;
        self
    }

    /// Build the resource seal on a single thread (`--single-threaded-signing`).
    pub fn single_threaded_signing(mut self, single_threaded_signing: bool) -> Self {
        self.action.single_threaded_signing = single_threaded_signing;
        self
    }

    /// Perform every signing step, including the cryptographic ones, but
    /// discard the result instead of writing it (`--dryrun`).
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.action.dry_run = dry_run;
        self
    }

    /// Write the signature to this file instead of into the code, leaving the
    /// target untouched (`--detached`).
    pub fn detached(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.detached = Some(path.into());
        self
    }

    /// Write the detached signature into the system database
    /// (`--detached-database`); requires elevated privileges.
    pub fn detached_database(mut self, detached_database: bool) -> Self {
        self.action.detached_database = detached_database;
        self
    }

    /// Append the list of files touched by the signing operation to this path,
    /// or to standard output with `-` (`--file-list`).
    pub fn file_list(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.file_list = Some(path.into());
        self
    }
}

impl Sealed for Sign {
    fn args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();

        // `codesign` follows a verb-noun rule: options given before `--sign`
        // are silently ignored, so the operation always goes first.
        args.option("--sign", &self.identity);

        if let Some(identifier) = &self.identifier {
            args.option("--identifier", identifier);
        }
        if let Some(requirements) = &self.requirements {
            args.option("--requirements", requirements);
        }
        if let Some(prefix) = &self.prefix {
            args.option("--prefix", prefix);
        }
        if let Some(keychain) = &self.keychain {
            args.option("--keychain", keychain);
        }

        if let Some(entitlements) = &self.entitlements {
            args.option("--entitlements", entitlements);
        }
        if self.force_library_entitlements {
            args.flag("--force-library-entitlements");
        }
        if self.generate_entitlement_der {
            args.flag("--generate-entitlement-der");
        }
        if !self.options.is_empty() {
            args.flag("--options");
            args.built(joined(self.options));
        }
        if let Some(runtime_version) = &self.runtime_version {
            args.option("--runtime-version", runtime_version);
        }
        if let Some(path) = &self.launch_constraint_self {
            args.option("--launch-constraint-self", path);
        }
        if let Some(path) = &self.launch_constraint_parent {
            args.option("--launch-constraint-parent", path);
        }
        if let Some(path) = &self.launch_constraint_responsible {
            args.option("--launch-constraint-responsible", path);
        }
        if let Some(path) = &self.library_constraint {
            args.option("--library-constraint", path);
        }
        if self.enforce_constraint_validity {
            args.flag("--enforce-constraint-validity");
        }

        if self.force {
            args.flag("--force");
        }
        if self.deep {
            args.flag("--deep");
        }
        // `--preserve-metadata` and `--timestamp` take an optional value, so
        // getopt only accepts the `=` form for them.
        if !self.preserve_metadata.is_empty() {
            let list = joined(self.preserve_metadata);
            args.built(format!("--preserve-metadata={list}"));
        }
        if let Some(page_size) = self.page_size {
            args.flag("--pagesize");
            args.built(page_size.to_string());
        }
        match &self.timestamp {
            Some(Timestamp::Enabled) => args.flag("--timestamp"),
            Some(Timestamp::ServerUrl(url)) => args.built(format!("--timestamp={url}")),
            Some(Timestamp::Disabled) => args.flag("--timestamp=none"),
            None => {}
        }
        if let Some(bundle_version) = &self.bundle_version {
            args.option("--bundle-version", bundle_version);
        }
        if self.strip_disallowed_xattrs {
            args.flag("--strip-disallowed-xattrs");
        }
        if self.single_threaded_signing {
            args.flag("--single-threaded-signing");
        }
        if self.dry_run {
            args.flag("--dryrun");
        }

        if let Some(detached) = &self.detached {
            args.option("--detached", detached);
        }
        if self.detached_database {
            args.flag("--detached-database");
        }
        if let Some(file_list) = &self.file_list {
            args.option("--file-list", file_list);
        }

        args.targets(targets);
        args
    }
}

/// Argument-list vocabulary, so that each `codesign` option renders on one
/// line and the arguments that have to allocate stay visible as such.
trait PushArgs<'a> {
    /// A standalone argument known at compile time: a bare flag such as
    /// `--force`, or a whole `=`-form argument such as `--timestamp=none`.
    fn flag(&mut self, name: &'static str);

    /// A flag followed by its value, borrowed from the action for `'a`.
    fn option<V: AsRef<OsStr> + ?Sized>(&mut self, name: &'static str, value: &'a V);

    /// An argument that only exists once rendered — a joined token list, a
    /// number, an interpolated `=`-form option — and so must be owned.
    fn built(&mut self, value: impl Into<OsString>);

    /// The paths the action operates on, which `codesign` expects last.
    fn targets(&mut self, targets: &'a [PathBuf]);
}

impl<'a> PushArgs<'a> for Vec<Cow<'a, OsStr>> {
    fn flag(&mut self, name: &'static str) {
        self.push(Cow::Borrowed(OsStr::new(name)));
    }

    fn option<V: AsRef<OsStr> + ?Sized>(&mut self, name: &'static str, value: &'a V) {
        self.flag(name);
        self.push(Cow::Borrowed(value.as_ref()));
    }

    fn built(&mut self, value: impl Into<OsString>) {
        self.push(Cow::Owned(value.into()));
    }

    fn targets(&mut self, targets: &'a [PathBuf]) {
        self.extend(targets.iter().map(|t| Cow::Borrowed(t.as_os_str())));
    }
}

/// Comma-joins the tokens of the flags set in `flags`, in declaration order.
///
/// Tokens come from each flag's `#[bitflags(flag_name)]`, so they are declared
/// rather than derived. `bitflags`' own formatter can't be used here: it
/// separates with ` | `, while `codesign` wants a bare comma-separated list.
fn joined<F: Flags + Copy>(flags: F) -> String {
    let mut tokens = String::new();
    for flag in F::FLAGS.iter().filter(|flag| flags.contains(*flag.value())) {
        if !tokens.is_empty() {
            tokens.push(',');
        }
        tokens.push_str(flag.name());
    }
    tokens
}

/// Timestamp policy embedded in the signature (`--timestamp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Timestamp {
    /// `--timestamp` — request a trusted timestamp from Apple's default server.
    Enabled,
    /// `--timestamp=<url>` — request a timestamp from a specific server.
    ServerUrl(String),
    /// `--timestamp=none` — do not contact any timestamp server.
    Disabled,
}

bitflags! {
    /// CodeDirectory option flags sealed into the signature (`--options`).
    ///
    /// Values mirror `SecCodeSignatureFlags` from `Security/CSCommon.h`; names
    /// are the tokens `codesign` accepts.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub struct SigningFlags: u32 {
        /// Marks the code as able to host guest code.
        #[bitflags(flag_name = "host")]
        const HOST = 0x0001;
        /// Hints that the code prefers being denied access to resources over
        /// losing its identity.
        #[bitflags(flag_name = "hard")]
        const HARD = 0x0100;
        /// Kills the process as soon as it becomes dynamically invalid.
        #[bitflags(flag_name = "kill")]
        const KILL = 0x0200;
        /// Makes validation honour certificate expiration.
        #[bitflags(flag_name = "expires")]
        const EXPIRES = 0x0400;
        /// Enforces library validation: only system libraries or libraries
        /// sharing the same team identifier may be linked.
        #[bitflags(flag_name = "library")]
        const LIBRARY = 0x2000;
        /// Opts into the hardened runtime (required for notarization).
        #[bitflags(flag_name = "runtime")]
        const RUNTIME = 0x1_0000;
        /// Marks the signature as linker-generated: replaceable without
        /// `--force` and never preserved.
        #[bitflags(flag_name = "linker-signed")]
        const LINKER_SIGNED = 0x2_0000;
    }
}

bitflags! {
    /// Metadata to reuse from an existing signature when re-signing
    /// (`--preserve-metadata`). Names are the tokens `codesign` accepts.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub struct PreserveMetadata: u8 {
        /// Keep the existing signing identifier.
        #[bitflags(flag_name = "identifier")]
        const IDENTIFIER = 1 << 0;
        /// Keep the existing entitlements.
        #[bitflags(flag_name = "entitlements")]
        const ENTITLEMENTS = 1 << 1;
        /// Keep the existing internal requirements, as a whole.
        #[bitflags(flag_name = "requirements")]
        const REQUIREMENTS = 1 << 2;
        /// Keep the existing CodeDirectory option flags.
        #[bitflags(flag_name = "flags")]
        const FLAGS = 1 << 3;
        /// Keep the existing hardened-runtime version.
        #[bitflags(flag_name = "runtime")]
        const RUNTIME = 1 << 4;
        /// Keep the existing launch constraints. Ignored when any
        /// `launch_constraint_*` option is supplied.
        #[bitflags(flag_name = "launch-constraints")]
        const LAUNCH_CONSTRAINTS = 1 << 5;
        /// Keep the existing library load constraints. Ignored when
        /// [`library_constraint`](Codesign::library_constraint) is supplied.
        #[bitflags(flag_name = "library-constraints")]
        const LIBRARY_CONSTRAINTS = 1 << 6;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    /// Renders the arguments, taking ownership so assertions can compare them
    /// against plain `OsString`s.
    fn args_of(builder: &Codesign<Sign>) -> Vec<OsString> {
        builder
            .action
            .args(&builder.targets)
            .into_iter()
            .map(Cow::into_owned)
            .collect()
    }

    #[test]
    fn bare_action_only_signs() {
        assert_eq!(
            args_of(&Codesign::sign("app", "-")),
            os(&["--sign", "-", "app"])
        );
    }

    #[test]
    #[expect(deprecated, reason = "`--deep` is still rendered, deprecated or not")]
    fn scalar_setters_are_forwarded() {
        let action = Codesign::sign("app", "Developer ID")
            .identifier("com.example.app")
            .entitlements("app.entitlements")
            .force(true)
            .deep(true)
            .page_size(4096)
            .dry_run(true);
        assert_eq!(
            args_of(&action),
            os(&[
                "--sign",
                "Developer ID",
                "--identifier",
                "com.example.app",
                "--entitlements",
                "app.entitlements",
                "--force",
                "--deep",
                "--pagesize",
                "4096",
                "--dryrun",
                "app",
            ]),
        );
    }

    #[test]
    fn flag_tokens_match_the_codesign_spelling() {
        assert_eq!(
            joined(SigningFlags::all()),
            "host,hard,kill,expires,library,runtime,linker-signed"
        );
        assert_eq!(
            joined(PreserveMetadata::all()),
            "identifier,entitlements,requirements,flags,runtime,launch-constraints,library-constraints",
        );
    }

    #[test]
    fn flag_sets_render_in_declaration_order() {
        let action = Codesign::sign("app", "-")
            .options(SigningFlags::RUNTIME | SigningFlags::KILL)
            .preserve_metadata(PreserveMetadata::ENTITLEMENTS | PreserveMetadata::IDENTIFIER);
        assert_eq!(
            args_of(&action),
            os(&[
                "--sign",
                "-",
                "--options",
                "kill,runtime",
                "--preserve-metadata=identifier,entitlements",
                "app",
            ]),
        );
    }

    #[test]
    fn flag_sets_replace_rather_than_accumulate() {
        let action = Codesign::sign("app", "-")
            .options(SigningFlags::RUNTIME)
            .options(SigningFlags::LIBRARY);
        assert_eq!(
            args_of(&action),
            os(&["--sign", "-", "--options", "library", "app"])
        );
    }

    #[test]
    fn timestamp_variants() {
        let rendered = |timestamp| args_of(&Codesign::sign("app", "-").timestamp(timestamp));
        assert!(rendered(Timestamp::Enabled).contains(&OsString::from("--timestamp")));
        assert!(rendered(Timestamp::Disabled).contains(&OsString::from("--timestamp=none")));
        assert!(
            rendered(Timestamp::ServerUrl("http://ts.example".into()))
                .contains(&OsString::from("--timestamp=http://ts.example"))
        );
    }

    #[test]
    fn every_constraint_kind_is_emitted() {
        let action = Codesign::sign("app", "-")
            .library_constraint("library.plist")
            .launch_constraint_self("self.plist")
            .launch_constraint_parent("parent.plist")
            .launch_constraint_responsible("responsible.plist");
        assert_eq!(
            args_of(&action),
            os(&[
                "--sign",
                "-",
                "--launch-constraint-self",
                "self.plist",
                "--launch-constraint-parent",
                "parent.plist",
                "--launch-constraint-responsible",
                "responsible.plist",
                "--library-constraint",
                "library.plist",
                "app",
            ]),
        );
    }

    #[test]
    fn repeating_a_constraint_kind_keeps_the_last_path() {
        let action = Codesign::sign("app", "-")
            .launch_constraint_self("first.plist")
            .launch_constraint_self("third.plist");
        assert_eq!(
            args_of(&action),
            os(&[
                "--sign",
                "-",
                "--launch-constraint-self",
                "third.plist",
                "app"
            ]),
        );
    }

    #[test]
    fn targets_come_last() {
        let action = Codesign::sign(vec!["a.app", "b.app"], "-").force(true);
        assert_eq!(
            args_of(&action),
            os(&["--sign", "-", "--force", "a.app", "b.app"])
        );
    }
}
