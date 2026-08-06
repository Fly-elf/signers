//! The signing action (`codesign --sign`).

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use bitflags::{Flags, bitflags};

use super::actions::sealed::ToArgs;
use crate::codesign::Codesign;

/// The signing action, and the options it was configured with
/// (`codesign --sign`).
///
/// You never build one: [`Codesign::sign`] does, and it is the only way to get
/// one. What fills it in afterwards are the setters on
/// [`Codesign<Sign>`](Codesign#impl-Codesign%3CSign%3E) — one per `codesign`
/// signing flag, from [`identifier`](Codesign::identifier) through to
/// [`file_list`](Codesign::file_list).
///
/// Everything starts at `codesign`'s own default, so a builder with no setters
/// applied runs plain `codesign --sign <identity> <targets>`.
///
/// [`Default`] leaves the identity empty; it's just the base the constructor
/// builds on.
///
/// # Examples
///
/// Re-sign a patched binary ad-hoc. `-` is the ad-hoc identity, and
/// [`force`](Codesign::force) is what allows replacing the signature already
/// there — without it `codesign` refuses:
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::Codesign;
///
/// Codesign::sign("patched.dylib", "-").force(true).await?;
/// # Ok(()) }
/// ```
///
/// Re-sign, keeping what the old signature carried rather than rebuilding it
/// from scratch:
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::Codesign;
/// use signers::codesign::sign::PreserveMetadata;
///
/// Codesign::sign("patched.app", "-")
///     .force(true)
///     .preserve_metadata(PreserveMetadata::ENTITLEMENTS | PreserveMetadata::IDENTIFIER)
///     .await?;
/// # Ok(()) }
/// ```
///
/// Sign for distribution: a real identity, its entitlements, the hardened
/// runtime notarization requires, and a timestamp so the signature outlives the
/// certificate:
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::Codesign;
/// use signers::codesign::sign::{SigningFlags, Timestamp};
///
/// Codesign::sign("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
///     .entitlements("MyApp.entitlements")
///     .options(SigningFlags::RUNTIME)
///     .timestamp(Timestamp::Enabled)
///     .force(true)
///     .await?;
/// # Ok(()) }
/// ```
///
/// Sign several targets in one run. They share the options, and the targets are
/// all checked before any of them is signed — so a typo in the last path leaves
/// the first ones untouched rather than half-applied:
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::Codesign;
///
/// Codesign::sign(vec!["MyApp.app", "MyLib.dylib"], "-")
///     .force(true)
///     .await?;
/// # Ok(()) }
/// ```
///
/// Since nothing runs before the `.await`, an invocation can be assembled a
/// piece at a time:
///
/// ```no_run
/// # async fn run(hardened: bool) -> Result<(), signers::Error> {
/// use signers::Codesign;
/// use signers::codesign::sign::SigningFlags;
///
/// let mut signing = Codesign::sign("MyApp.app", "-").force(true);
/// if hardened {
///     signing = signing.options(SigningFlags::RUNTIME);
/// }
/// signing.await?;
/// # Ok(()) }
/// ```
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
    /// Signing identifier to use, instead of the one derived from the target's
    /// `Info.plist` or filename (`--identifier`).
    pub fn identifier(mut self, identifier: impl Into<String>) -> Self {
        self.action.identifier = Some(identifier.into());
        self
    }

    /// Internal requirements to embed: a path to a requirements file, or the
    /// source itself prefixed with `=` (`--requirements`).
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), signers::Error> {
    /// # use signers::Codesign;
    /// Codesign::sign("MyApp.app", "-")
    ///     .requirements("=designated => anchor apple")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub fn requirements(mut self, requirements: impl Into<String>) -> Self {
        self.action.requirements = Some(requirements.into());
        self
    }

    /// Prefix to complete a derived identifier that has no dot in it, e.g.
    /// `com.example.` (`--prefix`).
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.action.prefix = Some(prefix.into());
        self
    }

    /// Look for the signing identity in this keychain only (`--keychain`).
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

    /// CodeDirectory flags to seal into the signature (`--options`).
    ///
    /// It's the whole set at once: calling it again replaces the flags rather
    /// than adding to them.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), signers::Error> {
    /// use signers::Codesign;
    /// use signers::codesign::sign::SigningFlags;
    ///
    /// Codesign::sign("MyApp.app", "-")
    ///     .options(SigningFlags::RUNTIME | SigningFlags::KILL)
    ///     .await?;
    /// # Ok(()) }
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

    /// Metadata to carry over from the signature you're replacing
    /// (`--preserve-metadata`).
    ///
    /// Only does something alongside [`force`](Codesign::force) — there's
    /// nothing to carry over otherwise — and nothing at all if the old
    /// signature was linker-signed. Like [`options`](Codesign::options), it
    /// replaces the set rather than adding to it.
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), signers::Error> {
    /// use signers::Codesign;
    /// use signers::codesign::sign::PreserveMetadata;
    ///
    /// // Re-sign a patched binary, keeping the entitlements it already had.
    /// Codesign::sign("MyApp.app", "-")
    ///     .force(true)
    ///     .preserve_metadata(PreserveMetadata::ENTITLEMENTS)
    ///     .await?;
    /// # Ok(()) }
    /// ```
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

    /// Whether to timestamp the signature, and where from (`--timestamp`).
    ///
    /// A trusted timestamp is what keeps a signature valid after the signing
    /// certificate expires, so distribution builds want one.
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

    /// Append the list of files the signing touched to this path
    /// (`--file-list`).
    ///
    /// `codesign` also takes `-` here, meaning standard output, but this crate
    /// captures that and has nowhere to hand it to you — so `-` fails at
    /// `.await` with [`Error::FileListToStdout`](crate::Error::FileListToStdout)
    /// rather than dropping the list on the floor.
    pub fn file_list(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.file_list = Some(path.into());
        self
    }
}

impl ToArgs for Sign {
    fn validate(&self) -> crate::errors::Result<()> {
        if self.file_list.as_deref() == Some(Path::new("-")) {
            return Err(crate::errors::Error::FileListToStdout);
        }
        Ok(())
    }

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
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

    /// The paths the action operates on, which `codesign` expects last,
    /// introduced by the `--` end-of-options separator.
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
        // Without the separator, `codesign`'s getopt reads a target whose name
        // starts with `-` as options: `codesign --sign - -patched` fails with
        // "unknown architecture name", having parsed `-patched` as `-p -a ...`.
        self.flag("--");
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

/// The value the [`timestamp`](Codesign::timestamp) option takes
/// (`--timestamp`).
///
/// Not a bool, because leaving the option unset — `codesign`'s own default — is
/// a third thing, distinct from [`Disabled`](Timestamp::Disabled) explicitly
/// refusing to contact a server.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> Result<(), signers::Error> {
/// use signers::Codesign;
/// use signers::codesign::sign::Timestamp;
///
/// let identity = "Developer ID Application: Jane Doe (A1B2C3D4E5)";
///
/// // A trusted timestamp from Apple's own server — what distribution builds want.
/// Codesign::sign("MyApp.app", identity)
///     .timestamp(Timestamp::Enabled)
///     .await?;
///
/// // A specific timestamp authority instead of Apple's.
/// Codesign::sign("MyApp.app", identity)
///     .timestamp(Timestamp::ServerUrl("http://timestamp.example.com".into()))
///     .await?;
///
/// // No timestamp, explicitly — different from never calling `timestamp` at all.
/// Codesign::sign("MyApp.app", "-")
///     .timestamp(Timestamp::Disabled)
///     .await?;
/// # Ok(()) }
/// ```
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
    /// The value the [`options`](Codesign::options) option takes: the
    /// CodeDirectory flags to seal into the signature (`--options`).
    ///
    /// A set — combine the flags with `|`. Values mirror
    /// `SecCodeSignatureFlags` from `Security/CSCommon.h`; names are the tokens
    /// `codesign` accepts.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), signers::Error> {
    /// use signers::Codesign;
    /// use signers::codesign::sign::SigningFlags;
    ///
    /// // The hardened runtime, plus killing the process if it becomes
    /// // dynamically invalid at runtime.
    /// Codesign::sign("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
    ///     .options(SigningFlags::RUNTIME | SigningFlags::KILL)
    ///     .await?;
    /// # Ok(()) }
    /// ```
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
    /// The value the [`preserve_metadata`](Codesign::preserve_metadata) option
    /// takes: what to reuse from the signature being replaced
    /// (`--preserve-metadata`).
    ///
    /// A set — combine the flags with `|`. Names are the tokens `codesign`
    /// accepts.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), signers::Error> {
    /// use signers::Codesign;
    /// use signers::codesign::sign::PreserveMetadata;
    ///
    /// // Re-sign a patched binary, keeping its identifier and internal
    /// // requirements rather than deriving them again from scratch.
    /// Codesign::sign("patched.app", "-")
    ///     .force(true)
    ///     .preserve_metadata(PreserveMetadata::IDENTIFIER | PreserveMetadata::REQUIREMENTS)
    ///     .await?;
    /// # Ok(()) }
    /// ```
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
            .to_args(&builder.targets)
            .into_iter()
            .map(Cow::into_owned)
            .collect()
    }

    #[test]
    fn bare_action_only_signs() {
        assert_eq!(
            args_of(&Codesign::sign("app", "-")),
            os(&["--sign", "-", "--", "app"])
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
                "--",
                "app",
            ]),
        );
    }

    /// Every option this action can render, so that adding one without
    /// rendering it — or rendering it in the wrong form — fails here.
    ///
    /// The focused tests below explain individual behaviours; this one exists
    /// to be exhaustive, and covers the several options whose effect nothing
    /// can observe from outside (`--detached-database` needs root).
    #[test]
    #[expect(deprecated, reason = "`--deep` is still rendered, deprecated or not")]
    fn every_option_renders_exactly_once() {
        let action = Codesign::sign("app", "Developer ID")
            .identifier("com.example.app")
            .requirements("=designated => anchor apple")
            .prefix("com.example.")
            .keychain("build.keychain")
            .entitlements("app.entitlements")
            .force_library_entitlements(true)
            .generate_entitlement_der(true)
            .options(SigningFlags::RUNTIME)
            .runtime_version("13.1")
            .launch_constraint_self("self.plist")
            .launch_constraint_parent("parent.plist")
            .launch_constraint_responsible("responsible.plist")
            .library_constraint("library.plist")
            .enforce_constraint_validity(true)
            .force(true)
            .deep(true)
            .preserve_metadata(PreserveMetadata::FLAGS)
            .page_size(4096)
            .timestamp(Timestamp::ServerUrl("http://ts.example".into()))
            .bundle_version("A")
            .strip_disallowed_xattrs(true)
            .single_threaded_signing(true)
            .dry_run(true)
            .detached("app.sig")
            .detached_database(true)
            .file_list("signed.txt");

        assert_eq!(
            args_of(&action),
            os(&[
                "--sign",
                "Developer ID",
                "--identifier",
                "com.example.app",
                "--requirements",
                "=designated => anchor apple",
                "--prefix",
                "com.example.",
                "--keychain",
                "build.keychain",
                "--entitlements",
                "app.entitlements",
                "--force-library-entitlements",
                "--generate-entitlement-der",
                "--options",
                "runtime",
                "--runtime-version",
                "13.1",
                "--launch-constraint-self",
                "self.plist",
                "--launch-constraint-parent",
                "parent.plist",
                "--launch-constraint-responsible",
                "responsible.plist",
                "--library-constraint",
                "library.plist",
                "--enforce-constraint-validity",
                "--force",
                "--deep",
                "--preserve-metadata=flags",
                "--pagesize",
                "4096",
                "--timestamp=http://ts.example",
                "--bundle-version",
                "A",
                "--strip-disallowed-xattrs",
                "--single-threaded-signing",
                "--dryrun",
                "--detached",
                "app.sig",
                "--detached-database",
                "--file-list",
                "signed.txt",
                "--",
                "app",
            ]),
        );
    }

    /// That these are the tokens `codesign` *accepts* is settled against the
    /// real binary in `tests/codesign_async/sign.rs`; here they only have to
    /// stay comma-joined, in declaration order, with no separators of any kind.
    #[test]
    fn flag_tokens_are_joined_in_declaration_order() {
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
    fn empty_flag_sets_render_no_argument_at_all() {
        // Not `--options ""`, which `codesign` rejects: the option is dropped.
        let action = Codesign::sign("app", "-")
            .options(SigningFlags::empty())
            .preserve_metadata(PreserveMetadata::empty());
        assert_eq!(args_of(&action), os(&["--sign", "-", "--", "app"]));
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
                "--",
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
            os(&["--sign", "-", "--options", "library", "--", "app"])
        );
    }

    /// Each variant is a single argument: `--timestamp` takes its value only in
    /// the `=` form, so a stray `--timestamp none` would be read as a timestamp
    /// request followed by a target named `none`.
    #[test]
    fn timestamp_variants_each_render_as_one_argument() {
        let rendered = |timestamp| args_of(&Codesign::sign("app", "-").timestamp(timestamp));
        assert_eq!(
            rendered(Timestamp::Enabled),
            os(&["--sign", "-", "--timestamp", "--", "app"]),
        );
        assert_eq!(
            rendered(Timestamp::Disabled),
            os(&["--sign", "-", "--timestamp=none", "--", "app"]),
        );
        assert_eq!(
            rendered(Timestamp::ServerUrl("http://ts.example".into())),
            os(&["--sign", "-", "--timestamp=http://ts.example", "--", "app"]),
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
                "--",
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
                "--",
                "app"
            ]),
        );
    }

    #[test]
    fn a_file_list_of_stdout_fails_validation() {
        let action = Codesign::sign("app", "-").file_list("-");
        let error = action.action.validate().unwrap_err();
        assert!(
            matches!(error, crate::errors::Error::FileListToStdout),
            "got {error:?}"
        );
    }

    #[test]
    fn a_file_list_pointing_at_a_real_path_passes_validation() {
        let action = Codesign::sign("app", "-").file_list("signed.txt");
        assert!(action.action.validate().is_ok());
    }

    #[test]
    fn targets_come_last() {
        let action = Codesign::sign(vec!["a.app", "b.app"], "-").force(true);
        assert_eq!(
            args_of(&action),
            os(&["--sign", "-", "--force", "--", "a.app", "b.app"])
        );
    }
}
