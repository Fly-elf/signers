//! The signing action and the types its options take (`--sign`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::codesign::action::sealed::{SharedRun, ToArgs};
use crate::codesign::action::{PushArgs, joined};
use crate::codesign::{Codesign, PreserveMetadata, SigningFlags, Timestamp};
use crate::target::Shape;

/// Options of the signing action: the `A` in `Codesign<Sign>`.
///
/// [`Codesign::sign`], [`Codesign::sign_adhoc`] and [`Codesign::sign_for_distribution`] create
/// it. You set its options with [the signing setters](Codesign#impl-Codesign%3CSign,+S%3E). An
/// option you never set keeps `codesign`'s default.
///
/// # Examples
///
/// Sign the nested code first, then the bundle that seals it. This replaces the deprecated
/// [`deep`](Codesign::deep):
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::Codesign;
///
/// let identity = "Developer ID Application: Jane Doe (A1B2C3D4E5)";
///
/// Codesign::sign_for_distribution("MyApp.app/Contents/Frameworks/Engine.framework", identity)
///     .await?;
/// Codesign::sign_for_distribution("MyApp.app", identity)
///     .entitlements("MyApp.entitlements")
///     .await?;
/// # Ok(()) }
/// ```
///
/// Leave the binary unchanged and write its signature to a separate file:
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::Codesign;
///
/// Codesign::sign_adhoc("mytool").detached("mytool.sig").await?;
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
    /// Options for `identity`, with everything else at `codesign`'s defaults.
    pub(crate) fn new(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            ..Self::default()
        }
    }

    /// Options for an ad hoc signature (identity `-`).
    pub(crate) fn adhoc() -> Self {
        Self::new("-")
    }

    /// Options for `identity`, with the hardened runtime and a timestamp on.
    pub(crate) fn for_distribution(identity: impl Into<String>) -> Self {
        Self {
            options: SigningFlags::RUNTIME,
            timestamp: Some(Timestamp::Enabled),
            ..Self::new(identity)
        }
    }
}

/// Signing options, for [`sign`](Codesign::sign) and its presets.
///
/// Each setter maps to one `codesign` flag. A later call replaces an earlier one, and `false`
/// leaves a flag out.
impl<S: Shape> Codesign<Sign, S> {
    /// Seals this identifier instead of deriving one from `Info.plist` or the file name
    /// (`--identifier`).
    ///
    /// Every target in the batch gets this identifier, and each program should have its own.
    pub fn identifier(mut self, identifier: impl Into<String>) -> Self {
        self.action.identifier = Some(identifier.into());
        self
    }

    /// Embeds internal requirements from a file, or from source prefixed with `=`
    /// (`--requirements`).
    ///
    /// The kinds of requirement you don't specify get `codesign`'s defaults. On the command line,
    /// `-` reads from standard input. Here `codesign` gets no input, so `-` makes `.await` fail with
    /// [`Error::StdioPath`](crate::Error::StdioPath) before anything runs.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::sign("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
    ///     .requirements("=designated => identifier \"com.example.myapp\" and anchor apple generic")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub fn requirements(mut self, requirements: impl Into<String>) -> Self {
        self.action.requirements = Some(requirements.into());
        self
    }

    /// Prefixes a derived identifier that contains no dot, e.g. with `com.example.` (`--prefix`).
    ///
    /// Include the trailing dot. It has no effect when you set
    /// [`identifier`](Codesign::identifier).
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.action.prefix = Some(prefix.into());
        self
    }

    /// Looks up the signing identity in this keychain only (`--keychain`).
    ///
    /// The keychain doesn't need to be on the search list, so a temporary one works. The
    /// certificate chain still comes from the search list only.
    pub fn keychain(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.keychain = Some(path.into());
        self
    }

    /// Embeds the entitlements in this plist (`--entitlements`).
    ///
    /// `codesign` leaves them out of libraries unless you also set
    /// [`force_library_entitlements`](Codesign::force_library_entitlements).
    pub fn entitlements(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.entitlements = Some(path.into());
        self
    }

    /// Embeds the entitlements in libraries too, not only in main executables
    /// (`--force-library-entitlements`).
    ///
    /// Without it, `codesign` signs a library with no entitlements and reports no error.
    pub fn force_library_entitlements(mut self, force_library_entitlements: bool) -> Self {
        self.action.force_library_entitlements = force_library_entitlements;
        self
    }

    /// Embeds the entitlements as DER as well as XML (`--generate-entitlement-der`).
    ///
    /// This has been the default since macOS 12.
    pub fn generate_entitlement_der(mut self, generate_entitlement_der: bool) -> Self {
        self.action.generate_entitlement_der = generate_entitlement_der;
        self
    }

    /// Sets the code signing flags to seal (`--options`).
    ///
    /// This replaces the whole set, including the one from
    /// [`sign_for_distribution`](Codesign::sign_for_distribution).
    pub fn options(mut self, options: SigningFlags) -> Self {
        self.action.options = options;
        self
    }

    /// Records this hardened runtime version instead of the SDK's (`--runtime-version`).
    ///
    /// Only takes effect with [`SigningFlags::RUNTIME`]. Without that flag, `codesign` ignores it.
    pub fn runtime_version(mut self, version: impl Into<String>) -> Self {
        self.action.runtime_version = Some(version.into());
        self
    }

    /// Embeds the launch constraint in this plist, on the executable itself
    /// (`--launch-constraint-self`).
    pub fn launch_constraint_self(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.launch_constraint_self = Some(path.into());
        self
    }

    /// Embeds the launch constraint in this plist, on the executable's parent process
    /// (`--launch-constraint-parent`).
    pub fn launch_constraint_parent(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.launch_constraint_parent = Some(path.into());
        self
    }

    /// Embeds the launch constraint in this plist, on the executable's responsible process
    /// (`--launch-constraint-responsible`).
    pub fn launch_constraint_responsible(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.launch_constraint_responsible = Some(path.into());
        self
    }

    /// Embeds the constraint in this plist on the libraries the executable may load
    /// (`--library-constraint`).
    ///
    /// System libraries are exempt.
    pub fn library_constraint(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.library_constraint = Some(path.into());
        self
    }

    /// Makes an invalid constraint fail the signing instead of only warning
    /// (`--enforce-constraint-validity`).
    ///
    /// By default `codesign` reports unknown keys and malformed constraints but signs anyway, so
    /// you can sign constraints meant for a newer macOS.
    ///
    /// <div class="warning">
    ///
    /// On macOS 27.0, `codesign` rejects every constraint when this is set, valid ones included,
    /// with "Failure serializing Lightweight code requirement".
    ///
    /// </div>
    pub fn enforce_constraint_validity(mut self, enforce_constraint_validity: bool) -> Self {
        self.action.enforce_constraint_validity = enforce_constraint_validity;
        self
    }

    /// Replaces an existing signature instead of failing (`--force`).
    ///
    /// Patching a binary breaks its signature but leaves it in place, so re-signing it needs
    /// `force`. Setting it on an unsigned target does no harm.
    pub fn force(mut self, force: bool) -> Self {
        self.action.force = force;
        self
    }

    /// Signs the nested code too, applying every option to it as well (`--deep`).
    ///
    /// Apple deprecated this for signing in macOS 13, because the options rarely suit the nested
    /// code. Instead, sign the nested code first and the bundle last, as in the [`Sign`] examples.
    #[deprecated(
        since = "0.1.0",
        note = "Apple deprecated --deep for signing as of macOS 13.0; \
                sign nested bundle content explicitly instead"
    )]
    pub fn deep(mut self, deep: bool) -> Self {
        self.action.deep = deep;
        self
    }

    /// Reuses parts of the signature being replaced (`--preserve-metadata`).
    ///
    /// Needs [`force`](Codesign::force), since without it there is no replacing. Values you set
    /// explicitly win over preserved ones. `codesign` ignores this option when the old signature
    /// came from the linker.
    pub fn preserve_metadata(mut self, metadata: PreserveMetadata) -> Self {
        self.action.preserve_metadata = metadata;
        self
    }

    /// Sets the signing page size in bytes, or `0` for a single page (`--pagesize`).
    ///
    /// Anything but a power of two or `0` makes `codesign` fail. Only the main executable is
    /// affected, not resources.
    pub fn page_size(mut self, page_size: u32) -> Self {
        self.action.page_size = Some(page_size);
        self
    }

    /// Sets whether to get a secure timestamp, and from where (`--timestamp`).
    ///
    /// If you don't set it, `codesign` decides on its own. The server is contacted during
    /// `.await`, and if it can't be reached the signing fails. Ad hoc signatures ignore this
    /// option.
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.action.timestamp = Some(timestamp);
        self
    }

    /// Signs this version of a versioned bundle instead of the current one (`--bundle-version`).
    ///
    /// `version` names a directory under the bundle's `Versions`, e.g. `"A"`.
    pub fn bundle_version(mut self, version: impl Into<String>) -> Self {
        self.action.bundle_version = Some(version.into());
        self
    }

    /// Removes extended attributes that block signing, such as resource forks
    /// (`--strip-disallowed-xattrs`).
    ///
    /// Without it, a target that carries one fails with "resource fork, Finder information, or
    /// similar detritus not allowed".
    pub fn strip_disallowed_xattrs(mut self, strip_disallowed_xattrs: bool) -> Self {
        self.action.strip_disallowed_xattrs = strip_disallowed_xattrs;
        self
    }

    /// Builds the resource seal on one thread (`--single-threaded-signing`).
    pub fn single_threaded_signing(mut self, single_threaded_signing: bool) -> Self {
        self.action.single_threaded_signing = single_threaded_signing;
        self
    }

    /// Runs the whole signing, identity and keychain access included, but writes nothing
    /// (`--dryrun`).
    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.action.dry_run = dry_run;
        self
    }

    /// Writes the signature to this file and leaves the target unchanged (`--detached`).
    ///
    /// Every target's signature goes to this one file, so with
    /// [`per_target(true)`](Codesign::per_target) `.await` fails with
    /// [`Error::SharedOutputPerTarget`](crate::Error::SharedOutputPerTarget).
    pub fn detached(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.detached = Some(path.into());
        self
    }

    /// Writes a detached signature to the system database (`--detached-database`).
    ///
    /// This needs root. Otherwise `codesign` fails with "cannot access a database" and leaves the
    /// target unchanged.
    pub fn detached_database(mut self, detached_database: bool) -> Self {
        self.action.detached_database = detached_database;
        self
    }

    /// Appends to this file the paths that signing may have changed, one per line
    /// (`--file-list`).
    ///
    /// Any file not listed is unchanged. A listed file may be unchanged too.
    ///
    /// On the command line, `-` means standard output. Here the crate captures that output, so
    /// `-` makes `.await` fail with [`Error::StdioPath`](crate::Error::StdioPath)
    /// before anything runs. With [`per_target(true)`](Codesign::per_target) it fails with
    /// [`Error::SharedOutputPerTarget`](crate::Error::SharedOutputPerTarget), since every process
    /// would append to the same file.
    pub fn file_list(mut self, path: impl Into<PathBuf>) -> Self {
        self.action.file_list = Some(path.into());
        self
    }
}

impl SharedRun for Sign {}

impl ToArgs for Sign {
    type Output = ();
    const PER_TARGET: bool = false;

    fn validate(&self) -> crate::errors::Result<()> {
        if self.file_list.as_deref() == Some(Path::new("-")) {
            return Err(crate::errors::Error::StdioPath("file_list"));
        }
        if self.requirements.as_deref() == Some("-") {
            return Err(crate::errors::Error::StdioPath("requirements"));
        }
        Ok(())
    }

    fn shared_output(&self) -> Option<&'static str> {
        if self.file_list.is_some() {
            Some("file_list")
        } else if self.detached.is_some() {
            Some("detached")
        } else {
            None
        }
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

    fn output(
        &self,
        targets: &[PathBuf],
        _stdout: String,
        _stderr: String,
    ) -> crate::errors::Result<Vec<()>> {
        Ok(vec![(); targets.len()])
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn os(strings: &[&str]) -> Vec<OsString> {
        strings.iter().map(OsString::from).collect()
    }

    /// Renders the arguments, taking ownership so assertions can compare them
    /// against plain `OsString`s.
    fn args_of<S>(builder: &Codesign<Sign, S>) -> Vec<OsString> {
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
    fn adhoc_signs_with_dash_identity() {
        assert_eq!(
            args_of(&Codesign::sign_adhoc("app")),
            os(&["--sign", "-", "--", "app"])
        );
    }

    #[test]
    fn for_distribution_enables_hardened_runtime_and_timestamp() {
        assert_eq!(
            args_of(&Codesign::sign_for_distribution("app", "Developer ID")),
            os(&[
                "--sign",
                "Developer ID",
                "--options",
                "runtime",
                "--timestamp",
                "--",
                "app",
            ])
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
    /// real binary in `tests/codesign_async/sign/signing_flags.rs`; here they only have to
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
            matches!(error, crate::errors::Error::StdioPath("file_list")),
            "got {error:?}"
        );
    }

    #[test]
    fn a_file_list_pointing_at_a_real_path_passes_validation() {
        let action = Codesign::sign("app", "-").file_list("signed.txt");
        assert!(action.action.validate().is_ok());
    }

    #[test]
    fn requirements_of_stdin_fail_validation() {
        let action = Codesign::sign("app", "-").requirements("-");
        let error = action.action.validate().unwrap_err();
        assert!(
            matches!(error, crate::errors::Error::StdioPath("requirements")),
            "got {error:?}"
        );
    }

    /// Only the exact value `-` reads standard input: source text, a path that
    /// merely starts or ends with a dash, and the empty string are all fine.
    #[test]
    fn requirements_other_than_a_lone_dash_pass_validation() {
        for value in ["=-", "= -", "-x", "--", "./-", "-/a.rqset", " -", "- ", ""] {
            let action = Codesign::sign("app", "-").requirements(value);
            assert!(action.action.validate().is_ok(), "{value:?}");
        }
    }

    /// `codesign` reads these `-` as a plain file name, so they are not refused.
    #[test]
    fn a_dash_in_any_other_option_passes_validation() {
        let action = Codesign::sign("app", "-")
            .entitlements("-")
            .detached("-")
            .keychain("-")
            .launch_constraint_self("-")
            .launch_constraint_parent("-")
            .launch_constraint_responsible("-")
            .library_constraint("-")
            .identifier("-")
            .prefix("-");
        assert!(action.action.validate().is_ok());
    }

    #[test]
    fn requirements_source_text_is_one_argument_after_the_flag() {
        let action = Codesign::sign("app", "-").requirements("=designated => anchor apple");
        assert_eq!(
            args_of(&action),
            os(&[
                "--sign",
                "-",
                "--requirements",
                "=designated => anchor apple",
                "--",
                "app"
            ])
        );
    }

    #[test]
    fn targets_come_last() {
        let action = Codesign::sign(vec!["a.app", "b.app"], "-").force(true);
        assert_eq!(
            args_of(&action),
            os(&["--sign", "-", "--force", "--", "a.app", "b.app"])
        );
    }

    #[test]
    fn the_output_is_one_unit_per_target_whatever_codesign_printed() {
        let action = Codesign::sign("app", "-").action;
        let targets = [PathBuf::from("a"), PathBuf::from("b"), PathBuf::from("c")];

        let silent: Vec<()> = action
            .output(&targets, String::new(), String::new())
            .unwrap();
        assert_eq!(silent.len(), 3);

        let noisy = action.output_bytes(&targets[..1], b"noise".to_vec(), vec![0xff, 0xfe]);
        assert_eq!(noisy.unwrap().len(), 1);

        let none = action.output(&[], "noise".into(), String::new());
        assert_eq!(none.unwrap().len(), 0);
    }

    /// Signing mutates its targets, so the batch stays one `codesign` process
    /// unless the caller asks otherwise.
    #[test]
    fn every_constructor_defaults_to_one_process_for_all_targets() {
        assert!(!Codesign::sign("app", "-").per_target);
        assert!(!Codesign::sign_adhoc(vec!["a.app", "b.app"]).per_target);
        assert!(!Codesign::sign_for_distribution(["a.app", "b.app"], "Developer ID").per_target);
    }

    #[test]
    fn per_target_keeps_the_last_value_and_renders_no_argument() {
        let action = Codesign::sign(vec!["app"], "-").per_target(true);
        assert!(action.per_target);
        assert_eq!(args_of(&action), os(&["--sign", "-", "--", "app"]));

        let action = action.per_target(false);
        assert!(!action.per_target);
        assert_eq!(args_of(&action), os(&["--sign", "-", "--", "app"]));
    }

    #[test]
    fn only_options_writing_one_shared_file_are_reported_as_shared_output() {
        let shared = |builder: Codesign<Sign>| builder.action.shared_output();

        assert_eq!(shared(Codesign::sign("app", "-")), None);
        assert_eq!(
            shared(Codesign::sign("app", "-").file_list("signed.txt")),
            Some("file_list")
        );
        assert_eq!(
            shared(Codesign::sign("app", "-").detached("app.sig")),
            Some("detached")
        );
        // The other options that take a path only read it.
        assert_eq!(
            shared(
                Codesign::sign("app", "-")
                    .entitlements("app.entitlements")
                    .keychain("build.keychain")
                    .detached_database(true)
                    .force(true)
            ),
            None
        );
    }

    #[test]
    fn the_file_list_is_the_shared_output_named_when_both_are_set() {
        for action in [
            Codesign::sign("app", "-")
                .file_list("signed.txt")
                .detached("app.sig"),
            Codesign::sign("app", "-")
                .detached("app.sig")
                .file_list("signed.txt"),
        ] {
            assert_eq!(action.action.shared_output(), Some("file_list"));
        }
    }

    /// `sign` has no exit code of its own to tell apart, so every one of them
    /// stays the generic failure, whatever it printed on standard output.
    #[test]
    fn a_failed_run_is_reported_with_its_code_and_diagnostics() {
        let action = Codesign::sign("app", "-").action;
        for code in [1, 2, 3] {
            match action.failure(
                code,
                "file modified: /x".into(),
                "app: no identity found".into(),
            ) {
                crate::errors::Error::Codesign(crate::errors::CodesignError::Failed {
                    code: reported,
                    stdout,
                    stderr,
                }) => {
                    assert_eq!(reported, code);
                    assert_eq!(stdout, "file modified: /x");
                    assert_eq!(stderr, "app: no identity found");
                }
                other => panic!("expected Failed, got {other:?}"),
            }
        }
    }
}
