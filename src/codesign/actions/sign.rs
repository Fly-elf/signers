use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::codesign::action::action;
use crate::codesign::action::joined;
use crate::codesign::tool::Codesign;
use crate::codesign::{PreserveMetadata, SigningFlags, Timestamp};
use crate::engine::{Operation, PushArgs, Rejection, SharedRun};
use crate::errors::Output;

action! {
    /// Builder of a signing run, returned by [`sign`](crate::codesign::sign) and its presets.
    ///
    /// [`sign_adhoc`](crate::codesign::sign_adhoc) and
    /// [`sign_for_distribution`](crate::codesign::sign_for_distribution) are the presets. Each
    /// setter maps to one `codesign` flag. A later call replaces an earlier one, `false` leaves the
    /// flag out, and an option you never set keeps `codesign`'s default.
    ///
    /// # Examples
    ///
    /// Sign the nested code first, then the bundle that seals it. This replaces the deprecated
    /// [`deep`](Sign::deep):
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// let identity = "Developer ID Application: Jane Doe (A1B2C3D4E5)";
    ///
    /// codesign::sign_for_distribution("MyApp.app/Contents/Frameworks/Engine.framework", identity)
    ///     .await?;
    /// codesign::sign_for_distribution("MyApp.app", identity)
    ///     .entitlements("MyApp.entitlements")
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Leave the binary unchanged and write its signature to a separate file:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// codesign::sign_adhoc("mytool").detached("mytool.sig").await?;
    /// # Ok(()) }
    /// ```
    Sign => () {
        identity: String,
    }
    setters {
        // Identity and requirements
        /// Seals this identifier instead of deriving one from `Info.plist` or the file name
        /// (`--identifier`).
        ///
        /// Every target in the batch gets this identifier, and each program should have its own.
        identifier: Option<impl Into<String>>,
        /// Embeds internal requirements from a file, or from source prefixed with `=`
        /// (`--requirements`).
        ///
        /// The kinds of requirement you don't specify get `codesign`'s defaults. On the command line,
        /// `-` reads from standard input. Here `codesign` gets no input, so `-` makes `.await` fail
        /// with [`Error::StdioPath`](crate::Error::StdioPath) before anything runs.
        ///
        /// # Examples
        ///
        /// ```no_run
        /// # async fn run() -> signers::Result<()> {
        /// use signers::codesign;
        ///
        /// codesign::sign("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
        ///     .requirements("=designated => identifier \"com.example.myapp\" and anchor apple generic")
        ///     .await?;
        /// # Ok(()) }
        /// ```
        requirements: Option<impl Into<String>>,
        /// Prefixes a derived identifier that contains no dot, e.g. with `com.example.` (`--prefix`).
        ///
        /// Include the trailing dot. It has no effect when you set
        /// [`identifier`](Self::identifier).
        prefix: Option<impl Into<String>>,
        /// Looks up the signing identity in this keychain (`--keychain`).
        ///
        /// On macOS 27 or later it is the only keychain searched, so it needn't be on the
        /// search list and a temporary one works. On macOS 26 `codesign` ignores it for the
        /// lookup, and the keychain holding the identity must be on the search list. The
        /// certificate chain always comes from the search list.
        keychain: Option<impl Into<PathBuf>>,

        // Entitlements and security
        /// Embeds the entitlements in this plist (`--entitlements`).
        ///
        /// `codesign` leaves them out of libraries unless you also set
        /// [`force_library_entitlements`](Self::force_library_entitlements).
        entitlements: Option<impl Into<PathBuf>>,
        /// Embeds the entitlements in libraries too, not only in main executables
        /// (`--force-library-entitlements`).
        ///
        /// Without it, `codesign` signs a library with no entitlements and reports no error.
        force_library_entitlements: bool,
        /// Embeds the entitlements as DER as well as XML (`--generate-entitlement-der`).
        ///
        /// This has been the default since macOS 12.
        generate_entitlement_der: bool,
        /// Sets the code signing flags to seal (`--options`).
        ///
        /// This replaces the whole set, including the one from
        /// [`sign_for_distribution`](crate::codesign::sign_for_distribution). Bits without a name are
        /// ignored, so a set with only unnamed bits acts as an empty one.
        options: SigningFlags,
        /// Records this hardened runtime version instead of the SDK's (`--runtime-version`).
        ///
        /// Only takes effect with [`SigningFlags::RUNTIME`]. Without that flag, `codesign` ignores it.
        runtime_version: Option<impl Into<String>>,
        /// Embeds the launch constraint in this plist, on the executable itself
        /// (`--launch-constraint-self`).
        launch_constraint_self: Option<impl Into<PathBuf>>,
        /// Embeds the launch constraint in this plist, on the executable's parent process
        /// (`--launch-constraint-parent`).
        launch_constraint_parent: Option<impl Into<PathBuf>>,
        /// Embeds the launch constraint in this plist, on the executable's responsible process
        /// (`--launch-constraint-responsible`).
        launch_constraint_responsible: Option<impl Into<PathBuf>>,
        /// Embeds the constraint in this plist on the libraries the executable may load
        /// (`--library-constraint`).
        ///
        /// System libraries are exempt.
        library_constraint: Option<impl Into<PathBuf>>,
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
        enforce_constraint_validity: bool,

        // Signing behaviour
        /// Replaces an existing signature instead of failing (`--force`).
        ///
        /// Patching a binary breaks its signature but leaves it in place, so re-signing it needs
        /// `force`. Setting it on an unsigned target does no harm.
        force: bool,
        /// Signs the nested code too, applying every option to it as well (`--deep`).
        ///
        /// Apple deprecated this for signing in macOS 13, because the options rarely suit the nested
        /// code. Instead, sign the nested code first and the bundle last, as in the [`Sign`] examples.
        #[deprecated(
            since = "0.1.0",
            note = "Apple deprecated --deep for signing as of macOS 13.0; \
                    sign nested bundle content explicitly instead"
        )]
        deep: bool,
        /// Reuses parts of the signature being replaced (`--preserve-metadata`).
        ///
        /// Needs [`force`](Self::force), since without it there is no replacing.
        /// Values you set explicitly win over preserved ones. `codesign` ignores this option when the
        /// old signature came from the linker. Bits without a name are ignored, so a set with only
        /// unnamed bits acts as an empty one.
        preserve_metadata: PreserveMetadata,
        /// Sets the signing page size in bytes, or `0` for a single page (`--pagesize`).
        ///
        /// Anything but a power of two or `0` makes `codesign` fail. Only the main executable is
        /// affected, not resources.
        page_size: Option<u32>,
        /// Sets whether to get a secure timestamp, and from where (`--timestamp`).
        ///
        /// If you don't set it, `codesign` decides on its own. The server is contacted during
        /// `.await`, and if it can't be reached the signing fails. Ad hoc signatures ignore this
        /// option.
        timestamp: Option<Timestamp>,
        /// Signs this version of a versioned bundle instead of the current one (`--bundle-version`).
        ///
        /// The version names a directory under the bundle's `Versions`, e.g. `"A"`.
        bundle_version: Option<impl Into<String>>,
        /// Removes extended attributes that block signing, such as resource forks
        /// (`--strip-disallowed-xattrs`).
        ///
        /// Without it, a target that carries one fails with "resource fork, Finder information, or
        /// similar detritus not allowed".
        strip_disallowed_xattrs: bool,
        /// Builds the resource seal on one thread (`--single-threaded-signing`).
        single_threaded_signing: bool,
        /// Runs the whole signing, identity and keychain access included, but writes nothing
        /// (`--dryrun`).
        dry_run: bool,

        // Output and collateral files
        /// Writes the signature to this file and leaves the target unchanged (`--detached`).
        ///
        /// Every target's signature goes to this one file, so with
        /// [`per_target(true)`](Self::per_target) `.await` fails with
        /// [`Error::SharedOutputPerTarget`](crate::Error::SharedOutputPerTarget).
        detached: Option<impl Into<PathBuf>>,
        /// Writes a detached signature to the system database (`--detached-database`).
        ///
        /// This needs root. Otherwise `codesign` fails with "cannot access a database" and leaves the
        /// target unchanged.
        detached_database: bool,
        /// Appends to this file the paths that signing may have changed, one per line
        /// (`--file-list`).
        ///
        /// Any file not listed is unchanged. A listed file may be unchanged too.
        ///
        /// On the command line, `-` means standard output. Here the crate captures that output, so `-`
        /// makes `.await` fail with [`Error::StdioPath`](crate::Error::StdioPath) before anything runs.
        /// With [`per_target(true)`](Self::per_target) it fails with
        /// [`Error::SharedOutputPerTarget`](crate::Error::SharedOutputPerTarget), since every process
        /// would append to the same file.
        file_list: Option<impl Into<PathBuf>>,
    }
}

impl Options {
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

impl<S, R> SharedRun for Sign<S, R> {}

impl Operation for Options {
    type Tool = Codesign;
    type Output = ();
    const BATCH: bool = false;

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
        if let Some(list) = joined(self.options) {
            args.flag("--options");
            args.built(list);
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
        if let Some(list) = joined(self.preserve_metadata) {
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

    fn output(&self, targets: &[PathBuf], _: &Output) -> Result<Vec<()>, Rejection> {
        Ok(vec![(); targets.len()])
    }
}

#[cfg(test)]
#[path = "unit_tests/sign.rs"]
mod tests;
