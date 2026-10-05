use std::marker::PhantomData;
use std::path::PathBuf;

use crate::codesign::action::Action;
use crate::codesign::action::sealed::SharedRun;
use crate::codesign::{
    Display, ExtractCertificates, InternalRequirements, RemoveSignature, Sign, ValidateConstraint,
    Verify,
};
use crate::target::{self, IntoTargets, Multi, One};

pub trait Runtime {}

#[derive(Debug, Clone)]
pub struct Runner<A, S, R> {
    pub(super) targets: Vec<PathBuf>,
    pub(super) action: A,
    pub(super) per_target: bool,
    pub(super) shape: PhantomData<fn() -> (S, R)>,
}

#[cfg(feature = "blocking")]
impl<A, S, R> Runner<A, S, R> {
    pub(super) fn with_runtime<R2: Runtime>(self) -> Runner<A, S, R2> {
        Runner {
            targets: self.targets,
            action: self.action,
            per_target: self.per_target,
            shape: PhantomData,
        }
    }
}

pub(super) fn new<A: Action, T: IntoTargets, R: Runtime>(
    target: T,
    action: A,
) -> Runner<A, T::Shape, R> {
    Runner {
        targets: target.into_targets(),
        action,
        per_target: A::PER_TARGET && !<T::Shape as target::sealed::Shape>::SINGLE,
        shape: PhantomData,
    }
}

/// Constructors, one per action.
impl<R: Runtime> Runner<(), One, R> {
    /// Signs `target` with the identity that `identity` names (`--sign`).
    ///
    /// `identity` is `-` for an ad hoc signature (see [`sign_adhoc`](Codesign::sign_adhoc)).
    /// Otherwise it selects a certificate, with its private key, from the keychain search list:
    ///
    /// - the name of an identity preference;
    /// - part of the certificate's common name, matching only one certificate (an exact match
    ///   wins), case-sensitive;
    /// - the certificate's SHA-1 hash, as 40 hex digits.
    ///
    /// Signing an already signed target fails with "is already signed" unless you set
    /// [`force`](Codesign::force). A signature added by the linker doesn't need `force`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::sign("MyApp.app", "Apple Development: Jane Doe (A1B2C3D4E5)")
    ///     .force(true)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub fn sign<T: IntoTargets>(
        target: T,
        identity: impl Into<String>,
    ) -> Runner<Sign, T::Shape, R> {
        new(target, Sign::new(identity))
    }

    /// Signs `target` ad hoc, with no certificate (`--sign -`).
    ///
    /// An ad hoc signature names no signer. That suits local use, including re-signing patched
    /// binaries, but not distribution. It never gets a timestamp.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// // The patch broke the old signature; `force` replaces it.
    /// Codesign::sign_adhoc("patched.dylib").force(true).await?;
    /// # Ok(()) }
    /// ```
    pub fn sign_adhoc<T: IntoTargets>(target: T) -> Runner<Sign, T::Shape, R> {
        new(target, Sign::adhoc())
    }

    /// Signs `target` for notarization: hardened runtime and timestamp
    /// (`--options runtime --timestamp`).
    ///
    /// This is [`sign`](Codesign::sign) with `.options(SigningFlags::RUNTIME)` and
    /// `.timestamp(Timestamp::Enabled)` already set. Later setters override both.
    /// [`options`](Codesign::options) replaces the whole set, so keep `RUNTIME` in it.
    ///
    /// `.await` fetches the timestamp from Apple's server, so without network access the signing
    /// fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    /// use signers::codesign::SigningFlags;
    ///
    /// Codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
    ///     .entitlements("MyApp.entitlements")
    ///     .options(SigningFlags::RUNTIME | SigningFlags::LIBRARY)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    pub fn sign_for_distribution<T: IntoTargets>(
        target: T,
        identity: impl Into<String>,
    ) -> Runner<Sign, T::Shape, R> {
        new(target, Sign::for_distribution(identity))
    }

    /// Removes the signature from `target` (`--remove-signature`).
    ///
    /// On a bundle, `codesign` removes the main executable's signature and the resource seal. It
    /// leaves nested code signed and an empty `_CodeSignature` directory behind. It accepts
    /// unsigned targets, and files that aren't code, without changing them.
    ///
    /// You don't need to remove a signature before re-signing: [`sign`](Codesign::sign) with
    /// [`force`](Codesign::force) replaces it in one step.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::remove_signature(vec!["mytool", "libfoo.dylib"]).await?;
    /// # Ok(()) }
    /// ```
    pub fn remove_signature<T: IntoTargets>(target: T) -> Runner<RemoveSignature, T::Shape, R> {
        new(target, RemoveSignature::default())
    }

    /// Checks the signature of `target` (`--verify`), changing nothing.
    ///
    /// `.await` yields `()` per target when every one verifies. Without options it checks that
    /// the signature is intact and covers the code. Whether the system would run the code is a
    /// different question: verified code can still be refused by Gatekeeper.
    ///
    /// Given several targets, each is verified on its own by default, so one `.await` reports
    /// every target that failed, as [`Error::Batch`]. [`per_target(false)`](Codesign::per_target)
    /// runs one `codesign` instead, which stops at the first target it rejects.
    ///
    /// # Errors
    ///
    /// A target that doesn't verify fails with [`CodesignError::VerificationFailed`]: the
    /// signature is invalid or modified, the target is unsigned, or the requirement text doesn't
    /// compile. A valid signature that doesn't meet a requirement fails with
    /// [`CodesignError::RequirementUnsatisfied`]. The checks made before `codesign` starts are
    /// on [`Codesign`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::verify("MyApp.app").deep(true).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Tell a broken signature from a requirement that isn't met:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::{Codesign, CodesignError, Error};
    ///
    /// match Codesign::verify("mytool").test_requirement("anchor apple").await {
    ///     Ok(()) => println!("signed by Apple"),
    ///     Err(Error::Codesign(CodesignError::RequirementUnsatisfied { .. })) => {
    ///         println!("validly signed, but not by Apple");
    ///     }
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(()) }
    /// ```
    pub fn verify<T: IntoTargets>(target: T) -> Runner<Verify, T::Shape, R> {
        new(target, Verify::default())
    }

    /// Reads the signature of `target` as a [`Signature`] (`--display`),
    /// changing nothing.
    ///
    /// `.await` yields one [`Signature`] per target: identifier, signing
    /// flags, hashes, the certificate chain, entitlements and more.
    /// [`Signature::raw`](Signature::raw) and
    /// [`Signature::field`](Signature::field) reach whatever the typed fields don't.
    ///
    /// Given several targets, each is read on its own by default, so one `.await` reports every
    /// target that failed, as [`Error::Batch`]. The signatures of the targets that did read are
    /// dropped with it. [`per_target(false)`](Codesign::per_target) runs one `codesign` instead:
    /// it stops at the first target it rejects, and the entitlements of every target stay
    /// [`None`](Signature#structfield.entitlements).
    ///
    /// # Errors
    ///
    /// An unsigned target fails with [`CodesignError::Failed`], exit code 1. With one `codesign`
    /// over several targets, its `stderr` also holds the reports of the targets before the unsigned
    /// one. A [`signature_slot`](Codesign::signature_slot) the code has no signature in fails with
    /// [`CodesignError::NoSignature`]. A report or entitlements that can't be read fails with
    /// [`CodesignError::UnexpectedOutput`]. The checks made before `codesign` starts are on
    /// [`Codesign`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    /// use signers::codesign::SignatureKind;
    ///
    /// let signature = Codesign::display("MyApp.app").await?;
    /// if signature.signature == SignatureKind::AdHoc {
    ///     println!("{} is signed ad hoc", signature.identifier);
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// Read the entitlements of a binary:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let signature = Codesign::display("mytool").await?;
    /// let debuggable = signature
    ///     .entitlements
    ///     .as_ref()
    ///     .and_then(|entitlements| entitlements.get("com.apple.security.get-task-allow"))
    ///     .and_then(|value| value.as_boolean())
    ///     .unwrap_or(false);
    /// # let _ = debuggable;
    /// # Ok(()) }
    /// ```
    ///
    /// Read two binaries at once:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let [ls, cat] = Codesign::display(["/bin/ls", "/bin/cat"]).await?;
    /// println!("{} {}", ls.cd_hash, cat.cd_hash);
    /// # Ok(()) }
    /// ```
    pub fn display<T: IntoTargets>(target: T) -> Runner<Display, T::Shape, R> {
        new(target, Display::default())
    }

    /// Checks that each plist is a valid launch or library constraint (`--validate-constraint`).
    ///
    /// A constraint plist holds the bare constraint dictionary, such as
    /// `{ "team-identifier": "A1B2C3D4E5" }`. It is not the `ccat`/`comp`/`reqs` wrapper that
    /// [`display`](Codesign::display) reports, which is rejected. `.await` yields `()` per plist.
    ///
    /// Given several plists, each is checked on its own by default, so one `.await` reports every
    /// plist that failed, as [`Error::Batch`]. [`per_target(false)`](Codesign::per_target) runs one
    /// `codesign` instead. Then the first plist `codesign` can't read stops the run, and the
    /// plists after it go unchecked. The rejections of the plists before it can't be told apart:
    /// the whole run fails with one [`CodesignError::ConstraintInvalid`].
    ///
    /// # Errors
    ///
    /// A constraint with an unknown key or an empty one fails with
    /// [`CodesignError::ConstraintInvalid`]. A plist that is missing, or isn't a dictionary,
    /// fails with [`CodesignError::Failed`], exit code 1. The checks made before `codesign`
    /// starts are on [`Codesign`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// Codesign::validate_constraint("launch-constraint.plist").await?;
    /// # Ok(()) }
    /// ```
    ///
    /// Check several plists and list the invalid ones:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::{Codesign, Error};
    ///
    /// match Codesign::validate_constraint(vec!["launch.plist", "library.plist"]).await {
    ///     Ok(_) => {}
    ///     Err(Error::Batch(failures)) => {
    ///         for (path, error) in &failures {
    ///             eprintln!("{}: {error}", path.display());
    ///         }
    ///     }
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(()) }
    /// ```
    pub fn validate_constraint<T: IntoTargets>(
        plist: T,
    ) -> Runner<ValidateConstraint, T::Shape, R> {
        new(plist, ValidateConstraint)
    }

    /// Reads the certificate chain that signed `target`, leaf first (`--extract-certificates`).
    ///
    /// `.await` yields one `Vec` of [`Certificate`] per target,
    /// the signing certificate first and the root last. A target signed ad hoc has none, so its
    /// `Vec` is empty. [`save_to`](Codesign::save_to) also writes the chains to PEM files.
    ///
    /// Given several targets, each is read on its own, concurrently, and every one that failed is
    /// reported together as [`Error::Batch`]. One `codesign` over several targets would write
    /// every chain to the same files, so this action always runs one per target and has no
    /// [`per_target`](Codesign::per_target) setter:
    ///
    /// ```compile_fail,E0599
    /// signers::Codesign::extract_certificates(vec!["a"]).per_target(false);
    /// ```
    ///
    /// # Errors
    ///
    /// An unsigned target fails with [`CodesignError::Failed`], exit code 1. A file that can't be
    /// read or written fails with [`Error::Io`], also when the system's temporary directory can't
    /// be used. The checks made before `codesign` starts are on [`Codesign`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let chains = Codesign::extract_certificates(vec!["A.app", "B.app"]).await?;
    /// for chain in &chains {
    ///     println!("{} certificates", chain.len());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn extract_certificates<T: IntoTargets>(
        target: T,
    ) -> Runner<ExtractCertificates, T::Shape, R> {
        new(target, ExtractCertificates::default())
    }

    /// Reads the requirements of the signature of `target` (`--display -r-`).
    ///
    /// `.await` yields one `Vec` of [`Requirement`] per target, in the order `codesign` keeps the requirements, which
    /// is not the order given to [`requirements`](Codesign::requirements) when signing. A
    /// requirement the signature doesn't embed, but the system supplies, is marked
    /// [`implicit`](Requirement#structfield.implicit). The `Vec` is empty when
    /// `codesign` prints none. [`display`](Codesign::display) reports only how many
    /// requirements there are, in [`Signature::internal_requirements`](Signature#structfield.internal_requirements).
    ///
    /// Given several targets, each is read on its own, concurrently, and every one that failed is
    /// reported together as [`Error::Batch`]. `codesign` prints the requirements of all targets
    /// together, with nothing to tell which target a line belongs to, so this action always runs one
    /// per target and has no [`per_target`](Codesign::per_target) setter:
    ///
    /// ```compile_fail,E0599
    /// signers::Codesign::internal_requirements(vec!["a"]).per_target(false);
    /// ```
    ///
    /// # Errors
    ///
    /// An unsigned target fails with [`CodesignError::Failed`], exit code 1. A line that can't be
    /// read as a requirement fails with [`CodesignError::UnexpectedOutput`]. The checks made before
    /// `codesign` starts are on [`Codesign`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// for requirement in Codesign::internal_requirements("MyApp.app").await? {
    ///     println!("{:?}: {}", requirement.kind, requirement.expression);
    /// }
    /// # Ok(()) }
    /// ```
    pub fn internal_requirements<T: IntoTargets>(
        target: T,
    ) -> Runner<InternalRequirements, T::Shape, R> {
        new(target, InternalRequirements)
    }
}

/// Options for a `Vec`, slice or array of targets.
impl<A: Action + SharedRun, S: Multi, R: Runtime> Runner<A, S, R> {
    /// Runs one `codesign` per target, concurrently, instead of one for all of them.
    ///
    /// One process stops at the first target it rejects and reports that one only. Per target,
    /// every target runs, and the failures come together as [`Error::Batch`], in input order. At
    /// most [`available_parallelism`](std::thread::available_parallelism) processes run at a
    /// time. The default is `false` for [`sign`](Codesign::sign) and
    /// [`remove_signature`](Codesign::remove_signature), which change the targets in order, and
    /// `true` for [`verify`](Codesign::verify), [`display`](Codesign::display) and
    /// [`validate_constraint`](Codesign::validate_constraint), which only read them.
    ///
    /// Only a `Vec`, slice or array of targets has this setter, even with one element: that is
    /// the `S: Multi` bound. A single target always runs one `codesign`:
    ///
    /// ```compile_fail,E0599
    /// signers::Codesign::sign("a", "-").per_target(true);
    /// ```
    ///
    /// [`extract_certificates`](Codesign::extract_certificates) and
    /// [`internal_requirements`](Codesign::internal_requirements) have no such setter either: they
    /// always run one `codesign` per target.
    ///
    /// An option that writes one shared file, [`file_list`](Codesign::file_list) or
    /// [`detached`](Codesign::detached), makes `.await` fail with
    /// [`Error::SharedOutputPerTarget`].
    ///
    /// <div class="warning">
    ///
    /// The runs overlap in no fixed order. A bundle in the same batch as the code nested in it
    /// can be sealed before that code is signed, which leaves the bundle's signature invalid.
    /// Sign the nested code in an earlier run.
    ///
    /// </div>
    ///
    /// # Examples
    ///
    /// Sign each library on its own, and report every one that failed:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::{Codesign, Error};
    ///
    /// let libraries = vec!["liba.dylib", "libb.dylib", "libc.dylib"];
    /// match Codesign::sign_adhoc(libraries).force(true).per_target(true).await {
    ///     Ok(_) => {}
    ///     Err(Error::Batch(failures)) => {
    ///         for (path, error) in &failures {
    ///             eprintln!("{}: {error}", path.display());
    ///         }
    ///     }
    ///     Err(error) => return Err(error),
    /// }
    /// # Ok(()) }
    /// ```
    pub fn per_target(mut self, per_target: bool) -> Self {
        self.per_target = per_target;
        self
    }
}
