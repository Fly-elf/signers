use super::actions::sign;
use crate::codesign::{
    Display, ExtractCertificates, RemoveSignature, Requirements, Sign, ValidateConstraint, Verify,
};
use crate::target::IntoTargets;

/// Signs `target` with the identity that `identity` names (`--sign`).
///
/// `identity` is `-` for an ad hoc signature (see
/// [`sign_adhoc`](crate::codesign::sign_adhoc)). Otherwise it selects a certificate, with
/// its private key, from the keychain search list:
///
/// - the name of an identity preference;
/// - part of the certificate's common name, matching only one certificate (an exact match
///   wins), case-sensitive;
/// - the certificate's SHA-1 hash, as 40 hex digits.
///
/// Signing an already signed target fails with "is already signed" unless you set
/// [`force`](crate::codesign::Sign::force). A signature added by the linker doesn't need
/// `force`.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign;
///
/// codesign::sign("MyApp.app", "Apple Development: Jane Doe (A1B2C3D4E5)")
///     .force(true)
///     .await?;
/// # Ok(()) }
/// ```
pub fn sign<T: IntoTargets>(target: T, identity: impl Into<String>) -> Sign<T::Shape> {
    Sign::new(target, sign::Options::new(identity))
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
/// use signers::codesign;
///
/// // The patch broke the old signature; `force` replaces it.
/// codesign::sign_adhoc("patched.dylib").force(true).await?;
/// # Ok(()) }
/// ```
pub fn sign_adhoc<T: IntoTargets>(target: T) -> Sign<T::Shape> {
    Sign::new(target, sign::Options::adhoc())
}

/// Signs `target` for notarization: hardened runtime and timestamp
/// (`--options runtime --timestamp`).
///
/// This is [`sign`](crate::codesign::sign) with `.options(SigningFlags::RUNTIME)` and
/// `.timestamp(Timestamp::Enabled)` already set. Later setters override both.
/// [`options`](crate::codesign::Sign::options) replaces the whole set, so keep `RUNTIME` in it.
///
/// `.await` fetches the timestamp from Apple's server, so without network access the signing
/// fails.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign::{self, SigningFlags};
///
/// codesign::sign_for_distribution("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
///     .entitlements("MyApp.entitlements")
///     .options(SigningFlags::RUNTIME | SigningFlags::LIBRARY)
///     .await?;
/// # Ok(()) }
/// ```
pub fn sign_for_distribution<T: IntoTargets>(
    target: T,
    identity: impl Into<String>,
) -> Sign<T::Shape> {
    Sign::new(target, sign::Options::for_distribution(identity))
}

/// Checks the signature of `target` (`--verify`), changing nothing.
///
/// `.await` yields `()` per target when every one verifies. Without options it checks that
/// the signature is intact and covers the code. Whether the system would run the code is a
/// different question: verified code can still be refused by Gatekeeper.
///
/// Given several targets, each is verified on its own by default, so one `.await` reports every
/// target that failed, as [`Error::Batch`](crate::Error::Batch).
/// [`per_target(false)`](Verify::per_target) runs one `codesign` instead, which
/// stops at the first target it rejects.
///
/// # Errors
///
/// A target that doesn't verify fails with
/// [`CodesignError::VerificationFailed`](crate::CodesignError::VerificationFailed): the
/// signature is invalid or modified, the target is unsigned, or the requirement text doesn't
/// compile. A valid signature that doesn't meet a requirement fails with
/// [`CodesignError::RequirementUnsatisfied`](crate::CodesignError::RequirementUnsatisfied). The
/// checks made before `codesign` starts are listed in [`codesign`](crate::codesign#errors).
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign;
///
/// codesign::verify("MyApp.app").deep(true).await?;
/// # Ok(()) }
/// ```
///
/// Tell a broken signature from a requirement that isn't met:
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::{CodesignError, Error, codesign};
///
/// match codesign::verify("mytool").test_requirement("anchor apple").await {
///     Ok(()) => println!("signed by Apple"),
///     Err(Error::Codesign(CodesignError::RequirementUnsatisfied { .. })) => {
///         println!("validly signed, but not by Apple");
///     }
///     Err(error) => return Err(error),
/// }
/// # Ok(()) }
/// ```
pub fn verify<T: IntoTargets>(target: T) -> Verify<T::Shape> {
    Verify::new(target, Default::default())
}

/// Reads the signature of `target` as a [`Signature`](crate::codesign::Signature)
/// (`--display`), changing nothing.
///
/// `.await` yields one [`Signature`](crate::codesign::Signature) per target: identifier,
/// signing flags, hashes, the certificate chain, entitlements and more.
/// [`Signature::raw`](crate::codesign::Signature::raw) and
/// [`Signature::field`](crate::codesign::Signature::field) reach whatever the typed fields
/// don't.
///
/// Given several targets, each is read on its own by default, so one `.await` reports every
/// target that failed, as [`Error::Batch`](crate::Error::Batch). The signatures of the targets
/// that did read are dropped with it. [`per_target(false)`](Display::per_target)
/// runs one `codesign` instead: it stops at the first target it rejects, and the entitlements
/// of every target stay [`None`](crate::codesign::Signature#structfield.entitlements).
///
/// # Errors
///
/// An unsigned target fails with [`CodesignError::Failed`](crate::CodesignError::Failed), exit
/// code 1. With one `codesign` over several targets, its `stderr` also holds the reports of the
/// targets before the unsigned one. A [`signature_slot`](Display::signature_slot)
/// the code has no signature in fails with
/// [`CodesignError::NoSignature`](crate::CodesignError::NoSignature). A report or entitlements
/// that can't be read fails with
/// [`CodesignError::UnexpectedOutput`](crate::CodesignError::UnexpectedOutput). The checks made
/// before `codesign` starts are listed in [`codesign`](crate::codesign#errors).
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign::{self, SignatureKind};
///
/// let signature = codesign::display("MyApp.app").await?;
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
/// use signers::codesign;
///
/// let signature = codesign::display("mytool").await?;
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
/// use signers::codesign;
///
/// let [ls, cat] = codesign::display(["/bin/ls", "/bin/cat"]).await?;
/// println!("{} {}", ls.cd_hash, cat.cd_hash);
/// # Ok(()) }
/// ```
pub fn display<T: IntoTargets>(target: T) -> Display<T::Shape> {
    Display::new(target, Default::default())
}

/// Removes the signature from `target` (`--remove-signature`).
///
/// On a bundle, `codesign` removes the main executable's signature and the resource seal. It
/// leaves nested code signed and an empty `_CodeSignature` directory behind. It accepts
/// unsigned targets, and files that aren't code, without changing them.
///
/// You don't need to remove a signature before re-signing:
/// [`sign`](crate::codesign::sign) with [`force`](crate::codesign::Sign::force) replaces
/// it in one step.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign;
///
/// codesign::remove_signature(vec!["mytool", "libfoo.dylib"]).await?;
/// # Ok(()) }
/// ```
pub fn remove_signature<T: IntoTargets>(target: T) -> RemoveSignature<T::Shape> {
    RemoveSignature::new(target, Default::default())
}

/// Checks that each plist is a valid launch or library constraint (`--validate-constraint`).
///
/// A constraint plist holds the bare constraint dictionary, such as
/// `{ "team-identifier": "A1B2C3D4E5" }`. It is not the `ccat`/`comp`/`reqs` wrapper that
/// [`display`](crate::codesign::display) reports, which is rejected. `.await` yields `()`
/// per plist.
///
/// Given several plists, each is checked on its own by default, so one `.await` reports every
/// plist that failed, as [`Error::Batch`](crate::Error::Batch).
/// [`per_target(false)`](ValidateConstraint::per_target) runs one `codesign` instead. Then
/// the first plist `codesign` can't read stops the run, and the plists after it go unchecked.
/// The rejections of the plists before it can't be told apart: the whole run fails with one
/// [`CodesignError::ConstraintInvalid`](crate::CodesignError::ConstraintInvalid).
///
/// # Errors
///
/// A constraint with an unknown key or an empty one fails with
/// [`CodesignError::ConstraintInvalid`](crate::CodesignError::ConstraintInvalid). A plist that
/// is missing, or isn't a dictionary, fails with
/// [`CodesignError::Failed`](crate::CodesignError::Failed), exit code 1. The checks made before
/// `codesign` starts are listed in [`codesign`](crate::codesign#errors).
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign;
///
/// codesign::validate_constraint("launch-constraint.plist").await?;
/// # Ok(()) }
/// ```
///
/// Check several plists and list the invalid ones:
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::{Error, codesign};
///
/// match codesign::validate_constraint(vec!["launch.plist", "library.plist"]).await {
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
pub fn validate_constraint<T: IntoTargets>(plist: T) -> ValidateConstraint<T::Shape> {
    ValidateConstraint::new(plist, Default::default())
}

/// Reads the requirements of the signature of `target` (`--display -r-`).
///
/// `.await` yields one `Vec` of [`Requirement`](crate::codesign::Requirement) per target, in
/// the order `codesign` keeps the requirements, which is not the order given to
/// [`requirements`](crate::codesign::Sign::requirements) when signing. A requirement the
/// signature doesn't embed, but the system supplies, is marked
/// [`implicit`](crate::codesign::Requirement#structfield.implicit). The `Vec` is empty when
/// `codesign` prints none. [`display`](crate::codesign::display) reports only how many
/// requirements there are, in
/// [`Signature::internal_requirements`](crate::codesign::Signature#structfield.internal_requirements).
///
/// Given several targets, each is read on its own, concurrently, and every one that failed is
/// reported together as [`Error::Batch`](crate::Error::Batch). `codesign` prints the
/// requirements of all targets together, with nothing to tell which target a line belongs to,
/// so this action always runs one per target, and
/// [`per_target`](Requirements::per_target) can't be called on it:
///
/// ```compile_fail,E0277
/// signers::codesign::requirements(vec!["a"]).per_target(false);
/// ```
///
/// # Errors
///
/// An unsigned target fails with [`CodesignError::Failed`](crate::CodesignError::Failed), exit
/// code 1. A line that can't be read as a requirement fails with
/// [`CodesignError::UnexpectedOutput`](crate::CodesignError::UnexpectedOutput). The checks made
/// before `codesign` starts are listed in [`codesign`](crate::codesign#errors).
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign;
///
/// for requirement in codesign::requirements("MyApp.app").await? {
///     println!("{:?}: {}", requirement.kind, requirement.expression);
/// }
/// # Ok(()) }
/// ```
pub fn requirements<T: IntoTargets>(target: T) -> Requirements<T::Shape> {
    Requirements::new(target, Default::default())
}

/// Reads the certificate chain that signed `target`, leaf first (`--extract-certificates`).
///
/// `.await` yields one `Vec` of [`Certificate`](crate::codesign::Certificate) per target, the
/// signing certificate first and the root last. A target signed ad hoc has none, so its `Vec`
/// is empty. [`save_to`](ExtractCertificates::save_to) also writes the chains to PEM files.
///
/// Given several targets, each is read on its own, concurrently, and every one that failed is
/// reported together as [`Error::Batch`](crate::Error::Batch). One `codesign` over several
/// targets would write every chain to the same files, so this action always runs one per target,
/// and [`per_target`](ExtractCertificates::per_target) can't be called on it:
///
/// ```compile_fail,E0277
/// signers::codesign::extract_certificates(vec!["a"]).per_target(false);
/// ```
///
/// # Errors
///
/// An unsigned target fails with [`CodesignError::Failed`](crate::CodesignError::Failed), exit
/// code 1. A file that can't be read or written fails with [`Error::Io`](crate::Error::Io),
/// also when the system's temporary directory can't be used. The checks made before `codesign`
/// starts are listed in [`codesign`](crate::codesign#errors).
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign;
///
/// let chains = codesign::extract_certificates(vec!["A.app", "B.app"]).await?;
/// for chain in &chains {
///     println!("{} certificates", chain.len());
/// }
/// # Ok(()) }
/// ```
pub fn extract_certificates<T: IntoTargets>(target: T) -> ExtractCertificates<T::Shape> {
    ExtractCertificates::new(target, Default::default())
}
