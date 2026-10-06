use std::marker::PhantomData;
use std::path::PathBuf;

use crate::codesign::action::Action;
use crate::codesign::action::sealed::SharedRun;
use crate::codesign::{Display, Verify};
use crate::target::{self, IntoTargets, Multi, One};

pub trait Runtime {}

/// The builder behind [`Codesign`](crate::Codesign) and `blocking::Codesign`; name those instead.
///
/// Both are this type with a different `R`, which only decides how a run starts: `.await` or
/// `.run()`. Their pages list the constructors and setters shown below, with the same
/// documentation, and the method that runs them.
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
    /// Checks the signature of `target` (`--verify`), changing nothing.
    ///
    /// `.await` yields `()` per target when every one verifies. Without options it checks that
    /// the signature is intact and covers the code. Whether the system would run the code is a
    /// different question: verified code can still be refused by Gatekeeper.
    ///
    /// Given several targets, each is verified on its own by default, so one `.await` reports every
    /// target that failed, as [`Error::Batch`](crate::Error::Batch).
    /// [`per_target(false)`](crate::Codesign#method.per_target) runs one `codesign` instead, which
    /// stops at the first target it rejects.
    ///
    /// # Errors
    ///
    /// A target that doesn't verify fails with
    /// [`CodesignError::VerificationFailed`](crate::CodesignError::VerificationFailed): the
    /// signature is invalid or modified, the target is unsigned, or the requirement text doesn't
    /// compile. A valid signature that doesn't meet a requirement fails with
    /// [`CodesignError::RequirementUnsatisfied`](crate::CodesignError::RequirementUnsatisfied). The
    /// checks made before `codesign` starts are on [`Codesign`](crate::Codesign#errors).
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
    /// that did read are dropped with it. [`per_target(false)`](crate::Codesign#method.per_target)
    /// runs one `codesign` instead: it stops at the first target it rejects, and the entitlements
    /// of every target stay [`None`](crate::codesign::Signature#structfield.entitlements).
    ///
    /// # Errors
    ///
    /// An unsigned target fails with [`CodesignError::Failed`](crate::CodesignError::Failed), exit
    /// code 1. With one `codesign` over several targets, its `stderr` also holds the reports of the
    /// targets before the unsigned one. A [`signature_slot`](crate::Codesign#method.signature_slot)
    /// the code has no signature in fails with
    /// [`CodesignError::NoSignature`](crate::CodesignError::NoSignature). A report or entitlements
    /// that can't be read fails with
    /// [`CodesignError::UnexpectedOutput`](crate::CodesignError::UnexpectedOutput). The checks made
    /// before `codesign` starts are on [`Codesign`](crate::Codesign#errors).
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
}

/// Options for a `Vec`, slice or array of targets.
impl<A: Action + SharedRun, S: Multi, R: Runtime> Runner<A, S, R> {
    /// Runs one `codesign` per target, concurrently, instead of one for all of them.
    ///
    /// One process stops at the first target it rejects and reports that one only. Per target,
    /// every target runs, and the failures come together as [`Error::Batch`](crate::Error::Batch),
    /// in input order. At most [`available_parallelism`](std::thread::available_parallelism)
    /// processes run at a time. The default is `false` for [`sign`](crate::Codesign#method.sign)
    /// and [`remove_signature`](crate::Codesign#method.remove_signature), which change the targets
    /// in order, and `true` for [`verify`](crate::Codesign#method.verify),
    /// [`display`](crate::Codesign#method.display) and
    /// [`validate_constraint`](crate::Codesign#method.validate_constraint), which only read them.
    ///
    /// Only a `Vec`, slice or array of targets has this setter, even with one element: that is
    /// the `S: Multi` bound. A single target always runs one `codesign`:
    ///
    /// ```compile_fail,E0599
    /// signers::Codesign::sign("a", "-").per_target(true);
    /// ```
    ///
    /// [`extract_certificates`](crate::Codesign#method.extract_certificates) and
    /// [`internal_requirements`](crate::Codesign#method.internal_requirements) have no such setter
    /// either: they always run one `codesign` per target.
    ///
    /// An option that writes one shared file, [`file_list`](crate::Codesign#method.file_list) or
    /// [`detached`](crate::Codesign#method.detached), makes `.await` fail with
    /// [`Error::SharedOutputPerTarget`](crate::Error::SharedOutputPerTarget).
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::codesign::action::sealed::ToArgs;

    /// Constructors and setters are written once for every runtime, so a
    /// marker of their own is enough to check them.
    #[derive(Debug)]
    struct AnyRuntime;

    impl Runtime for AnyRuntime {}

    fn display<T: IntoTargets>(target: T) -> Runner<Display, T::Shape, AnyRuntime> {
        new(target, Display::default())
    }

    /// `A::PER_TARGET` is true for display, yet a single target never
    /// starts per target; the other shapes do.
    #[test]
    fn the_constructor_default_is_false_for_a_single_target_whatever_the_action() {
        const { assert!(Display::PER_TARGET) };

        assert!(!display("a").per_target);
        assert!(!display(String::from("a")).per_target);
        assert!(!display(Path::new("a")).per_target);
        assert!(!display(PathBuf::from("a")).per_target);

        assert!(display(vec!["a"]).per_target);
        assert!(display(vec!["a", "b"]).per_target);
        assert!(display(&["a", "b"][..]).per_target);
        assert!(display(["a"]).per_target);
        assert!(display(["a", "b"]).per_target);
    }

    /// The setter is typed on the shape, not on the length.
    #[test]
    fn a_one_element_collection_keeps_the_per_target_setter() {
        let from_vec = display(vec!["a"]).per_target(false);
        assert!(!from_vec.per_target);
        let from_array = display(["a"]).per_target(false);
        assert!(!from_array.per_target);

        assert!(
            display(vec!["a"])
                .per_target(false)
                .per_target(true)
                .per_target
        );
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn changing_the_runtime_keeps_targets_action_and_per_target() {
        #[derive(Debug)]
        struct Other;
        impl Runtime for Other {}

        for per_target in [true, false] {
            let runner: Runner<Verify, _, AnyRuntime> =
                new(vec!["a", "", "a"], Verify::default()).per_target(per_target);
            let action = format!("{:?}", runner.action);

            let moved: Runner<Verify, _, Other> = runner.with_runtime();

            assert_eq!(moved.targets, ["a", "", "a"].map(PathBuf::from));
            assert_eq!(moved.per_target, per_target);
            assert_eq!(format!("{:?}", moved.action), action);
        }
    }
}
