//! What every `codesign` action shares: argument rendering helpers and the `action!` macro that
//! defines each action's public type over the engine's `Job`.

use bitflags::Flags;

/// Comma-joins the `flag_name` tokens of the flags set in `flags`, in declaration order.
///
/// Not `bitflags`' `Display`, which separates with ` | `.
pub(crate) fn joined<F: Flags + Copy>(flags: F) -> Option<String> {
    let mut tokens = String::new();
    for flag in F::FLAGS.iter().filter(|flag| flags.contains(*flag.value())) {
        if !tokens.is_empty() {
            tokens.push(',');
        }
        tokens.push_str(flag.name());
    }
    (!tokens.is_empty()).then_some(tokens)
}

// Emits an action's public type over the engine's `Job`, its private `Options`, a private `new`, one setter
// per field of the `setters` block, `per_target`, `IntoFuture` (async) and `run` (blocking).
// Fields in the first block get no setter. Setter forms: `Option<impl Into<T>>` takes
// `impl Into<T>` and stores `Some`; `Option<T>` takes `T` and stores `Some`; `T` takes `T`.
// The rule arms below must keep that order, from the most specific form to any type.
macro_rules! action {
    (
        $(#[$attr:meta])*
        $name:ident => $output:ty {
            $($field:ident : $field_ty:ty),* $(,)?
        }
        setters {
            $($setters:tt)*
        }
    ) => {
        $crate::codesign::action::action!(@options [$($field: $field_ty,)*] $($setters)*);

        #[derive(Debug, Clone)]
        #[must_use = "an action does nothing until it is `.await`ed or `.run()`"]
        $(#[$attr])*
        pub struct $name<S = $crate::target::One, R = $crate::engine::Async> {
            job: $crate::engine::Job<S, R>,
            options: Options,
        }

        impl<S, R> $name<S, R>
        where
            S: $crate::target::Shape,
        {
            pub(crate) fn new<T>(target: T, options: Options) -> Self
            where
                T: $crate::IntoTargets<Shape = S>,
            {
                Self { job: $crate::engine::Job::new::<Options, T>(target), options }
            }
        }

        impl<S, R> $name<S, R> {
            $crate::codesign::action::action!(@setters $($setters)*);

            /// Runs one `codesign` per target, concurrently, instead of one for all of them.
            ///
            /// One process stops at the first target it rejects and reports that one only. Per target,
            /// every target runs, and the failures come together as [`Error::Batch`](crate::Error::Batch),
            /// in input order. At most [`available_parallelism`](std::thread::available_parallelism)
            /// processes run at a time. The default is `false` for [`sign`](crate::codesign::sign), its
            /// presets and [`remove_signature`](crate::codesign::remove_signature), which change the
            /// targets in order, and `true` for [`verify`](crate::codesign::verify),
            /// [`display`](crate::codesign::display) and
            /// [`validate_constraint`](crate::codesign::validate_constraint), which only read them.
            ///
            /// With `per_target(true)`, the runs that haven't started yet don't start once the future is
            /// dropped.
            ///
            /// Only a `Vec`, slice or array of targets has this setter, even with one element. A single
            /// target always runs one `codesign`:
            ///
            /// ```compile_fail,E0277
            /// signers::codesign::sign("a", "-").per_target(true);
            /// ```
            ///
            /// [`requirements`](crate::codesign::requirements) and
            /// [`extract_certificates`](crate::codesign::extract_certificates) can't take it either: they always run one `codesign` per target.
            ///
            /// An option that writes one shared file, [`file_list`](crate::codesign::Sign::file_list) or
            /// [`detached`](crate::codesign::Sign::detached), makes `.await` fail with
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
            /// use signers::{Error, codesign};
            ///
            /// let libraries = vec!["liba.dylib", "libb.dylib", "libc.dylib"];
            /// match codesign::sign_adhoc(libraries).force(true).per_target(true).await {
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
            pub fn per_target(mut self, per_target: bool) -> Self
            where
                S: $crate::target::Multi,
                Self: $crate::engine::SharedRun,
            {
                self.job.batch = per_target;
                self
            }
        }

        /// Runs the action when awaited. Its [errors](crate::codesign#errors) and
        /// [panics](crate::codesign#panics) are listed in [`codesign`](crate::codesign).
        impl<S> ::std::future::IntoFuture for $name<S, $crate::engine::Async>
        where
            S: $crate::target::Shape,
        {
            type Output = $crate::Result<<S as $crate::target::Shape>::Out<$output>>;
            type IntoFuture = ::std::pin::Pin<
                ::std::boxed::Box<dyn ::std::future::Future<Output = Self::Output> + Send>,
            >;

            /// Returns the future that runs the action. Nothing happens until it's polled.
            ///
            /// Once every `codesign` run has exited 0, it resolves to the action's output for each
            /// target, shaped like the targets: one output for a single path, a `Vec` of them for a
            /// `Vec` or slice, an array of `N` for an array of `N`.
            fn into_future(self) -> Self::IntoFuture {
                self.job.run(self.options)
            }
        }

        #[cfg(feature = "blocking")]
        impl<S> $name<S, $crate::engine::Blocking>
        where
            S: $crate::target::Shape,
        {
            /// Runs the action, blocking the calling thread until every `codesign` has finished.
            ///
            /// It checks, runs and returns exactly like `.await` on the async builder: the same output
            /// shape, the same errors, and the same concurrent processes with
            /// [`per_target`](Self::per_target). It builds a single-threaded Tokio runtime for the call
            /// and drops it before returning.
            ///
            /// # Errors
            ///
            /// Those listed in [`codesign`](crate::codesign#errors). A runtime that can't be created
            /// fails with [`ProcessError::Spawn`](crate::ProcessError::Spawn).
            ///
            /// # Panics
            ///
            /// Panics when called inside a Tokio runtime, such as from an `async fn` it runs. There,
            /// `.await` the builder from [`codesign`](crate::codesign) instead.
            ///
            /// # Examples
            ///
            /// ```no_run
            /// # fn main() -> signers::Result<()> {
            /// use signers::codesign::blocking;
            ///
            /// let [ls, cat] = blocking::display(["/bin/ls", "/bin/cat"]).run()?;
            /// println!("{} {}", ls.identifier, cat.identifier);
            /// # Ok(()) }
            /// ```
            pub fn run(self) -> $crate::Result<<S as $crate::target::Shape>::Out<$output>> {
                self.job.run(self.options)
            }
        }
    };

    // Collects the private `Options` fields; a setter's attributes stay off its field.
    (@options [$($acc:tt)*]) => {
        #[derive(Debug, Clone, Default)]
        pub(crate) struct Options { $($acc)* }
    };
    (@options [$($acc:tt)*] $(#[$m:meta])* $f:ident : Option<impl Into<$t:ty>> $(, $($rest:tt)*)?) => {
        $crate::codesign::action::action!(@options [$($acc)* $f: Option<$t>,] $($($rest)*)?);
    };
    (@options [$($acc:tt)*] $(#[$m:meta])* $f:ident : $t:ty $(, $($rest:tt)*)?) => {
        $crate::codesign::action::action!(@options [$($acc)* $f: $t,] $($($rest)*)?);
    };

    // One setter per field, named after it; attributes (docs, `#[deprecated]`) go on the setter.
    (@setters) => {};
    (@setters $(#[$m:meta])* $f:ident : Option<impl Into<$t:ty>> $(, $($rest:tt)*)?) => {
        $(#[$m])*
        pub fn $f(mut self, $f: impl Into<$t>) -> Self {
            self.options.$f = Some($f.into());
            self
        }
        $crate::codesign::action::action!(@setters $($($rest)*)?);
    };
    (@setters $(#[$m:meta])* $f:ident : Option<$t:ty> $(, $($rest:tt)*)?) => {
        $(#[$m])*
        pub fn $f(mut self, $f: $t) -> Self {
            self.options.$f = Some($f);
            self
        }
        $crate::codesign::action::action!(@setters $($($rest)*)?);
    };
    (@setters $(#[$m:meta])* $f:ident : $t:ty $(, $($rest:tt)*)?) => {
        $(#[$m])*
        pub fn $f(mut self, $f: $t) -> Self {
            self.options.$f = $f;
            self
        }
        $crate::codesign::action::action!(@setters $($($rest)*)?);
    };
}

pub(crate) use action;
