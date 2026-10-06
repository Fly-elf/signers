use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tempfile::TempDir;

use crate::codesign::Certificate;
use crate::codesign::action::PushArgs;
use crate::codesign::action::action;
use crate::codesign::action::sealed::ToArgs;
use crate::errors::{Error, Result};

action! {
    /// Options of the certificate-extraction action: the `A` in `Codesign<ExtractCertificates>`.
    ///
    /// [`Codesign::extract_certificates`](crate::Codesign#method.extract_certificates) creates it. Its
    /// one option, [`save_to`](crate::Codesign#method.save_to), also writes each chain to a PEM file.
    /// `.await` yields the chain of each target as a `Vec` of [`Certificate`], leaf first.
    ///
    /// # Examples
    ///
    /// Read the chain of a signed binary, and tell an ad hoc signature, which has none:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let chain = Codesign::extract_certificates("MyApp.app").await?;
    /// match chain.first() {
    ///     Some(leaf) => println!("signed with a certificate of {} bytes", leaf.der().len()),
    ///     None => println!("signed ad hoc"),
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// Save the chains of two apps as PEM files in `certs/`:
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::Codesign;
    ///
    /// let [a, b] = Codesign::extract_certificates(["A.app", "B.app"])
    ///     .save_to("certs")
    ///     .await?;
    /// // `certs/A.app.pem` and `certs/B.app.pem` now hold what `a` and `b` hold.
    /// # Ok(()) }
    /// ```
    ExtractCertificates => Vec<Certificate> {
        run: RunCell,
    }
    setters {
        /// Also writes each target's chain as a PEM file in `dir`.
        ///
        /// The file is named after the target, `MyApp.app` into `MyApp.app.pem`, and holds the chain
        /// leaf first, so `openssl` reads it as it is. A name already taken, by an earlier target of
        /// the same run or by a file that was there before, gets a number instead:
        /// `MyApp.app2.pem`, `MyApp.app3.pem`. A file is never overwritten. Targets that share a name
        /// are numbered in no fixed order, because they run concurrently.
        ///
        /// A target with an ad hoc signature has no certificates and gets no file. `dir` is created,
        /// with its parents, only when at least one file is to be written: if every target is ad hoc,
        /// it is left alone. The files of the targets that were read stay when another target of the
        /// same run fails.
        ///
        /// A `dir` or a file that can't be written fails with [`Error::Io`].
        ///
        /// A later call replaces an earlier one.
        ///
        /// [`Error::Io`]: crate::Error::Io
        save_to: Option<impl Into<PathBuf>>,
    }
}

#[derive(Debug, Default)]
struct RunState {
    dir: Option<TempDir>,
    next: usize,
    // Keyed by the address of the run's target slice, not by its path: the
    // same path can be given twice, and each run must read its own files.
    prefixes: HashMap<usize, OsString>,
}

#[derive(Debug, Default)]
struct RunCell(Mutex<RunState>);

impl Clone for RunCell {
    // A clone hasn't run yet: it starts with no run state.
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl Options {
    fn state(&self) -> MutexGuard<'_, RunState> {
        self.run.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl ToArgs for Options {
    type Output = Vec<Certificate>;
    const PER_TARGET: bool = true;

    fn validate(&self) -> Result<()> {
        let dir = TempDir::new().map_err(|source| Error::Io {
            path: std::env::temp_dir(),
            source,
        })?;
        *self.state() = RunState {
            dir: Some(dir),
            ..RunState::default()
        };
        Ok(())
    }

    fn to_args<'a>(&'a self, targets: &'a [PathBuf]) -> Vec<Cow<'a, OsStr>> {
        let prefix = {
            let mut state = self.state();
            let n = state.next;
            state.next += 1;
            let dir = state
                .dir
                .as_ref()
                .expect("validate creates the directory before any run");
            let prefix = dir.path().join(format!("{n}-")).into_os_string();
            state
                .prefixes
                .insert(targets.as_ptr().addr(), prefix.clone());
            prefix
        };

        let mut arg = OsString::from("--extract-certificates=");
        arg.push(&prefix);

        let mut args: Vec<Cow<'a, OsStr>> = Vec::new();
        args.flag("--display");
        args.built(arg);
        args.targets(targets);
        args
    }

    fn output(
        &self,
        targets: &[PathBuf],
        _stdout: String,
        _stderr: String,
    ) -> Result<Vec<Vec<Certificate>>> {
        let prefix = self
            .state()
            .prefixes
            .remove(&targets.as_ptr().addr())
            .expect("to_args records the prefix of every run");

        let mut chain = Vec::new();
        for index in 0.. {
            let mut path = prefix.clone();
            path.push(index.to_string());
            let path = PathBuf::from(path);
            match std::fs::read(&path) {
                Ok(der) => chain.push(Certificate::from_der(der)),
                Err(error) if error.kind() == ErrorKind::NotFound => break,
                Err(source) => return Err(Error::Io { path, source }),
            }
        }

        if let Some(dir) = &self.save_to
            && !chain.is_empty()
        {
            save_pem(dir, &targets[0], &chain)?;
        }
        Ok(vec![chain])
    }
}

fn save_pem(dir: &Path, target: &Path, chain: &[Certificate]) -> Result<()> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| Error::Io { path, source }
    };

    std::fs::create_dir_all(dir).map_err(io(dir))?;

    let name = match target.file_name() {
        Some(name) => name.to_owned(),
        // `.` or `..`: the directory it stands for has the name.
        None => std::fs::canonicalize(target)
            .map_err(io(target))?
            .file_name()
            .unwrap_or(OsStr::new("certificates"))
            .to_owned(),
    };

    let pem = pem(chain);
    for n in 1usize.. {
        let mut file_name = name.clone();
        if n > 1 {
            file_name.push(n.to_string());
        }
        file_name.push(".pem");
        let path = dir.join(file_name);

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => return file.write_all(pem.as_bytes()).map_err(io(&path)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(source) => return Err(Error::Io { path, source }),
        }
    }
    unreachable!("some file name is always free")
}

fn pem(chain: &[Certificate]) -> String {
    let mut pem = String::new();
    for certificate in chain {
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        let encoded = STANDARD.encode(certificate.der());
        let mut rest = encoded.as_str();
        while !rest.is_empty() {
            let (line, tail) = rest.split_at(rest.len().min(64));
            pem.push_str(line);
            pem.push('\n');
            rest = tail;
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codesign::extract_certificates;

    /// A run leaves its scratch directory, counter and prefixes in the
    /// options; a copy made afterwards must not inherit or share any of them.
    #[test]
    fn a_clone_starts_without_the_run_state_of_its_original() {
        let original = extract_certificates("a").options;
        original.validate().unwrap();
        let targets = [PathBuf::from("a")];
        original.to_args(&targets);
        {
            let state = original.state();
            assert!(state.dir.is_some());
            assert_eq!(state.next, 1);
            assert_eq!(state.prefixes.len(), 1);
        }

        let copy = original.clone();

        let state = copy.state();
        assert!(state.dir.is_none());
        assert_eq!(state.next, 0);
        assert!(state.prefixes.is_empty());
        assert!(original.state().dir.is_some());
    }

    /// The chains of several targets come from separate runs, so there is no
    /// shared run to opt into. Resolves only while `ExtractCertificates` is
    /// not `SharedRun`.
    #[test]
    fn the_action_cannot_share_a_run() {
        trait AmbiguousIfShared<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfShared<()> for T {}
        impl<T: ?Sized + crate::codesign::action::sealed::SharedRun> AmbiguousIfShared<u8> for T {}

        <ExtractCertificates as AmbiguousIfShared<_>>::check();
    }

    #[test]
    fn save_to_keeps_the_last_directory() {
        let options = extract_certificates("a")
            .save_to("first")
            .save_to("second")
            .options;

        assert_eq!(options.save_to, Some(PathBuf::from("second")));
    }

    #[test]
    fn the_arguments_extract_into_the_run_directory_and_list_the_targets_last() {
        let options = extract_certificates("a").options;
        options.validate().unwrap();
        let targets = [PathBuf::from("a"), PathBuf::from("-b")];

        let args = options.to_args(&targets);

        let prefix = options.state().dir.as_ref().unwrap().path().join("0-");
        let mut expected = OsString::from("--extract-certificates=");
        expected.push(prefix);
        assert_eq!(args[0], OsStr::new("--display"));
        assert_eq!(args[1], expected);
        assert_eq!(&args[2..], ["--", "a", "-b"].map(OsStr::new));
    }

    #[test]
    fn every_run_gets_its_own_prefix() {
        let options = extract_certificates("a").options;
        options.validate().unwrap();
        let (first, second) = ([PathBuf::from("a")], [PathBuf::from("a")]);

        let one = options.to_args(&first)[1].to_string_lossy().into_owned();
        let two = options.to_args(&second)[1].to_string_lossy().into_owned();

        assert!(one.ends_with("/0-"), "{one}");
        assert!(two.ends_with("/1-"), "{two}");
    }
}
