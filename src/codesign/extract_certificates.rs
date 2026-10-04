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

use super::actions::PushArgs;
use super::actions::sealed::ToArgs;
use crate::codesign::Codesign;
use crate::errors::{Error, Result};
use crate::target::Shape;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn into_der(self) -> Vec<u8> {
        self.der
    }
}

#[derive(Debug, Default)]
pub struct ExtractCertificates {
    save_to: Option<PathBuf>,
    run: Mutex<RunState>,
}

#[derive(Debug, Default)]
struct RunState {
    dir: Option<TempDir>,
    next: usize,
    // Keyed by the address of the run's target slice, not by its path: the
    // same path can be given twice, and each run must read its own files.
    prefixes: HashMap<usize, OsString>,
}

impl Clone for ExtractCertificates {
    fn clone(&self) -> Self {
        Self {
            save_to: self.save_to.clone(),
            run: Mutex::default(),
        }
    }
}

impl ExtractCertificates {
    fn state(&self) -> MutexGuard<'_, RunState> {
        self.run.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<S: Shape> Codesign<ExtractCertificates, S> {
    pub fn save_to(mut self, dir: impl Into<PathBuf>) -> Self {
        self.action.save_to = Some(dir.into());
        self
    }
}

impl ToArgs for ExtractCertificates {
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
                Ok(der) => chain.push(Certificate { der }),
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
        let encoded = STANDARD.encode(&certificate.der);
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
