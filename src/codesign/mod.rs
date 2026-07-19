//! Async signing API backed by the macOS `codesign` binary (subprocess).

mod actions;

use std::future::{Future, IntoFuture};
use std::path::PathBuf;
use std::pin::Pin;

use crate::errors::{Error, Result};
use crate::target::IntoTargets;

pub use actions::{Action, DigestAlgorithm, Metadata, Sign, SigningFlag, Timestamp};

/// Fluent builder over a signing action, parameterised by the action type.
///
/// Create one with a constructor ([`Codesign::sign`], ...), chain the options
/// that action supports, then `.await` it to run `codesign`.
#[derive(Debug, Clone)]
pub struct Codesign<A> {
    targets: Vec<PathBuf>,
    action: A,
}

impl Codesign<()> {
    /// Signs one or more targets with `codesign`.
    ///
    /// Defaults to ad-hoc signing (`-`) while replacing any existing signature —
    /// the common case when re-signing patched binaries. Override via
    /// [`identity`](Codesign::identity), [`force`](Codesign::force) and
    /// [`deep`](Codesign::deep).
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), signers::Error> {
    /// use signers::codesign::Codesign;
    ///
    /// Codesign::sign("MyApp.app").identity("-").deep(true).await?;
    /// # Ok(()) }
    /// ```
    pub fn sign(target: impl IntoTargets) -> Codesign<Sign> {
        Codesign {
            targets: target.into_targets(),
            action: Sign::default(),
        }
    }
}

impl<A: Action + Send + 'static> IntoFuture for Codesign<A> {
    type Output = Result<()>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            if self.targets.is_empty() {
                return Err(Error::NoTargets);
            }
            for target in &self.targets {
                match tokio::fs::try_exists(target).await {
                    Ok(true) => {}
                    Ok(false) => return Err(Error::TargetNotFound(target.clone())),
                    Err(source) => {
                        return Err(Error::TargetAccess {
                            path: target.clone(),
                            source,
                        });
                    }
                }
            }

            let args = self.action.args(&self.targets);
            tracing::debug!(?args, "running codesign");

            let output = tokio::process::Command::new("codesign")
                .args(&args)
                .output()
                .await
                .map_err(Error::Spawn)?;

            if output.status.success() {
                Ok(())
            } else {
                Err(Error::Codesign {
                    status: output.status,
                    stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
                })
            }
        })
    }
}
