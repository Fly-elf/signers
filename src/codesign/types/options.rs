use bitflags::bitflags;

/// Which of the two signatures of a code object to use (`--signature-slot`).
///
/// Without it, `codesign` uses the slot the system prefers. The second slot exists only if the
/// code carries two signatures. Pass it to [`verify`](crate::codesign::verify).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureSlot {
    /// The first signature (`1`).
    First,
    /// The second signature (`2`).
    Second,
}

impl SignatureSlot {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::First => "1",
            Self::Second => "2",
        }
    }
}

/// Where [`timestamp`](crate::codesign::Sign::timestamp) gets a secure timestamp from, if anywhere.
///
/// Leaving the option unset isn't the same as [`Disabled`](Timestamp::Disabled): unset lets
/// `codesign` decide.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign::{self, Timestamp};
///
/// let identity = "Developer ID Application: Jane Doe (A1B2C3D4E5)";
///
/// // An offline build: no timestamp server is contacted.
/// codesign::sign("MyApp.app", identity)
///     .timestamp(Timestamp::Disabled)
///     .await?;
///
/// // Your own timestamp authority instead of Apple's.
/// codesign::sign("MyApp.app", identity)
///     .timestamp(Timestamp::ServerUrl("http://tsa.example.com".into()))
///     .await?;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Timestamp {
    /// Apple's timestamp server (`--timestamp`).
    Enabled,
    /// The timestamp server at this URL (`--timestamp=<url>`).
    ServerUrl(String),
    /// No timestamp (`--timestamp=none`).
    Disabled,
}

bitflags! {
    /// Code signing flags that [`options`](crate::codesign::Sign::options) seals into the
    /// signature.
    ///
    /// Combine them with `|`. The bits are the ones `codesign -dv` prints as `flags=0x…`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign::{self, SigningFlags};
    ///
    /// codesign::sign("MyApp.app", "Developer ID Application: Jane Doe (A1B2C3D4E5)")
    ///     .options(SigningFlags::RUNTIME | SigningFlags::LIBRARY)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub struct SigningFlags: u32 {
        /// Lets the code host guest code (`host`).
        #[bitflags(flag_name = "host")]
        const HOST = 0x0001;
        /// Asks the system to deny the process a resource rather than invalidate its identity
        /// (`hard`).
        #[bitflags(flag_name = "hard")]
        const HARD = 0x0100;
        /// Kills the process as soon as its signature becomes invalid (`kill`).
        #[bitflags(flag_name = "kill")]
        const KILL = 0x0200;
        /// Fails verification once any certificate in the chain has expired (`expires`).
        #[bitflags(flag_name = "expires")]
        const EXPIRES = 0x0400;
        /// Lets the executable load only system libraries or its own team's (`library`).
        #[bitflags(flag_name = "library")]
        const LIBRARY = 0x2000;
        /// Opts into the hardened runtime, which notarization requires (`runtime`).
        #[bitflags(flag_name = "runtime")]
        const RUNTIME = 0x1_0000;
        /// Marks the signature as the linker's: replaced without `force`, never preserved
        /// (`linker-signed`).
        #[bitflags(flag_name = "linker-signed")]
        const LINKER_SIGNED = 0x2_0000;
    }
}

bitflags! {
    /// Parts of the old signature that
    /// [`preserve_metadata`](crate::codesign::Sign::preserve_metadata) carries over.
    ///
    /// Combine them with `|`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign::{self, PreserveMetadata};
    ///
    /// // Re-sign a patched binary and keep the identifier and entitlements it had.
    /// codesign::sign_adhoc("patched")
    ///     .force(true)
    ///     .preserve_metadata(PreserveMetadata::IDENTIFIER | PreserveMetadata::ENTITLEMENTS)
    ///     .await?;
    /// # Ok(()) }
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub struct PreserveMetadata: u8 {
        /// The signing identifier (`identifier`).
        #[bitflags(flag_name = "identifier")]
        const IDENTIFIER = 1 << 0;
        /// The entitlements (`entitlements`).
        #[bitflags(flag_name = "entitlements")]
        const ENTITLEMENTS = 1 << 1;
        /// All the internal requirements, since they can't be picked one by one
        /// (`requirements`).
        #[bitflags(flag_name = "requirements")]
        const REQUIREMENTS = 1 << 2;
        /// The code signing flags (`flags`).
        #[bitflags(flag_name = "flags")]
        const FLAGS = 1 << 3;
        /// The hardened runtime version (`runtime`).
        #[bitflags(flag_name = "runtime")]
        const RUNTIME = 1 << 4;
        /// The launch constraints, unless a `launch_constraint_*` option is set
        /// (`launch-constraints`).
        #[bitflags(flag_name = "launch-constraints")]
        const LAUNCH_CONSTRAINTS = 1 << 5;
        /// The library constraint, unless
        /// [`library_constraint`](crate::codesign::Sign::library_constraint) is set
        /// (`library-constraints`).
        #[bitflags(flag_name = "library-constraints")]
        const LIBRARY_CONSTRAINTS = 1 << 6;
    }
}

/// The extra restrictions that [`strict`](crate::codesign::Verify::strict) applies.
///
/// `codesign` takes one value here, so one is enough, and the last one set wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strict {
    /// Every strict check there is, now and in later macOS versions (`--strict`).
    ///
    /// A new macOS can add checks, so code that passes today can fail later.
    All,
    /// Rejects a symbolic link in a bundle that is broken, points outside the bundle, or isn't
    /// sealed by the signature (`--strict=symlinks`).
    Symlinks,
    /// Rejects resource forks, Finder attributes and similar sideband data (`--strict=sideband`).
    ///
    /// Signing already enforces this, so it rarely changes a result.
    Sideband,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_levels_compare_by_value() {
        assert_eq!(Strict::All, Strict::All);
        assert_ne!(Strict::All, Strict::Symlinks);
        assert_ne!(Strict::Symlinks, Strict::Sideband);
    }

    #[test]
    fn signature_slots_render_as_their_number() {
        assert_eq!(SignatureSlot::First.as_str(), "1");
        assert_eq!(SignatureSlot::Second.as_str(), "2");
    }
}
