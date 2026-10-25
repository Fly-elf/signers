use std::path::PathBuf;
use std::str::FromStr;

use bitflags::bitflags;

use super::options::SigningFlags;
use crate::engine::Rejection;

/// The signature of one target, as `codesign --display` reports it.
///
/// Each field comes from a line of the report; fields that are `Option` or empty are for lines
/// `codesign` prints only for some signatures. Nothing is lost to the typed view: [`raw`] returns
/// the report as printed, minus trailing whitespace, and [`field`] looks up any line, mapped or
/// not. A line this crate doesn't know is ignored.
///
/// The type is `#[non_exhaustive]`, so a later version can add fields. Read it, don't build it.
///
/// # Examples
///
/// ```no_run
/// # async fn run() -> signers::Result<()> {
/// use signers::codesign::{self, SignatureKind, SigningFlags};
///
/// let signature = codesign::display("MyApp.app").await?;
///
/// println!("{} ({})", signature.identifier, signature.cd_hash);
/// if signature.code_directory.flags.contains(SigningFlags::RUNTIME) {
///     println!("hardened runtime");
/// }
/// if let SignatureKind::Certificate { authorities, .. } = &signature.signature {
///     println!("signed through {} certificates", authorities.len());
/// }
/// # Ok(()) }
/// ```
///
/// [`raw`]: Signature::raw
/// [`field`]: Signature::field
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    /// The path of the main executable (`Executable`).
    ///
    /// For a bundle it is the executable inside it, and for a versioned bundle read with
    /// [`bundle_version`](crate::codesign::Display::bundle_version) it names that version. The
    /// report is decoded lossily, so a byte that isn't UTF-8 in the path becomes U+FFFD.
    pub executable: PathBuf,
    /// The signing identifier (`Identifier`).
    pub identifier: String,
    /// What kind of code it is (`Format`).
    pub format: Format,
    /// The code directory, the part of the signature that seals the code (`CodeDirectory`).
    pub code_directory: CodeDirectory,
    /// The platform identifier of an Apple system binary (`Platform identifier`).
    pub platform_identifier: Option<u32>,
    /// The warning `codesign` gives when library validation can't protect the code
    /// (`Library validation warning`).
    pub library_validation_warning: Option<String>,
    /// The platform the Mach-O was built for (`VersionPlatform`).
    pub platform: Option<Platform>,
    /// The oldest OS version the code runs on (`VersionMin`).
    pub min_os: Option<OsVersion>,
    /// The SDK version the code was built with (`VersionSDK`).
    pub sdk: Option<OsVersion>,
    /// The hash algorithm of the chosen code directory (`Hash type`).
    pub hash_type: HashType,
    /// Every hash algorithm the signature carries a code directory for (`Hash choices`).
    pub hash_choices: Vec<HashType>,
    /// The code directory hash for each algorithm in the signature (`CandidateCDHash`).
    pub cd_hashes: Vec<CdHash>,
    /// The hash that identifies the code, in hex (`CDHash`).
    pub cd_hash: String,
    /// The CMS digest and its type (`CMSDigest`, `CMSDigestType`).
    pub cms_digest: Option<CmsDigest>,
    /// Where the executable segment of the Mach-O sits (`Executable Segment`).
    pub executable_segment: Option<ExecutableSegment>,
    /// The size of the pages the code is hashed in; `None` when the code isn't paged
    /// (`Page size`).
    pub page_size: Option<u32>,
    /// How the code was signed: ad hoc or with a certificate (`Signature`).
    pub signature: SignatureKind,
    /// The secure timestamp, as `codesign` prints it (`Timestamp`).
    ///
    /// A signature has either this or [`signed_time`](Signature::signed_time). The text follows
    /// the user's locale and time zone, so don't parse it.
    pub timestamp: Option<String>,
    /// The time the signature was made, as `codesign` prints it (`Signed Time`).
    ///
    /// The text follows the user's locale and time zone, so don't parse it.
    pub signed_time: Option<String>,
    /// The notarization ticket stapled to the code (`Notarization Ticket`).
    pub notarization_ticket: Option<String>,
    /// Whether the signature covers an `Info.plist` (`Info.plist`).
    pub info_plist: InfoPlist,
    /// The Team ID of the signer; `None` for ad hoc and for unteamed certificates
    /// (`TeamIdentifier`).
    pub team_identifier: Option<String>,
    /// The hardened runtime version; only code signed with the runtime option has one
    /// (`Runtime Version`).
    pub runtime_version: Option<OsVersion>,
    /// The seal over the bundle's resources; `None` when nothing is sealed (`Sealed Resources`).
    pub sealed_resources: Option<SealedResources>,
    /// How many requirements the signature embeds, and their size; `None` when there are none
    /// (`Internal requirements`).
    /// [`requirements`](crate::codesign::requirements) reads the
    /// requirements themselves.
    pub internal_requirements: Option<RequirementsSummary>,
    /// The number of signatures in the code (`Total signatures`).
    ///
    /// `None` when the report has no such line, as for code signed by the linker and on macOS
    /// before 27.
    pub total_signatures: Option<u32>,
    /// The index of the signature this report describes (`Chosen signature`).
    ///
    /// `None` when the report has no such line, as for code signed by the linker and on macOS
    /// before 27.
    pub chosen_signature: Option<u32>,
    /// The code nested directly in a bundle, as `codesign` prints each path (`Nested`).
    ///
    /// Only [`deep`](crate::codesign::Display::deep) lists them; without it this is empty.
    pub nested: Vec<String>,
    /// The launch and library constraints the code carries.
    pub constraints: Constraints,
    /// The entitlements, or `None` if the target has none.
    ///
    /// They are read only when `codesign` runs over a single target, because over several in one
    /// run it prints entitlements that can't be matched back to their targets. With
    /// [`per_target(false)`](crate::codesign::Display::per_target) and several targets, this is
    /// `None` for all of them.
    pub entitlements: Option<plist::Dictionary>,
    raw: String,
}

impl Signature {
    /// Returns this target's report, as `codesign` printed it, minus trailing whitespace.
    ///
    /// It is the same in every run mode, whether the target ran alone or with others.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Returns the value of the first report line that reads `key=value`.
    ///
    /// The key is the text before the first `=`, with no trimming: `"Identifier"`, `"Authority"`.
    /// A key that repeats, such as `Authority`, gives its first line. It reaches lines the typed
    /// fields don't map.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign;
    ///
    /// let signature = codesign::display("mytool").await?;
    /// assert_eq!(signature.field("Identifier"), Some(signature.identifier.as_str()));
    /// # Ok(()) }
    /// ```
    pub fn field(&self, key: &str) -> Option<&str> {
        self.raw.lines().find_map(|line| {
            line.split_once('=')
                .and_then(|(k, value)| (k == key).then_some(value))
        })
    }
}

/// The kind of code a signature is on (`Format`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    /// A Mach-O for one architecture, e.g. `arm64`.
    MachOThin(String),
    /// A universal Mach-O, with its architectures in the order printed.
    MachOUniversal(Vec<String>),
    /// Any file that isn't a Mach-O, such as a script.
    Generic,
    /// A disk image.
    DiskImage,
    /// A bundle with code inside.
    #[non_exhaustive]
    Bundle {
        /// `true` for an application bundle.
        app: bool,
        /// The format of the bundle's main executable.
        executable: Box<Format>,
    },
    /// A bundle with an `Info.plist` and no executable.
    InfoPlistBundle,
    /// An installer package bundle.
    InstallerPackage,
    /// A widget bundle.
    Widget,
    /// A format this crate doesn't know, as printed.
    Other(String),
}

/// The code directory of a signature (`CodeDirectory`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeDirectory {
    /// The version of the code directory structure, e.g. `0x20400`.
    pub version: u32,
    /// The size of the code directory in bytes.
    pub size: u32,
    /// The signing flags sealed into the signature.
    ///
    /// Bits that [`SigningFlags`] has no name for are kept, such as the ad hoc bit `0x2`.
    pub flags: SigningFlags,
    /// How many hashes the code directory holds.
    pub hashes: CodeHashes,
    /// Where the signature is stored.
    pub location: Location,
}

/// How many hashes a code directory holds, as `codesign` prints them: `code+special`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeHashes {
    /// The hashes of the code pages.
    pub code: u32,
    /// The hashes of the special slots, such as the requirements and the resources.
    pub special: u32,
}

/// Where a signature is stored (`location`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// Inside the code itself, or in its extended attributes.
    Embedded,
    /// In a separate file, read with [`detached`](crate::codesign::Display::detached).
    ExplicitDetached,
    /// In the system's database of detached signatures.
    System,
    /// A location this crate doesn't know, as printed.
    Other(String),
}

/// The platform a Mach-O was built for (`VersionPlatform`).
///
/// The variants are the values of the Mach-O `PLATFORM_*` constants.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    /// macOS.
    MacOs,
    /// iOS.
    Ios,
    /// tvOS.
    TvOs,
    /// watchOS.
    WatchOs,
    /// bridgeOS.
    BridgeOs,
    /// Mac Catalyst.
    MacCatalyst,
    /// The iOS simulator.
    IosSimulator,
    /// The tvOS simulator.
    TvOsSimulator,
    /// The watchOS simulator.
    WatchOsSimulator,
    /// DriverKit.
    DriverKit,
    /// visionOS.
    VisionOs,
    /// The visionOS simulator.
    VisionOsSimulator,
    /// A platform with no variant here, by its number.
    Unknown(u32),
}

/// An OS or SDK version.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsVersion {
    /// The major version.
    pub major: u32,
    /// The minor version.
    pub minor: u32,
    /// The patch version.
    pub patch: u32,
}

/// A hash algorithm, as `codesign` names it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    /// SHA-1 (`sha1`).
    Sha1,
    /// SHA-256 (`sha256`).
    Sha256,
    /// SHA-256 cut to 20 bytes (`sha256T`).
    Sha256Truncated,
    /// SHA-384 (`sha384`).
    Sha384,
    /// An algorithm with no variant here: its name, or `UNKNOWN(n)` for one that `codesign` only
    /// numbers.
    Unknown(String),
}

/// The code directory hash for one algorithm (`CandidateCDHash`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdHash {
    /// The algorithm of the code directory this hash is of.
    pub algorithm: HashType,
    /// The hash cut to 20 bytes, in hex.
    pub truncated: String,
    /// The whole hash, in hex, when `codesign` prints it (`CandidateCDHashFull`).
    pub full: Option<String>,
}

/// The CMS digest of a signature (`CMSDigest`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmsDigest {
    /// The digest, in hex.
    pub digest: String,
    /// The number of its algorithm (`CMSDigestType`).
    pub kind: u32,
}

/// The executable segment of a Mach-O, as sealed in its code directory (`Executable Segment`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutableSegment {
    /// The segment's base, as printed.
    pub base: u64,
    /// The segment's limit, as printed.
    pub limit: u64,
    /// The segment's flags, as printed in hex.
    pub flags: u64,
}

/// How code was signed (`Signature`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureKind {
    /// An ad hoc signature, which names no signer.
    AdHoc,
    /// A signature made with a certificate.
    #[non_exhaustive]
    Certificate {
        /// The size of the signature in bytes.
        size: u32,
        /// The certificate chain, leaf first.
        authorities: Vec<Authority>,
    },
}

/// A certificate in the chain of a signature (`Authority`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    /// The certificate's common name.
    Name(String),
    /// A certificate whose name `codesign` couldn't read.
    Unavailable,
}

/// Whether a signature covers an `Info.plist` (`Info.plist`).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoPlist {
    /// The signature doesn't cover one.
    NotBound,
    /// It covers an `Info.plist` with this many entries.
    Entries(u32),
}

/// The seal over a bundle's resources (`Sealed Resources`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedResources {
    /// The version of the resource rules.
    pub version: u32,
    /// How many rules there are.
    pub rules: u32,
    /// How many files are sealed.
    pub files: u32,
}

/// How many requirements a signature embeds, and their size (`Internal requirements`).
///
/// [`requirements`](crate::codesign::requirements) reads the requirements themselves.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequirementsSummary {
    /// How many requirements there are.
    pub count: u32,
    /// Their size in bytes.
    pub size: u32,
}

bitflags! {
    /// The launch and library constraints that code carries.
    ///
    /// Check a flag with `contains`. The report says which kinds exist, not what they require.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run() -> signers::Result<()> {
    /// use signers::codesign::{self, Constraints};
    ///
    /// let signature = codesign::display("MyApp.app").await?;
    /// if signature.constraints.contains(Constraints::LAUNCH_SELF) {
    ///     println!("constrained at launch");
    /// }
    /// # Ok(()) }
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Constraints: u8 {
        /// Constraints on the process itself (`Has Self Launch Constraints`).
        const LAUNCH_SELF = 1;
        /// Constraints on its parent process (`Has Parent Launch Constraints`).
        const LAUNCH_PARENT = 1 << 1;
        /// Constraints on its responsible process (`Has Responsible Launch Constraints`).
        const LAUNCH_RESPONSIBLE = 1 << 2;
        /// Constraints on the libraries it loads (`Has Library Load Constraints`).
        const LIBRARY_LOAD = 1 << 3;
    }
}

pub(crate) fn parse_report(report: &str) -> Result<Signature, Rejection> {
    let mut executable = None;
    let mut identifier = None;
    let mut format = None;
    let mut code_directory = None;
    let mut platform_identifier = None;
    let mut library_validation_warning = None;
    let mut platform = None;
    let mut min_os = None;
    let mut sdk = None;
    let mut hash_type = None;
    let mut hash_choices = Vec::new();
    let mut cd_hashes: Vec<CdHash> = Vec::new();
    let mut cd_hash = None;
    let mut cms_digest = None;
    let mut cms_digest_type = None;
    let mut segment_base = None;
    let mut segment_limit = None;
    let mut segment_flags = None;
    let mut page_size = None;
    let mut adhoc = false;
    let mut signature_size = None;
    let mut authorities = Vec::new();
    let mut timestamp = None;
    let mut signed_time = None;
    let mut notarization_ticket = None;
    let mut info_plist = None;
    let mut team_identifier = None;
    let mut runtime_version = None;
    let mut sealed_resources = None;
    let mut internal_requirements = None;
    let mut total_signatures = None;
    let mut chosen_signature = None;
    let mut nested = Vec::new();
    let mut constraints = Constraints::empty();

    for line in report.lines() {
        let constraint = match line.trim() {
            "Has Self Launch Constraints" => Constraints::LAUNCH_SELF,
            "Has Parent Launch Constraints" => Constraints::LAUNCH_PARENT,
            "Has Responsible Launch Constraints" => Constraints::LAUNCH_RESPONSIBLE,
            "Has Library Load Constraints" => Constraints::LIBRARY_LOAD,
            _ => Constraints::empty(),
        };
        if !constraint.is_empty() {
            constraints |= constraint;
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Executable" => executable = Some(PathBuf::from(value)),
            "Identifier" => identifier = Some(value.to_owned()),
            "Format" => format = Some(Format::parse(value)),
            "CodeDirectory v" => code_directory = Some(CodeDirectory::parse(line)?),
            "Platform identifier" => platform_identifier = Some(number(line, value)?),
            "Library validation warning" => library_validation_warning = Some(value.to_owned()),
            "VersionPlatform" => platform = Some(Platform::from_raw(number(line, value)?)),
            "VersionMin" => min_os = Some(OsVersion::from_packed(number(line, value)?)),
            "VersionSDK" => sdk = Some(OsVersion::from_packed(number(line, value)?)),
            "Hash type" => {
                let name = value.split_once(' ').map_or(value, |(name, _)| name);
                hash_type = Some(HashType::parse(name));
            }
            "Hash UNKNOWN type" => hash_type = Some(HashType::Unknown(format!("UNKNOWN({value})"))),
            "Hash choices" => hash_choices = value.split(',').map(HashType::parse).collect(),
            "CMSDigest" => cms_digest = Some(value.to_owned()),
            "CMSDigestType" => cms_digest_type = Some(number(line, value)?),
            "Executable Segment base" => segment_base = Some(number(line, value)?),
            "Executable Segment limit" => segment_limit = Some(number(line, value)?),
            "Executable Segment flags" => {
                let digits = value.strip_prefix("0x").ok_or_else(|| unreadable(line))?;
                segment_flags = Some(hex(line, digits)?);
            }
            "Page size" if value == "none" => page_size = None,
            "Page size" => page_size = Some(number(line, value)?),
            "CDHash" => cd_hash = Some(value.to_owned()),
            "Signature" if value == "adhoc" => adhoc = true,
            "Signature size" => signature_size = Some(number(line, value)?),
            "Authority" if value == "(unavailable)" => authorities.push(Authority::Unavailable),
            "Authority" => authorities.push(Authority::Name(value.to_owned())),
            "Timestamp" => timestamp = Some(value.to_owned()),
            "Signed Time" => signed_time = Some(value.to_owned()),
            "Notarization Ticket" => notarization_ticket = Some(value.to_owned()),
            "Info.plist" if value == "not bound" => info_plist = Some(InfoPlist::NotBound),
            "Info.plist entries" => info_plist = Some(InfoPlist::Entries(number(line, value)?)),
            "TeamIdentifier" => team_identifier = (value != "not set").then(|| value.to_owned()),
            "Runtime Version" => runtime_version = Some(OsVersion::parse_dotted(line, value)?),
            "Sealed Resources version" => {
                sealed_resources = Some(SealedResources {
                    version: number(line, token(line, line, "version")?)?,
                    rules: number(line, token(line, line, "rules")?)?,
                    files: number(line, token(line, line, "files")?)?,
                });
            }
            "Internal requirements count" => {
                internal_requirements = Some(RequirementsSummary {
                    count: number(line, token(line, line, "count")?)?,
                    size: number(line, token(line, line, "size")?)?,
                });
            }
            "Total signatures" => total_signatures = Some(number(line, value)?),
            "Chosen signature" => chosen_signature = Some(number(line, value)?),
            "Nested" => nested.push(value.to_owned()),
            _ => {
                if let Some(algorithm) = key.strip_prefix("CandidateCDHash ") {
                    cd_hashes.push(CdHash {
                        algorithm: HashType::parse(algorithm),
                        truncated: value.to_owned(),
                        full: None,
                    });
                } else if let Some(algorithm) = key.strip_prefix("CandidateCDHashFull ") {
                    let algorithm = HashType::parse(algorithm);
                    if let Some(entry) = cd_hashes.iter_mut().find(|h| h.algorithm == algorithm) {
                        entry.full = Some(value.to_owned());
                    }
                }
            }
        }
    }

    let signature = if adhoc {
        SignatureKind::AdHoc
    } else {
        SignatureKind::Certificate {
            size: signature_size.ok_or_else(|| missing("Signature"))?,
            authorities,
        }
    };

    Ok(Signature {
        executable: executable.ok_or_else(|| missing("Executable"))?,
        identifier: identifier.ok_or_else(|| missing("Identifier"))?,
        format: format.ok_or_else(|| missing("Format"))?,
        code_directory: code_directory.ok_or_else(|| missing("CodeDirectory"))?,
        platform_identifier,
        library_validation_warning,
        platform,
        min_os,
        sdk,
        hash_type: hash_type.ok_or_else(|| missing("Hash type"))?,
        hash_choices,
        cd_hashes,
        cd_hash: cd_hash.ok_or_else(|| missing("CDHash"))?,
        cms_digest: cms_digest
            .zip(cms_digest_type)
            .map(|(digest, kind)| CmsDigest { digest, kind }),
        executable_segment: segment_base.map(|base| ExecutableSegment {
            base,
            limit: segment_limit.unwrap_or(0),
            flags: segment_flags.unwrap_or(0),
        }),
        page_size,
        signature,
        timestamp,
        signed_time,
        notarization_ticket,
        info_plist: info_plist.ok_or_else(|| missing("Info.plist"))?,
        team_identifier,
        runtime_version,
        sealed_resources,
        internal_requirements,
        total_signatures,
        chosen_signature,
        nested,
        constraints,
        entitlements: None,
        raw: report.to_owned(),
    })
}

impl Format {
    fn parse(value: &str) -> Self {
        if let Some(rest) = value.strip_prefix("app bundle with ") {
            return Self::Bundle {
                app: true,
                executable: Box::new(Self::parse(rest)),
            };
        }
        if let Some(rest) = value.strip_prefix("bundle with ") {
            return Self::Bundle {
                app: false,
                executable: Box::new(Self::parse(rest)),
            };
        }
        if let Some(arch) = value
            .strip_prefix("Mach-O thin (")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            return Self::MachOThin(arch.to_owned());
        }
        if let Some(archs) = value
            .strip_prefix("Mach-O universal (")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            return Self::MachOUniversal(archs.split_whitespace().map(str::to_owned).collect());
        }
        match value {
            "bundle" => Self::InfoPlistBundle,
            "installer package bundle" => Self::InstallerPackage,
            "widget bundle" => Self::Widget,
            "disk image" => Self::DiskImage,
            "generic" => Self::Generic,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl CodeDirectory {
    // `location` is last and may hold a space (`explicit detached`), so it's
    // split off before the rest is read as space-separated `key=value` tokens.
    fn parse(line: &str) -> Result<Self, Rejection> {
        let (head, location) = line
            .split_once(" location=")
            .ok_or_else(|| unreadable(line))?;
        let flags = token(line, head, "flags")?;
        let flags = flags
            .split_once('(')
            .map_or(flags, |(bits, _)| bits)
            .strip_prefix("0x")
            .ok_or_else(|| unreadable(line))?;
        let (code, special) = token(line, head, "hashes")?
            .split_once('+')
            .ok_or_else(|| unreadable(line))?;

        Ok(Self {
            version: hex(line, token(line, head, "v")?)?,
            size: number(line, token(line, head, "size")?)?,
            flags: SigningFlags::from_bits_retain(hex(line, flags)?),
            hashes: CodeHashes {
                code: number(line, code)?,
                special: number(line, special)?,
            },
            location: match location {
                "embedded" => Location::Embedded,
                "explicit detached" => Location::ExplicitDetached,
                "system" => Location::System,
                other => Location::Other(other.to_owned()),
            },
        })
    }
}

impl Platform {
    fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::MacOs,
            2 => Self::Ios,
            3 => Self::TvOs,
            4 => Self::WatchOs,
            5 => Self::BridgeOs,
            6 => Self::MacCatalyst,
            7 => Self::IosSimulator,
            8 => Self::TvOsSimulator,
            9 => Self::WatchOsSimulator,
            10 => Self::DriverKit,
            11 => Self::VisionOs,
            12 => Self::VisionOsSimulator,
            other => Self::Unknown(other),
        }
    }
}

impl OsVersion {
    // Mach-O packs a version as `xxxx.yy.zz` nibbles: 0x1B0000 is 27.0.0.
    fn from_packed(value: u32) -> Self {
        Self {
            major: value >> 16,
            minor: (value >> 8) & 0xff,
            patch: value & 0xff,
        }
    }

    fn parse_dotted(line: &str, value: &str) -> Result<Self, Rejection> {
        let mut parts = value.split('.');
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(unreadable(line));
        };
        Ok(Self {
            major: number(line, major)?,
            minor: number(line, minor)?,
            patch: number(line, patch)?,
        })
    }
}

impl HashType {
    fn parse(name: &str) -> Self {
        match name {
            "sha1" => Self::Sha1,
            "sha256" => Self::Sha256,
            "sha256T" => Self::Sha256Truncated,
            "sha384" => Self::Sha384,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

fn token<'a>(line: &str, text: &'a str, key: &str) -> Result<&'a str, Rejection> {
    text.split_whitespace()
        .find_map(|token| {
            token
                .split_once('=')
                .and_then(|(k, value)| (k == key).then_some(value))
        })
        .ok_or_else(|| unreadable(line))
}

fn number<T: FromStr>(line: &str, value: &str) -> Result<T, Rejection> {
    value.parse().map_err(|_| unreadable(line))
}

fn hex<T: TryFrom<u64>>(line: &str, digits: &str) -> Result<T, Rejection> {
    u64::from_str_radix(digits, 16)
        .ok()
        .and_then(|value| T::try_from(value).ok())
        .ok_or_else(|| unreadable(line))
}

fn unreadable(line: &str) -> Rejection {
    Rejection::Unreadable(format!("unreadable report line {line:?}"))
}

fn missing(key: &str) -> Rejection {
    Rejection::Unreadable(format!("the report has no {key} line"))
}

#[cfg(test)]
#[path = "../unit_tests/signature.rs"]
mod tests;
