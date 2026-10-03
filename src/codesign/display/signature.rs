use std::path::PathBuf;
use std::str::FromStr;

use bitflags::bitflags;

use crate::codesign::sign::SigningFlags;
use crate::errors::{CodesignError, Error, Result};

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct Signature {
    pub executable: PathBuf,
    pub identifier: String,
    pub format: Format,
    pub code_directory: CodeDirectory,
    pub platform_identifier: Option<u32>,
    pub library_validation_warning: Option<String>,
    pub platform: Option<Platform>,
    pub min_os: Option<OsVersion>,
    pub sdk: Option<OsVersion>,
    pub hash_type: HashType,
    pub hash_choices: Vec<HashType>,
    pub cd_hashes: Vec<CdHash>,
    pub cd_hash: String,
    pub cms_digest: Option<CmsDigest>,
    pub executable_segment: Option<ExecutableSegment>,
    pub page_size: Option<u32>,
    pub signature: SignatureKind,
    pub timestamp: Option<String>,
    pub signed_time: Option<String>,
    pub notarization_ticket: Option<String>,
    pub info_plist: InfoPlist,
    pub team_identifier: Option<String>,
    pub runtime_version: Option<OsVersion>,
    pub sealed_resources: Option<SealedResources>,
    pub internal_requirements: Option<InternalRequirements>,
    pub total_signatures: u32,
    pub chosen_signature: u32,
    pub nested: Vec<String>,
    pub constraints: Constraints,
    pub entitlements: Option<plist::Dictionary>,
    raw: String,
}

impl Signature {
    pub fn raw(&self) -> &str {
        &self.raw
    }

    pub fn field(&self, key: &str) -> Option<&str> {
        self.raw.lines().find_map(|line| {
            line.split_once('=')
                .and_then(|(k, value)| (k == key).then_some(value))
        })
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Format {
    MachOThin(String),
    MachOUniversal(Vec<String>),
    Generic,
    DiskImage,
    Bundle { app: bool, executable: Box<Format> },
    InfoPlistBundle,
    InstallerPackage,
    Widget,
    Other(String),
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeDirectory {
    pub version: u32,
    pub size: u32,
    pub flags: SigningFlags,
    pub hashes: CodeHashes,
    pub location: Location,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeHashes {
    pub code: u32,
    pub special: u32,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    Embedded,
    ExplicitDetached,
    System,
    Other(String),
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Ios,
    TvOs,
    WatchOs,
    BridgeOs,
    MacCatalyst,
    IosSimulator,
    TvOsSimulator,
    WatchOsSimulator,
    DriverKit,
    VisionOs,
    VisionOsSimulator,
    Unknown(u32),
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OsVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    Sha1,
    Sha256,
    Sha256Truncated,
    Sha384,
    Unknown(String),
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdHash {
    pub algorithm: HashType,
    pub truncated: String,
    pub full: Option<String>,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmsDigest {
    pub digest: String,
    pub kind: u32,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutableSegment {
    pub base: u64,
    pub limit: u64,
    pub flags: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureKind {
    AdHoc,
    Certificate {
        size: u32,
        authorities: Vec<Authority>,
    },
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authority {
    Name(String),
    Unavailable,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoPlist {
    NotBound,
    Entries(u32),
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedResources {
    pub version: u32,
    pub rules: u32,
    pub files: u32,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalRequirements {
    pub count: u32,
    pub size: u32,
}

bitflags! {
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Constraints: u8 {
        const LAUNCH_SELF = 1;
        const LAUNCH_PARENT = 1 << 1;
        const LAUNCH_RESPONSIBLE = 1 << 2;
        const LIBRARY_LOAD = 1 << 3;
    }
}

pub(crate) fn parse_report(report: &str) -> Result<Signature> {
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
                internal_requirements = Some(InternalRequirements {
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
        total_signatures: total_signatures.ok_or_else(|| missing("Total signatures"))?,
        chosen_signature: chosen_signature.ok_or_else(|| missing("Chosen signature"))?,
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
    fn parse(line: &str) -> Result<Self> {
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

    fn parse_dotted(line: &str, value: &str) -> Result<Self> {
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

fn token<'a>(line: &str, text: &'a str, key: &str) -> Result<&'a str> {
    text.split_whitespace()
        .find_map(|token| {
            token
                .split_once('=')
                .and_then(|(k, value)| (k == key).then_some(value))
        })
        .ok_or_else(|| unreadable(line))
}

fn number<T: FromStr>(line: &str, value: &str) -> Result<T> {
    value.parse().map_err(|_| unreadable(line))
}

fn hex<T: TryFrom<u64>>(line: &str, digits: &str) -> Result<T> {
    u64::from_str_radix(digits, 16)
        .ok()
        .and_then(|value| T::try_from(value).ok())
        .ok_or_else(|| unreadable(line))
}

fn unreadable(line: &str) -> Error {
    CodesignError::UnexpectedOutput {
        detail: format!("unreadable report line {line:?}"),
    }
    .into()
}

fn missing(key: &str) -> Error {
    CodesignError::UnexpectedOutput {
        detail: format!("the report has no {key} line"),
    }
    .into()
}
