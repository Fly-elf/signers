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
    pub total_signatures: Option<u32>,
    pub chosen_signature: Option<u32>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `codesign -dvvvv` on a binary signed ad hoc, as printed on macOS 27.
    const ADHOC: &str = "\
Executable=/private/tmp/t004/h2
Identifier=h2-5555494416e8fd0ab7a931b481ae3e72480a7086
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=292 flags=0x2(adhoc) hashes=3+2 location=embedded
VersionPlatform=1
VersionMin=1769472
VersionSDK=1769472
Hash type=sha256 size=32
CandidateCDHash sha256=da0bf9309ef3710b135a2955182029a928202e55
CandidateCDHashFull sha256=da0bf9309ef3710b135a2955182029a928202e55930112123c6f95077e5d3ca8
Hash choices=sha256
CMSDigest=da0bf9309ef3710b135a2955182029a928202e55930112123c6f95077e5d3ca8
CMSDigestType=2
Executable Segment base=0
Executable Segment limit=16384
Executable Segment flags=0x1
Page size=16384
CDHash=da0bf9309ef3710b135a2955182029a928202e55
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=0 size=12
Total signatures=1
Chosen signature=1
";

    /// `codesign -dvvvv /bin/ls` on macOS 27: Apple-signed, universal.
    const APPLE: &str = "\
Executable=/bin/ls
Identifier=com.apple.ls
Format=Mach-O universal (x86_64 arm64e arm64e.x1)
CodeDirectory v=20400 size=325 flags=0x0(none) hashes=5+2 location=embedded
Platform identifier=26
VersionPlatform=1
VersionMin=720896
VersionSDK=1769472
Hash type=sha256 size=32
CandidateCDHash sha256=45d1613a435c6cb05794cbb585587a5245989943
CandidateCDHashFull sha256=45d1613a435c6cb05794cbb585587a5245989943ad1999f183d0f165a4750244
Hash choices=sha256
CMSDigest=45d1613a435c6cb05794cbb585587a5245989943ad1999f183d0f165a4750244
CMSDigestType=2
Executable Segment base=0
Executable Segment limit=32768
Executable Segment flags=0x1
Page size=16384
CDHash=45d1613a435c6cb05794cbb585587a5245989943
Signature size=4202
Authority=macOS Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
Signed Time=8 Aug 2026 at 22:31:18
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements count=1 size=60
Total signatures=1
Chosen signature=1
";

    fn parsed(report: &str) -> Signature {
        parse_report(report).unwrap_or_else(|e| panic!("{e}\nin report:\n{report}"))
    }

    /// The `detail` of the `UnexpectedOutput` that parsing `report` must fail with.
    fn rejection(report: &str) -> String {
        match parse_report(report) {
            Err(Error::Codesign(CodesignError::UnexpectedOutput { detail })) => detail,
            other => panic!("expected UnexpectedOutput, got {other:?}\nfor report:\n{report}"),
        }
    }

    /// `base` with every line starting with `prefix` dropped.
    fn without(base: &str, prefix: &str) -> String {
        base.lines()
            .filter(|line| !line.starts_with(prefix))
            .map(|line| format!("{line}\n"))
            .collect()
    }

    /// `base` with every line starting with `prefix` replaced by `lines`
    /// (several lines allowed), or `lines` appended if no line matched.
    fn replacing(base: &str, prefix: &str, lines: &str) -> String {
        let mut out = String::new();
        let mut replaced = false;
        for line in base.lines() {
            if line.starts_with(prefix) {
                if !replaced {
                    out.push_str(lines);
                    out.push('\n');
                    replaced = true;
                }
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        if !replaced {
            out.push_str(lines);
            out.push('\n');
        }
        out
    }

    #[test]
    fn an_ad_hoc_report_maps_every_line() {
        let expected = Signature {
            executable: PathBuf::from("/private/tmp/t004/h2"),
            identifier: "h2-5555494416e8fd0ab7a931b481ae3e72480a7086".into(),
            format: Format::MachOThin("arm64".into()),
            code_directory: CodeDirectory {
                version: 0x20400,
                size: 292,
                flags: SigningFlags::from_bits_retain(0x2),
                hashes: CodeHashes {
                    code: 3,
                    special: 2,
                },
                location: Location::Embedded,
            },
            platform_identifier: None,
            library_validation_warning: None,
            platform: Some(Platform::MacOs),
            min_os: Some(OsVersion {
                major: 27,
                minor: 0,
                patch: 0,
            }),
            sdk: Some(OsVersion {
                major: 27,
                minor: 0,
                patch: 0,
            }),
            hash_type: HashType::Sha256,
            hash_choices: vec![HashType::Sha256],
            cd_hashes: vec![CdHash {
                algorithm: HashType::Sha256,
                truncated: "da0bf9309ef3710b135a2955182029a928202e55".into(),
                full: Some(
                    "da0bf9309ef3710b135a2955182029a928202e55930112123c6f95077e5d3ca8".into(),
                ),
            }],
            cd_hash: "da0bf9309ef3710b135a2955182029a928202e55".into(),
            cms_digest: Some(CmsDigest {
                digest: "da0bf9309ef3710b135a2955182029a928202e55930112123c6f95077e5d3ca8".into(),
                kind: 2,
            }),
            executable_segment: Some(ExecutableSegment {
                base: 0,
                limit: 16384,
                flags: 1,
            }),
            page_size: Some(16384),
            signature: SignatureKind::AdHoc,
            timestamp: None,
            signed_time: None,
            notarization_ticket: None,
            info_plist: InfoPlist::NotBound,
            team_identifier: None,
            runtime_version: None,
            sealed_resources: None,
            internal_requirements: Some(InternalRequirements { count: 0, size: 12 }),
            total_signatures: Some(1),
            chosen_signature: Some(1),
            nested: vec![],
            constraints: Constraints::empty(),
            entitlements: None,
            raw: ADHOC.into(),
        };

        assert_eq!(parsed(ADHOC), expected);
    }

    #[test]
    fn an_apple_signed_report_maps_every_line() {
        let signature = parsed(APPLE);

        assert_eq!(signature.executable, PathBuf::from("/bin/ls"));
        assert_eq!(signature.identifier, "com.apple.ls");
        assert_eq!(
            signature.format,
            Format::MachOUniversal(vec!["x86_64".into(), "arm64e".into(), "arm64e.x1".into()])
        );
        assert_eq!(signature.code_directory.flags, SigningFlags::empty());
        assert_eq!(signature.platform_identifier, Some(26));
        assert_eq!(
            signature.min_os,
            Some(OsVersion {
                major: 11,
                minor: 0,
                patch: 0
            })
        );
        assert_eq!(
            signature.signature,
            SignatureKind::Certificate {
                size: 4202,
                authorities: vec![
                    Authority::Name("macOS Software Signing".into()),
                    Authority::Name("Apple Code Signing Certification Authority".into()),
                    Authority::Name("Apple Root CA".into()),
                ],
            }
        );
        assert_eq!(
            signature.signed_time.as_deref(),
            Some("8 Aug 2026 at 22:31:18")
        );
        assert_eq!(signature.timestamp, None);
        assert_eq!(
            signature.internal_requirements,
            Some(InternalRequirements { count: 1, size: 60 })
        );
    }

    #[test]
    fn the_format_line_follows_the_security_framework_grammar() {
        let thin = |arch: &str| Format::MachOThin(arch.into());
        let cases = [
            ("Mach-O thin (arm64)", thin("arm64")),
            ("Mach-O thin (arm64e.x1)", thin("arm64e.x1")),
            (
                "Mach-O universal (x86_64 arm64)",
                Format::MachOUniversal(vec!["x86_64".into(), "arm64".into()]),
            ),
            ("generic", Format::Generic),
            ("disk image", Format::DiskImage),
            (
                "app bundle with Mach-O thin (x86_64)",
                Format::Bundle {
                    app: true,
                    executable: Box::new(thin("x86_64")),
                },
            ),
            (
                "app bundle with Mach-O universal (arm64e arm64e.x1)",
                Format::Bundle {
                    app: true,
                    executable: Box::new(Format::MachOUniversal(vec![
                        "arm64e".into(),
                        "arm64e.x1".into(),
                    ])),
                },
            ),
            (
                "bundle with generic",
                Format::Bundle {
                    app: false,
                    executable: Box::new(Format::Generic),
                },
            ),
            (
                "bundle with Mach-O (unrecognized format)",
                Format::Bundle {
                    app: false,
                    executable: Box::new(Format::Other("Mach-O (unrecognized format)".into())),
                },
            ),
            ("bundle", Format::InfoPlistBundle),
            ("installer package bundle", Format::InstallerPackage),
            ("widget bundle", Format::Widget),
            (
                "Mach-O (unrecognized format)",
                Format::Other("Mach-O (unrecognized format)".into()),
            ),
            (
                "OS X Shared Library Cache (arm64e)",
                Format::Other("OS X Shared Library Cache (arm64e)".into()),
            ),
        ];

        for (value, format) in cases {
            let report = replacing(ADHOC, "Format=", &format!("Format={value}"));
            assert_eq!(parsed(&report).format, format, "Format={value}");
        }
    }

    #[test]
    fn the_code_directory_version_is_hexadecimal_and_unknown_flag_bits_are_kept() {
        let report = replacing(
            ADHOC,
            "CodeDirectory ",
            "CodeDirectory v=20500 size=560 flags=0x30002(adhoc,linker-signed,runtime) hashes=103+7 location=embedded",
        );

        let directory = parsed(&report).code_directory;

        assert_eq!(directory.version, 0x20500);
        assert_eq!(directory.size, 560);
        assert_eq!(directory.flags.bits(), 0x30002);
        assert_eq!(
            directory.hashes,
            CodeHashes {
                code: 103,
                special: 7
            }
        );
    }

    #[test]
    fn the_code_directory_location_takes_the_rest_of_the_line() {
        let cases = [
            ("embedded", Location::Embedded),
            ("explicit detached", Location::ExplicitDetached),
            ("system", Location::System),
            ("unsigned", Location::Other("unsigned".into())),
            ("somewhere else", Location::Other("somewhere else".into())),
        ];

        for (value, location) in cases {
            let line = format!(
                "CodeDirectory v=20400 size=292 flags=0x2(adhoc) hashes=3+2 location={value}"
            );
            let report = replacing(ADHOC, "CodeDirectory ", &line);
            assert_eq!(parsed(&report).code_directory.location, location, "{line}");
        }
    }

    #[test]
    fn a_malformed_code_directory_is_rejected() {
        let lines = [
            "CodeDirectory v=zz size=292 flags=0x2(adhoc) hashes=3+2 location=embedded",
            "CodeDirectory v=20400 size=big flags=0x2(adhoc) hashes=3+2 location=embedded",
            "CodeDirectory v=20400 size=292 flags=2(adhoc) hashes=3+2 location=embedded",
            "CodeDirectory v=20400 size=292 flags=0xq(adhoc) hashes=3+2 location=embedded",
            "CodeDirectory v=20400 size=292 flags=0x2(adhoc) hashes=3 location=embedded",
            "CodeDirectory v=20400 size=292 flags=0x2(adhoc) hashes=3+x location=embedded",
            "CodeDirectory v=20400 flags=0x2(adhoc) hashes=3+2 location=embedded",
            "CodeDirectory v=20400 size=292 flags=0x2(adhoc) hashes=3+2",
            "CodeDirectory size=292 flags=0x2(adhoc) hashes=3+2 location=embedded",
        ];

        for line in lines {
            let detail = rejection(&replacing(ADHOC, "CodeDirectory ", line));
            assert!(detail.contains("CodeDirectory"), "{line}: {detail}");
        }
    }

    #[test]
    fn every_version_platform_number_maps_to_its_platform() {
        let cases = [
            (0, Platform::Unknown(0)),
            (1, Platform::MacOs),
            (2, Platform::Ios),
            (3, Platform::TvOs),
            (4, Platform::WatchOs),
            (5, Platform::BridgeOs),
            (6, Platform::MacCatalyst),
            (7, Platform::IosSimulator),
            (8, Platform::TvOsSimulator),
            (9, Platform::WatchOsSimulator),
            (10, Platform::DriverKit),
            (11, Platform::VisionOs),
            (12, Platform::VisionOsSimulator),
            (13, Platform::Unknown(13)),
            (24, Platform::Unknown(24)),
        ];

        for (number, platform) in cases {
            let report = replacing(
                ADHOC,
                "VersionPlatform=",
                &format!("VersionPlatform={number}"),
            );
            assert_eq!(
                parsed(&report).platform,
                Some(platform),
                "VersionPlatform={number}"
            );
        }
    }

    #[test]
    fn os_versions_are_unpacked_from_their_nibble_encoding() {
        let version = |major, minor, patch| OsVersion {
            major,
            minor,
            patch,
        };
        let cases = [
            (1769472, version(27, 0, 0)),
            (720896, version(11, 0, 0)),
            (0x000A_0F03, version(10, 15, 3)),
            (0, version(0, 0, 0)),
        ];

        for (packed, expected) in cases {
            let report = replacing(ADHOC, "VersionMin=", &format!("VersionMin={packed}"));
            let report = replacing(&report, "VersionSDK=", &format!("VersionSDK={packed}"));
            let signature = parsed(&report);
            assert_eq!(signature.min_os, Some(expected), "VersionMin={packed}");
            assert_eq!(signature.sdk, Some(expected), "VersionSDK={packed}");
        }
    }

    #[test]
    fn hash_names_map_to_hash_types() {
        let cases = [
            ("sha1", HashType::Sha1),
            ("sha256", HashType::Sha256),
            ("sha256T", HashType::Sha256Truncated),
            ("sha384", HashType::Sha384),
            ("sha512", HashType::Unknown("sha512".into())),
            ("UNKNOWN(9)", HashType::Unknown("UNKNOWN(9)".into())),
        ];

        for (name, hash) in cases {
            let report = replacing(ADHOC, "Hash type=", &format!("Hash type={name} size=32"));
            let report = replacing(&report, "Hash choices=", &format!("Hash choices={name}"));
            let signature = parsed(&report);
            assert_eq!(signature.hash_type, hash, "Hash type={name}");
            assert_eq!(signature.hash_choices, [hash], "Hash choices={name}");
        }
    }

    #[test]
    fn an_unknown_hash_type_keeps_its_number() {
        let report = replacing(ADHOC, "Hash type=", "Hash UNKNOWN type=7");

        assert_eq!(
            parsed(&report).hash_type,
            HashType::Unknown("UNKNOWN(7)".into())
        );
    }

    #[test]
    fn hash_choices_keep_their_printed_order() {
        let report = replacing(ADHOC, "Hash choices=", "Hash choices=sha256,sha1,sha384");

        assert_eq!(
            parsed(&report).hash_choices,
            [HashType::Sha256, HashType::Sha1, HashType::Sha384]
        );
    }

    #[test]
    fn one_cd_hash_per_algorithm_in_printed_order() {
        let report = replacing(
            ADHOC,
            "CandidateCDHash",
            "CandidateCDHash sha1=401e\nCandidateCDHashFull sha1=401e\n\
             CandidateCDHash sha256=fa17\nCandidateCDHashFull sha256=fa17d5f7",
        );

        assert_eq!(
            parsed(&report).cd_hashes,
            [
                CdHash {
                    algorithm: HashType::Sha1,
                    truncated: "401e".into(),
                    full: Some("401e".into()),
                },
                CdHash {
                    algorithm: HashType::Sha256,
                    truncated: "fa17".into(),
                    full: Some("fa17d5f7".into()),
                },
            ]
        );
    }

    #[test]
    fn a_cd_hash_without_its_full_line_has_no_full_digest() {
        let report = without(ADHOC, "CandidateCDHashFull ");

        assert_eq!(
            parsed(&report).cd_hashes,
            [CdHash {
                algorithm: HashType::Sha256,
                truncated: "da0bf9309ef3710b135a2955182029a928202e55".into(),
                full: None,
            }]
        );
    }

    #[test]
    fn a_full_cd_hash_with_no_candidate_of_its_algorithm_is_ignored() {
        let report = replacing(
            ADHOC,
            "CandidateCDHashFull ",
            "CandidateCDHashFull sha384=abcd",
        );

        let cd_hashes = parsed(&report).cd_hashes;

        assert_eq!(cd_hashes.len(), 1, "{cd_hashes:?}");
        assert_eq!(cd_hashes[0].algorithm, HashType::Sha256);
        assert_eq!(cd_hashes[0].full, None);
    }

    #[test]
    fn the_cms_digest_needs_both_its_lines() {
        assert_eq!(parsed(&without(ADHOC, "CMSDigestType=")).cms_digest, None);
        assert_eq!(parsed(&without(ADHOC, "CMSDigest=")).cms_digest, None);
    }

    #[test]
    fn the_executable_segment_is_set_by_its_base_line() {
        let segment = |lines: &str| {
            let report = replacing(ADHOC, "Executable Segment ", lines);
            parsed(&report).executable_segment
        };

        assert_eq!(
            segment(
                "Executable Segment base=4096\nExecutable Segment limit=1310720\nExecutable Segment flags=0x1f"
            ),
            Some(ExecutableSegment {
                base: 4096,
                limit: 1310720,
                flags: 0x1f
            })
        );
        assert_eq!(
            segment("Executable Segment base=18446744073709551615"),
            Some(ExecutableSegment {
                base: u64::MAX,
                limit: 0,
                flags: 0
            })
        );
        assert_eq!(
            segment("Executable Segment limit=16384\nExecutable Segment flags=0x1"),
            None
        );
        assert_eq!(
            parsed(&without(ADHOC, "Executable Segment ")).executable_segment,
            None
        );
    }

    #[test]
    fn a_page_size_of_none_is_no_page_size() {
        assert_eq!(
            parsed(&replacing(ADHOC, "Page size=", "Page size=none")).page_size,
            None
        );
        assert_eq!(
            parsed(&replacing(ADHOC, "Page size=", "Page size=4096")).page_size,
            Some(4096)
        );
    }

    #[test]
    fn an_unavailable_authority_keeps_its_place() {
        let report = replacing(
            APPLE,
            "Authority=",
            "Authority=Developer ID Application: Someone (TEAM123456)\nAuthority=(unavailable)\nAuthority=Apple Root CA",
        );

        assert_eq!(
            parsed(&report).signature,
            SignatureKind::Certificate {
                size: 4202,
                authorities: vec![
                    Authority::Name("Developer ID Application: Someone (TEAM123456)".into()),
                    Authority::Unavailable,
                    Authority::Name("Apple Root CA".into()),
                ],
            }
        );
    }

    #[test]
    fn a_certificate_signature_may_list_no_authority() {
        let report = without(APPLE, "Authority=");

        assert_eq!(
            parsed(&report).signature,
            SignatureKind::Certificate {
                size: 4202,
                authorities: vec![]
            }
        );
    }

    #[test]
    fn dates_and_notarization_are_kept_verbatim() {
        let report = replacing(
            APPLE,
            "Signed Time=",
            "Timestamp=Aug 8, 2026 at 22:31:18\nSigned Time=8 Aug 2026 at 22:31:18\nNotarization Ticket=stapled",
        );

        let signature = parsed(&report);

        assert_eq!(
            signature.timestamp.as_deref(),
            Some("Aug 8, 2026 at 22:31:18")
        );
        assert_eq!(
            signature.signed_time.as_deref(),
            Some("8 Aug 2026 at 22:31:18")
        );
        assert_eq!(signature.notarization_ticket.as_deref(), Some("stapled"));
    }

    #[test]
    fn info_plist_is_either_not_bound_or_a_count_of_entries() {
        assert_eq!(parsed(ADHOC).info_plist, InfoPlist::NotBound);
        assert_eq!(
            parsed(&replacing(ADHOC, "Info.plist", "Info.plist entries=35")).info_plist,
            InfoPlist::Entries(35)
        );
    }

    #[test]
    fn a_team_identifier_that_is_not_set_is_none() {
        assert_eq!(parsed(ADHOC).team_identifier, None);
        assert_eq!(
            parsed(&without(ADHOC, "TeamIdentifier=")).team_identifier,
            None
        );
        assert_eq!(
            parsed(&replacing(
                ADHOC,
                "TeamIdentifier=",
                "TeamIdentifier=TEAM123456"
            ))
            .team_identifier
            .as_deref(),
            Some("TEAM123456")
        );
    }

    #[test]
    fn the_runtime_version_is_dotted() {
        let report = replacing(ADHOC, "Runtime Version=", "Runtime Version=14.2.1");

        assert_eq!(
            parsed(&report).runtime_version,
            Some(OsVersion {
                major: 14,
                minor: 2,
                patch: 1
            })
        );
        assert_eq!(parsed(ADHOC).runtime_version, None);
    }

    #[test]
    fn sealed_resources_are_none_or_three_counts() {
        assert_eq!(parsed(ADHOC).sealed_resources, None);
        assert_eq!(
            parsed(&without(ADHOC, "Sealed Resources")).sealed_resources,
            None
        );
        assert_eq!(
            parsed(&replacing(
                ADHOC,
                "Sealed Resources",
                "Sealed Resources version=2 rules=13 files=4853"
            ))
            .sealed_resources,
            Some(SealedResources {
                version: 2,
                rules: 13,
                files: 4853
            })
        );
    }

    #[test]
    fn internal_requirements_are_none_or_a_count_and_size() {
        assert_eq!(
            parsed(&replacing(
                ADHOC,
                "Internal requirements",
                "Internal requirements=none"
            ))
            .internal_requirements,
            None
        );
        assert_eq!(
            parsed(&without(ADHOC, "Internal requirements")).internal_requirements,
            None
        );
        assert_eq!(
            parsed(&replacing(
                ADHOC,
                "Internal requirements",
                "Internal requirements count=2 size=176"
            ))
            .internal_requirements,
            Some(InternalRequirements {
                count: 2,
                size: 176
            })
        );
    }

    #[test]
    fn optional_scalar_lines_are_mapped() {
        let report = replacing(
            ADHOC,
            "VersionPlatform=",
            "Platform identifier=26\nLibrary validation warning=OS X SDK version before 10.9 does not support Library Validation\nVersionPlatform=1",
        );

        let signature = parsed(&report);

        assert_eq!(signature.platform_identifier, Some(26));
        assert_eq!(
            signature.library_validation_warning.as_deref(),
            Some("OS X SDK version before 10.9 does not support Library Validation")
        );
    }

    #[test]
    fn version_lines_are_optional() {
        let report = without(&without(ADHOC, "Version"), "Executable Segment ");

        let signature = parsed(&report);

        assert_eq!(
            (signature.platform, signature.min_os, signature.sdk),
            (None, None, None)
        );
    }

    #[test]
    fn nested_code_keeps_its_order() {
        let report = format!(
            "{ADHOC}Nested=Frameworks/B.framework\nNested=Frameworks/A.framework\nNested=PlugIns/x y.appex\n"
        );

        assert_eq!(
            parsed(&report).nested,
            [
                "Frameworks/B.framework",
                "Frameworks/A.framework",
                "PlugIns/x y.appex"
            ]
        );
    }

    #[test]
    fn each_constraint_line_sets_its_bit() {
        let cases = [
            ("Has Self Launch Constraints", Constraints::LAUNCH_SELF),
            ("Has Parent Launch Constraints", Constraints::LAUNCH_PARENT),
            (
                "Has Responsible Launch Constraints",
                Constraints::LAUNCH_RESPONSIBLE,
            ),
            ("Has Library Load Constraints", Constraints::LIBRARY_LOAD),
        ];

        for (line, bit) in cases {
            // As printed: tab-indented under a section header.
            let report = format!("{ADHOC}Launch Constraints:\n\t{line}\n");
            assert_eq!(parsed(&report).constraints, bit, "{line}");
            let report = format!("{ADHOC}{line}\n");
            assert_eq!(parsed(&report).constraints, bit, "{line}");
        }

        let all = cases
            .iter()
            .map(|(line, _)| format!("\t{line}\n"))
            .collect::<String>();
        assert_eq!(
            parsed(&format!("{ADHOC}{all}")).constraints,
            Constraints::all()
        );
    }

    #[test]
    fn unknown_lines_are_ignored() {
        let noise = "\
preamble without any equals sign

    -2=0000000000000000000000000000000000000000000000000000000000000000
ScatterVector count=2
Brand New Key=value
Launch Constraints:
Has Some Future Constraints
\t[Dict]
\t\t[Key] ccat
\t\t[Value]
\t\t\t[Int] 0
";
        let report = format!(
            "{}{noise}{}",
            &ADHOC[..ADHOC.find("Page size").unwrap()],
            &ADHOC[ADHOC.find("Page size").unwrap()..]
        );

        let mut signature = parsed(&report);
        let mut expected = parsed(ADHOC);
        signature.raw.clear();
        expected.raw.clear();

        assert_eq!(signature, expected);
    }

    #[test]
    fn a_missing_required_line_is_rejected_by_name() {
        let required = [
            ("Executable=", "Executable"),
            ("Identifier=", "Identifier"),
            ("Format=", "Format"),
            ("CodeDirectory ", "CodeDirectory"),
            ("Hash type=", "Hash type"),
            ("CDHash=", "CDHash"),
            ("Signature=", "Signature"),
            ("Info.plist", "Info.plist"),
        ];

        for (prefix, key) in required {
            let detail = rejection(&without(ADHOC, prefix));
            assert!(detail.contains(key), "without {key}: {detail}");
        }

        let detail = rejection(&without(&without(APPLE, "Signature size="), "Authority="));
        assert!(detail.contains("Signature"), "{detail}");
    }

    /// `codesign -dvvvv` on fresh `cc` output: no signature count lines.
    #[test]
    fn a_linker_signed_report_has_no_signature_counts() {
        let report = without(&without(ADHOC, "Total signatures="), "Chosen signature=")
            .replace("flags=0x2(adhoc)", "flags=0x20002(adhoc,linker-signed)")
            .replace(
                "Internal requirements count=0 size=12",
                "Internal requirements=none",
            );

        let signature = parsed(&report);

        assert_eq!(signature.total_signatures, None);
        assert_eq!(signature.chosen_signature, None);
        assert_eq!(signature.internal_requirements, None);
        assert_eq!(parsed(ADHOC).total_signatures, Some(1));
        assert_eq!(parsed(ADHOC).chosen_signature, Some(1));
    }

    #[test]
    fn values_outside_the_known_forms_do_not_fill_a_required_line() {
        let cases = [
            ("Signature=", "Signature=detached"),
            ("Info.plist", "Info.plist=bound"),
        ];

        for (prefix, line) in cases {
            let detail = rejection(&replacing(ADHOC, prefix, line));
            assert!(
                detail.contains(prefix.trim_end_matches('=')),
                "{line}: {detail}"
            );
        }
    }

    #[test]
    fn an_empty_report_is_rejected() {
        rejection("");
    }

    #[test]
    fn a_mapped_line_with_an_unreadable_value_is_rejected_naming_it() {
        let cases = [
            ("Platform identifier=", "Platform identifier=twenty"),
            ("VersionPlatform=", "VersionPlatform=-1"),
            ("VersionMin=", "VersionMin=27.0"),
            ("VersionSDK=", "VersionSDK=x"),
            ("CMSDigestType=", "CMSDigestType=two"),
            ("Executable Segment base=", "Executable Segment base=zero"),
            ("Executable Segment limit=", "Executable Segment limit=-5"),
            ("Executable Segment flags=", "Executable Segment flags=0xzz"),
            ("Executable Segment flags=", "Executable Segment flags=1"),
            ("Page size=", "Page size=16k"),
            ("Info.plist", "Info.plist entries=many"),
            ("Runtime Version=", "Runtime Version=14.2"),
            ("Runtime Version=", "Runtime Version=14.x.1"),
            (
                "Sealed Resources",
                "Sealed Resources version=2 rules=x files=4",
            ),
            ("Sealed Resources", "Sealed Resources version=2 rules=13"),
            ("Internal requirements", "Internal requirements count=1"),
            (
                "Internal requirements",
                "Internal requirements count=one size=60",
            ),
            ("Total signatures=", "Total signatures=-1"),
            ("Chosen signature=", "Chosen signature=first"),
        ];

        for (prefix, line) in cases {
            let detail = rejection(&replacing(ADHOC, prefix, line));
            assert!(detail.contains(line), "{line}: {detail}");
        }

        let detail = rejection(&replacing(APPLE, "Signature size=", "Signature size=big"));
        assert!(detail.contains("Signature size=big"), "{detail}");
    }

    #[test]
    fn a_repeated_line_keeps_its_last_value_while_field_returns_the_first() {
        let report = format!("{ADHOC}Identifier=com.example.second\nPage size=4096\n");

        let signature = parsed(&report);

        assert_eq!(signature.identifier, "com.example.second");
        assert_eq!(signature.page_size, Some(4096));
        assert_eq!(
            signature.field("Identifier"),
            Some("h2-5555494416e8fd0ab7a931b481ae3e72480a7086")
        );
    }

    #[test]
    fn raw_is_the_report_as_given() {
        assert_eq!(parsed(ADHOC).raw(), ADHOC);
        assert_eq!(parsed(APPLE).raw(), APPLE);
    }

    #[test]
    fn field_matches_the_whole_key_and_splits_at_the_first_equals_sign() {
        let report = format!("{ADHOC}Has Self Launch Constraints\nWeird=a=b\n");
        let signature = parsed(&report);

        let cases = [
            ("Executable", Some("/private/tmp/t004/h2")),
            ("Executable Segment limit", Some("16384")),
            ("Executable Segment", None),
            (
                "Identifier",
                Some("h2-5555494416e8fd0ab7a931b481ae3e72480a7086"),
            ),
            ("identifier", None),
            ("Ident", None),
            (
                "CandidateCDHash sha256",
                Some("da0bf9309ef3710b135a2955182029a928202e55"),
            ),
            ("Sealed Resources", Some("none")),
            ("Internal requirements", None),
            ("Weird", Some("a=b")),
            ("Has Self Launch Constraints", None),
            ("", None),
        ];

        for (key, value) in cases {
            assert_eq!(signature.field(key), value, "field({key:?})");
        }
    }
}
