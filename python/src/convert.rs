use pyo3::IntoPyObjectExt;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use signers::codesign::{
    Authority, CdHash, CodeDirectory, Format, HashType, InfoPlist, Location, OsVersion, Platform,
    Signature, SignatureKind,
};

fn unsupported(what: &str) -> PyErr {
    PyValueError::new_err(format!("unsupported {what}"))
}

fn other<'py>(py: Python<'py>, value: impl IntoPyObject<'py>) -> PyResult<Bound<'py, PyAny>> {
    let d = PyDict::new(py);
    d.set_item("other", value)?;
    Ok(d.into_any())
}

fn named<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
    name.into_bound_py_any(py)
}

fn list<'py, T>(
    py: Python<'py>,
    items: &[T],
    f: impl Fn(Python<'py>, &T) -> PyResult<Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyList>> {
    let out = PyList::empty(py);
    for item in items {
        out.append(f(py, item)?)?;
    }
    Ok(out)
}

fn opt<'py, T>(
    py: Python<'py>,
    value: Option<&T>,
    f: impl Fn(Python<'py>, &T) -> PyResult<Bound<'py, PyAny>>,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    value.map(|v| f(py, v)).transpose()
}

fn format<'py>(py: Python<'py>, value: &Format) -> PyResult<Bound<'py, PyAny>> {
    let d = PyDict::new(py);
    let mut archs: Vec<&str> = Vec::new();
    let mut app = None;
    let mut executable = None;
    let mut other_text = None;
    let kind = match value {
        Format::MachOThin(arch) => {
            archs.push(arch);
            "MACHO_THIN"
        }
        Format::MachOUniversal(all) => {
            archs.extend(all.iter().map(String::as_str));
            "MACHO_UNIVERSAL"
        }
        Format::Generic => "GENERIC",
        Format::DiskImage => "DISK_IMAGE",
        Format::Bundle {
            app: is_app,
            executable: inner,
        } => {
            app = Some(*is_app);
            executable = Some(format(py, inner)?);
            "BUNDLE"
        }
        Format::InfoPlistBundle => "INFO_PLIST_BUNDLE",
        Format::InstallerPackage => "INSTALLER_PACKAGE",
        Format::Widget => "WIDGET",
        Format::Other(text) => {
            other_text = Some(text.as_str());
            "OTHER"
        }
        _ => return Err(unsupported("Format")),
    };
    d.set_item("kind", kind)?;
    d.set_item("archs", archs)?;
    d.set_item("app", app)?;
    d.set_item("executable", executable)?;
    d.set_item("other", other_text)?;
    Ok(d.into_any())
}

fn location<'py>(py: Python<'py>, value: &Location) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Location::Embedded => named(py, "EMBEDDED"),
        Location::ExplicitDetached => named(py, "EXPLICIT_DETACHED"),
        Location::System => named(py, "SYSTEM"),
        Location::Other(text) => other(py, text),
        _ => Err(unsupported("Location")),
    }
}

fn platform<'py>(py: Python<'py>, value: &Platform) -> PyResult<Bound<'py, PyAny>> {
    let name = match value {
        Platform::MacOs => "MAC_OS",
        Platform::Ios => "IOS",
        Platform::TvOs => "TV_OS",
        Platform::WatchOs => "WATCH_OS",
        Platform::BridgeOs => "BRIDGE_OS",
        Platform::MacCatalyst => "MAC_CATALYST",
        Platform::IosSimulator => "IOS_SIMULATOR",
        Platform::TvOsSimulator => "TV_OS_SIMULATOR",
        Platform::WatchOsSimulator => "WATCH_OS_SIMULATOR",
        Platform::DriverKit => "DRIVER_KIT",
        Platform::VisionOs => "VISION_OS",
        Platform::VisionOsSimulator => "VISION_OS_SIMULATOR",
        Platform::Unknown(n) => return other(py, *n),
        _ => return Err(unsupported("Platform")),
    };
    named(py, name)
}

fn hash_type<'py>(py: Python<'py>, value: &HashType) -> PyResult<Bound<'py, PyAny>> {
    match value {
        HashType::Sha1 => named(py, "SHA1"),
        HashType::Sha256 => named(py, "SHA256"),
        HashType::Sha256Truncated => named(py, "SHA256_TRUNCATED"),
        HashType::Sha384 => named(py, "SHA384"),
        HashType::Unknown(text) => other(py, text),
        _ => Err(unsupported("HashType")),
    }
}

fn counters<'py>(py: Python<'py>, fields: &[(&str, u64)]) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    for &(key, value) in fields {
        d.set_item(key, value)?;
    }
    Ok(d)
}

fn os_version<'py>(py: Python<'py>, v: &OsVersion) -> PyResult<Bound<'py, PyAny>> {
    let fields = [
        ("major", v.major.into()),
        ("minor", v.minor.into()),
        ("patch", v.patch.into()),
    ];
    Ok(counters(py, &fields)?.into_any())
}

fn code_directory<'py>(py: Python<'py>, value: &CodeDirectory) -> PyResult<Bound<'py, PyAny>> {
    let d = PyDict::new(py);
    d.set_item("version", value.version)?;
    d.set_item("size", value.size)?;
    d.set_item("flags", value.flags.bits())?;
    let hashes = [
        ("code", value.hashes.code.into()),
        ("special", value.hashes.special.into()),
    ];
    d.set_item("hashes", counters(py, &hashes)?)?;
    d.set_item("location", location(py, &value.location)?)?;
    Ok(d.into_any())
}

fn cd_hash<'py>(py: Python<'py>, value: &CdHash) -> PyResult<Bound<'py, PyAny>> {
    let d = PyDict::new(py);
    d.set_item("algorithm", hash_type(py, &value.algorithm)?)?;
    d.set_item("truncated", &value.truncated)?;
    d.set_item("full", &value.full)?;
    Ok(d.into_any())
}

fn plist_value<'py>(py: Python<'py>, value: &plist::Value) -> PyResult<Bound<'py, PyAny>> {
    use plist::Value;
    match value {
        Value::String(s) => s.into_bound_py_any(py),
        Value::Boolean(b) => b.into_bound_py_any(py),
        Value::Integer(i) => match i.as_signed() {
            Some(n) => n.into_bound_py_any(py),
            None => i.as_unsigned().unwrap_or_default().into_bound_py_any(py),
        },
        Value::Real(f) => f.into_bound_py_any(py),
        Value::Data(bytes) => Ok(PyBytes::new(py, bytes).into_any()),
        Value::Date(date) => py
            .import("datetime")?
            .getattr("datetime")?
            .call_method1("fromisoformat", (date.to_xml_format(),)),
        Value::Uid(uid) => uid.get().into_bound_py_any(py),
        Value::Array(items) => Ok(list(py, items, plist_value)?.into_any()),
        Value::Dictionary(dict) => Ok(plist_dict(py, dict)?.into_any()),
        _ => Err(unsupported("plist value")),
    }
}

fn plist_dict<'py>(py: Python<'py>, dict: &plist::Dictionary) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new(py);
    for (key, value) in dict {
        out.set_item(key, plist_value(py, value)?)?;
    }
    Ok(out)
}

pub(crate) fn signature<'py>(py: Python<'py>, s: &Signature) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("executable", &s.executable)?;
    d.set_item("identifier", &s.identifier)?;
    d.set_item("format", format(py, &s.format)?)?;
    d.set_item("code_directory", code_directory(py, &s.code_directory)?)?;
    d.set_item("platform_identifier", s.platform_identifier)?;
    d.set_item("library_validation_warning", &s.library_validation_warning)?;
    d.set_item("platform", opt(py, s.platform.as_ref(), platform)?)?;
    d.set_item("min_os", opt(py, s.min_os.as_ref(), os_version)?)?;
    d.set_item("sdk", opt(py, s.sdk.as_ref(), os_version)?)?;
    d.set_item("hash_type", hash_type(py, &s.hash_type)?)?;
    d.set_item("hash_choices", list(py, &s.hash_choices, hash_type)?)?;
    d.set_item("cd_hashes", list(py, &s.cd_hashes, cd_hash)?)?;
    d.set_item("cd_hash", &s.cd_hash)?;
    let cms = s
        .cms_digest
        .as_ref()
        .map(|c| -> PyResult<_> {
            let cms = PyDict::new(py);
            cms.set_item("digest", &c.digest)?;
            cms.set_item("kind", c.kind)?;
            Ok(cms)
        })
        .transpose()?;
    d.set_item("cms_digest", cms)?;
    let segment = s
        .executable_segment
        .map(|e| {
            counters(
                py,
                &[("base", e.base), ("limit", e.limit), ("flags", e.flags)],
            )
        })
        .transpose()?;
    d.set_item("executable_segment", segment)?;
    d.set_item("page_size", s.page_size)?;
    match &s.signature {
        SignatureKind::AdHoc => d.set_item("signature", py.None())?,
        SignatureKind::Certificate { size, authorities } => {
            let sig = PyDict::new(py);
            sig.set_item("size", size)?;
            let names: Vec<Option<&str>> = authorities
                .iter()
                .map(|a| match a {
                    Authority::Name(name) => Some(name.as_str()),
                    _ => None,
                })
                .collect();
            sig.set_item("authorities", names)?;
            d.set_item("signature", sig)?;
        }
        _ => return Err(unsupported("SignatureKind")),
    }
    d.set_item("timestamp", &s.timestamp)?;
    d.set_item("signed_time", &s.signed_time)?;
    d.set_item("notarization_ticket", &s.notarization_ticket)?;
    d.set_item(
        "info_plist",
        match s.info_plist {
            InfoPlist::NotBound => None,
            InfoPlist::Entries(n) => Some(n),
            _ => return Err(unsupported("InfoPlist")),
        },
    )?;
    d.set_item("team_identifier", &s.team_identifier)?;
    d.set_item(
        "runtime_version",
        opt(py, s.runtime_version.as_ref(), os_version)?,
    )?;
    let sealed = s
        .sealed_resources
        .map(|r| {
            let fields = [
                ("version", r.version.into()),
                ("rules", r.rules.into()),
                ("files", r.files.into()),
            ];
            counters(py, &fields)
        })
        .transpose()?;
    d.set_item("sealed_resources", sealed)?;
    let summary = s
        .internal_requirements
        .map(|r| counters(py, &[("count", r.count.into()), ("size", r.size.into())]))
        .transpose()?;
    d.set_item("internal_requirements", summary)?;
    d.set_item("total_signatures", s.total_signatures)?;
    d.set_item("chosen_signature", s.chosen_signature)?;
    d.set_item("nested", &s.nested)?;
    d.set_item("constraints", s.constraints.bits())?;
    d.set_item(
        "entitlements",
        s.entitlements
            .as_ref()
            .map(|e| plist_dict(py, e))
            .transpose()?,
    )?;
    d.set_item("raw", s.raw())?;
    Ok(d)
}
