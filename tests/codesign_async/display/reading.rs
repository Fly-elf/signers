//! One target, read back: every part of the report that varies with how the
//! target was signed, compared with what the `codesign` CLI prints for it.

use std::fs;
use std::path::PathBuf;

use signers::Codesign;
use signers::codesign::display::{
    Authority, Constraints, Format, HashType, InfoPlist, Location, OsVersion, Signature,
    SignatureKind,
};

use crate::support::fixture::{Workspace, fixture_str};
use crate::support::inspect;

/// The checks every successful read has to pass, whatever the target:
/// the report is the CLI's, and the values it carries are the CLI's.
fn assert_agrees_with_codesign(signature: &Signature, path: &std::path::Path) {
    let oracle = inspect::Signature::of(path);
    assert_eq!(
        signature.raw(),
        oracle.raw(),
        "raw report of {}",
        path.display()
    );
    assert_eq!(
        signature.executable,
        PathBuf::from(oracle.field("Executable").unwrap())
    );
    assert_eq!(signature.identifier, oracle.identifier());
    assert_eq!(signature.cd_hash, oracle.cd_hash());
    assert_eq!(signature.code_directory.flags.bits(), oracle.flags());
    assert_eq!(signature.code_directory.hashes.code, oracle.code_hashes());
    assert_eq!(signature.page_size, oracle.page_size());
    for line in oracle.raw().lines() {
        if let Some((key, _)) = line.split_once('=') {
            assert_eq!(signature.field(key), oracle.field(key), "field({key:?})");
        }
    }
}

#[tokio::test]
async fn an_ad_hoc_binary_is_read_back_as_codesign_prints_it() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-i", "com.example.hello"]);

    let signature = Codesign::display(&target).await.unwrap();

    assert_agrees_with_codesign(&signature, &target);
    let oracle = inspect::Signature::of(&target);
    assert_eq!(signature.identifier, "com.example.hello");
    let arch = oracle
        .format()
        .strip_prefix("Mach-O thin (")
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("not a thin format: {}", oracle.format()));
    assert_eq!(signature.format, Format::MachOThin(arch.to_owned()));
    assert_eq!(signature.signature, SignatureKind::AdHoc);
    assert_eq!(signature.code_directory.location, Location::Embedded);
    assert_eq!(signature.info_plist, InfoPlist::NotBound);
    assert_eq!(signature.team_identifier, None);
    assert_eq!(signature.sealed_resources, None);
    assert_eq!(signature.runtime_version, None);
    assert_eq!(signature.timestamp, None);
    assert_eq!(signature.signed_time, None);
    assert_eq!(signature.entitlements, None);
    assert_eq!(signature.constraints, Constraints::empty());
    assert!(signature.nested.is_empty());
    assert_eq!(signature.hash_type, HashType::Sha256);
    assert_eq!(signature.hash_choices, [HashType::Sha256]);
    let [cd_hash] = &signature.cd_hashes[..] else {
        panic!(
            "expected one candidate CDHash, got {:?}",
            signature.cd_hashes
        );
    };
    assert_eq!(cd_hash.algorithm, HashType::Sha256);
    assert_eq!(cd_hash.truncated, oracle.cd_hash());
    assert_eq!(
        cd_hash.full.as_deref(),
        oracle.field("CandidateCDHashFull sha256")
    );
    assert_eq!(
        (signature.total_signatures, signature.chosen_signature),
        (1, 1)
    );
    assert!(signature.executable_segment.is_some());
    assert!(signature.cms_digest.is_some());
    assert!(signature.platform.is_some());
}

/// A freshly linked binary on Apple Silicon: the most common state a binary
/// arrives in, and one whose report is shorter than any other.
#[tokio::test]
async fn a_linker_signed_binary_is_read_back() {
    let workspace = Workspace::new();
    let target = workspace.linker_signed("hello");

    let signature = Codesign::display(&target).await.unwrap();

    assert_agrees_with_codesign(&signature, &target);
    assert_eq!(signature.signature, SignatureKind::AdHoc);
}

#[tokio::test]
async fn reading_a_signature_leaves_the_target_untouched() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");
    let before = fs::read(&target).unwrap();

    Codesign::display(&target).await.unwrap();

    assert_eq!(fs::read(&target).unwrap(), before);
}

#[tokio::test]
async fn the_hardened_runtime_shows_as_a_flag_and_a_runtime_version() {
    let workspace = Workspace::new();
    let target = workspace.presigned("hello", &["-o", "runtime"]);

    let signature = Codesign::display(&target).await.unwrap();

    assert_agrees_with_codesign(&signature, &target);
    let printed = inspect::Signature::of(&target)
        .runtime_version()
        .expect("no runtime version printed")
        .to_owned();
    let OsVersion {
        major,
        minor,
        patch,
        ..
    } = signature.runtime_version.expect("no runtime version read");
    assert_eq!(format!("{major}.{minor}.{patch}"), printed);
    assert!(
        signature
            .code_directory
            .flags
            .contains(signers::codesign::sign::SigningFlags::RUNTIME)
    );
}

#[tokio::test]
async fn the_entitlements_are_read_back() {
    let workspace = Workspace::new();
    let entitlements = fixture_str("entitlements.plist");
    let target = workspace.presigned("hello", &["--entitlements", &entitlements]);

    let signature = Codesign::display(&target).await.unwrap();

    let expected: plist::Dictionary =
        plist::from_bytes(inspect::entitlements(&target).as_bytes()).unwrap();
    assert_eq!(signature.entitlements, Some(expected));
    assert_agrees_with_codesign(&signature, &target);
}

#[tokio::test]
async fn embedded_requirements_are_counted() {
    let workspace = Workspace::new();
    let target = workspace.presigned(
        "hello",
        &["-r=designated => identifier \"com.example.hello\""],
    );

    let signature = Codesign::display(&target).await.unwrap();

    assert_agrees_with_codesign(&signature, &target);
    let requirements = signature
        .internal_requirements
        .expect("no requirements read");
    assert_eq!(requirements.count, 1);
}

#[tokio::test]
async fn every_constraint_kind_is_read_back() {
    let constraint = fixture_str("launch-constraint.plist");
    let cases = [
        ("--launch-constraint-self", Constraints::LAUNCH_SELF),
        ("--launch-constraint-parent", Constraints::LAUNCH_PARENT),
        (
            "--launch-constraint-responsible",
            Constraints::LAUNCH_RESPONSIBLE,
        ),
        ("--library-constraint", Constraints::LIBRARY_LOAD),
    ];
    let workspace = Workspace::new();

    for (flag, bit) in cases {
        let target = workspace.presigned(
            flag.trim_start_matches('-'),
            &["-i", "com.example.constrained", flag, &constraint],
        );

        let signature = Codesign::display(&target)
            .await
            .unwrap_or_else(|e| panic!("{flag}: {e}"));

        assert_eq!(signature.constraints, bit, "{flag}");
        assert_agrees_with_codesign(&signature, &target);
    }
}

#[tokio::test]
async fn a_plain_file_is_a_generic_target() {
    let workspace = Workspace::new();
    let target = workspace.write("notes.txt", "signed text\n");
    super::adhoc_sign(&target, &[]);

    let signature = Codesign::display(&target).await.unwrap();

    assert_eq!(signature.format, Format::Generic);
    assert_eq!(signature.page_size, None);
    assert_eq!(signature.executable_segment, None);
    assert_agrees_with_codesign(&signature, &target);
}

#[tokio::test]
async fn a_universal_binary_lists_its_slices_in_printed_order() {
    let workspace = Workspace::new();
    let Some(target) = workspace.unsigned_universal("universal") else {
        crate::support::skip!("this toolchain cannot build a universal binary");
    };
    super::adhoc_sign(&target, &[]);

    let signature = Codesign::display(&target).await.unwrap();

    let printed = inspect::Signature::of(&target).format().to_owned();
    let archs = printed
        .strip_prefix("Mach-O universal (")
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("not a universal format: {printed}"));
    assert_eq!(
        signature.format,
        Format::MachOUniversal(archs.split(' ').map(str::to_owned).collect())
    );
    assert_agrees_with_codesign(&signature, &target);
}

#[tokio::test]
async fn an_app_bundle_reports_its_executable_info_plist_and_resources() {
    let workspace = Workspace::new();
    let bundle = workspace.app_bundle("Hello");
    super::adhoc_sign(&bundle, &[]);

    let signature = Codesign::display(&bundle).await.unwrap();

    assert_agrees_with_codesign(&signature, &bundle);
    let Format::Bundle { app, executable } = &signature.format else {
        panic!("not a bundle: {:?}", signature.format);
    };
    assert!(app);
    assert!(
        matches!(**executable, Format::MachOThin(_)),
        "{executable:?}"
    );
    assert_eq!(
        signature.executable.canonicalize().unwrap(),
        bundle.join("Contents/MacOS/Hello").canonicalize().unwrap()
    );
    let oracle = inspect::Signature::of(&bundle);
    let entries: u32 = oracle
        .info_plist()
        .strip_prefix("entries=")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(signature.info_plist, InfoPlist::Entries(entries));
    let sealed = signature.sealed_resources.expect("no sealed resources");
    assert_eq!(
        oracle.sealed_resources(),
        format!(
            "version={} rules={} files={}",
            sealed.version, sealed.rules, sealed.files
        )
    );
}

#[tokio::test]
async fn a_framework_is_a_bundle_but_not_an_app() {
    let workspace = Workspace::new();
    let framework = workspace.framework("Kit");
    super::adhoc_sign(&framework, &[]);

    let signature = Codesign::display(&framework).await.unwrap();

    assert!(
        matches!(&signature.format, Format::Bundle { app: false, .. }),
        "{:?}",
        signature.format
    );
    assert_agrees_with_codesign(&signature, &framework);
}

#[tokio::test]
async fn an_apple_platform_binary_carries_its_certificate_chain() {
    let target = std::path::Path::new("/bin/ls");

    let signature = Codesign::display(target).await.unwrap();

    assert_agrees_with_codesign(&signature, target);
    let oracle = inspect::Signature::of(target);
    let printed: Vec<Authority> = oracle
        .raw()
        .lines()
        .filter_map(|line| line.strip_prefix("Authority="))
        .map(|name| Authority::Name(name.to_owned()))
        .collect();
    let SignatureKind::Certificate { size, authorities } = &signature.signature else {
        panic!("not a certificate signature: {:?}", signature.signature);
    };
    assert_eq!(*authorities, printed);
    assert!(!authorities.is_empty());
    assert_eq!(
        size.to_string(),
        oracle.field("Signature size").expect("no signature size")
    );
    assert_eq!(
        signature
            .platform_identifier
            .map(|n| n.to_string())
            .as_deref(),
        oracle.field("Platform identifier")
    );
    assert_eq!(
        signature.signed_time.as_deref(),
        oracle.field("Signed Time")
    );
    assert_eq!(signature.team_identifier, None);
}

#[tokio::test]
async fn awkward_file_names_are_read() {
    let workspace = Workspace::new();
    let names = [
        PathBuf::from("with spaces.bin"),
        PathBuf::from("-dashed"),
        PathBuf::from("ünïcödé"),
    ];

    for name in names {
        let target = workspace.presigned(&name, &[]);

        let signature = Codesign::display(&target)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", name.display()));

        assert_agrees_with_codesign(&signature, &target);
    }
}

#[tokio::test]
async fn a_report_line_that_has_no_field_is_still_reachable() {
    let workspace = Workspace::new();
    let target = workspace.adhoc_signed("hello");

    let signature = Codesign::display(&target).await.unwrap();

    assert_eq!(signature.field("Hash type"), Some("sha256 size=32"));
    assert_eq!(signature.field("No Such Key"), None);
}
