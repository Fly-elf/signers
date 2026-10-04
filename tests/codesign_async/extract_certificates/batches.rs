//! Several targets: always one `codesign` per target, run concurrently, each
//! chain matched to its own target, the same path any number of times.

use std::future::IntoFuture;
use std::path::{Path, PathBuf};

use signers::Codesign;
use signers::codesign::extract_certificates::Certificate;

use super::{PLATFORM_BINARY, ders, platform_copy};
use crate::support::fixture::Workspace;
use crate::support::inspect;

fn platform_chain() -> Vec<Vec<u8>> {
    inspect::certificates(Path::new(PLATFORM_BINARY))
}

#[tokio::test]
async fn each_target_gets_its_own_chain_in_input_order() {
    let workspace = Workspace::new();
    let signed = platform_copy(&workspace, "signed");
    let adhoc = workspace.adhoc_signed("adhoc");
    let targets = vec![adhoc.clone(), signed.clone(), adhoc, signed];

    let chains: Vec<Vec<Certificate>> = Codesign::extract_certificates(targets).await.unwrap();

    let lengths: Vec<usize> = chains.iter().map(Vec::len).collect();
    let full = platform_chain();
    assert_eq!(lengths, [0, full.len(), 0, full.len()]);
    assert_eq!(ders(&chains[1]), full);
    assert_eq!(ders(&chains[3]), full);
}

#[tokio::test]
async fn an_array_of_targets_yields_an_array_of_chains() {
    let workspace = Workspace::new();
    let adhoc = workspace.adhoc_signed("adhoc");

    let [first, second] = Codesign::extract_certificates([PathBuf::from(PLATFORM_BINARY), adhoc])
        .await
        .unwrap();

    assert_eq!(ders(&first), platform_chain());
    assert_eq!(second, []);
}

/// The runs are concurrent and share one action, so each must read back the
/// files its own `codesign` wrote, never those of another run of the same path.
#[tokio::test]
async fn the_same_path_repeated_yields_the_full_chain_every_time() {
    let expected = platform_chain();

    for _ in 0..4 {
        let chains = Codesign::extract_certificates(vec![PLATFORM_BINARY; 16])
            .await
            .unwrap();

        assert_eq!(chains.len(), 16);
        for (n, chain) in chains.iter().enumerate() {
            assert_eq!(ders(chain), expected, "run {n}");
        }

        let chains: [Vec<Certificate>; 8] = Codesign::extract_certificates([PLATFORM_BINARY; 8])
            .await
            .unwrap();
        for (n, chain) in chains.iter().enumerate() {
            assert_eq!(ders(chain), expected, "array, run {n}");
        }
    }
}

#[tokio::test]
async fn unsigned_targets_are_collected_in_input_order() {
    let workspace = Workspace::new();
    let first_unsigned = workspace.unsigned("first unsigned");
    let signed = platform_copy(&workspace, "signed");
    let second_unsigned = workspace.unsigned("second unsigned");

    let error = Codesign::extract_certificates(vec![
        first_unsigned.clone(),
        signed,
        second_unsigned.clone(),
    ])
    .await
    .unwrap_err();

    let failures = crate::batch_failures(error);
    let failed: Vec<&PathBuf> = failures.iter().map(|(path, _)| path).collect();
    assert_eq!(failed, [&first_unsigned, &second_unsigned]);
    for (path, error) in failures {
        let stderr = crate::codesign_error(error);
        assert!(
            stderr.contains("code object is not signed at all"),
            "{stderr}"
        );
        assert!(stderr.contains(&path.display().to_string()), "{stderr}");
    }
}

#[tokio::test]
async fn a_cloned_builder_runs_on_its_own() {
    let builder = Codesign::extract_certificates(vec![PLATFORM_BINARY; 4]);
    let copy = builder.clone();

    let (original, copy) = tokio::join!(builder.into_future(), copy.into_future());

    let expected = platform_chain();
    for chain in original.unwrap().iter().chain(&copy.unwrap()) {
        assert_eq!(ders(chain), expected);
    }
}
