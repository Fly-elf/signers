//! `.run()` brings its own runtime: it needs none around it, and refuses to
//! block a thread that is already driving one.

use std::thread;

use signers::blocking::Codesign;
use signers::codesign::blocking::remove_signature;

use crate::support::fixture::Workspace;
use crate::support::inspect;

/// Each call has a runtime of its own, so calls from several threads at once
/// don't interfere, and a thread can run one call after another.
#[test]
fn runs_from_several_threads_at_once_and_one_after_another() {
    let workspace = Workspace::new();
    let targets: Vec<_> = (0..4)
        .map(|i| workspace.unsigned(format!("hello-{i}")))
        .collect();

    thread::scope(|scope| {
        for target in &targets {
            scope.spawn(move || {
                Codesign::sign_adhoc(target).run().unwrap();
                Codesign::verify(target).run().unwrap();
                remove_signature(target).run().unwrap();
            });
        }
    });

    for target in &targets {
        assert!(!inspect::is_signed(target), "{}", target.display());
    }
}

#[tokio::test]
#[should_panic(expected = "from within a runtime")]
async fn running_inside_an_async_runtime_panics() {
    let _ = Codesign::verify("/bin/ls").run();
}
