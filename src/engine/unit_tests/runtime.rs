use super::*;
use crate::engine::tool::testing::Sh;
use crate::errors::Error;

#[cfg(feature = "async")]
#[tokio::test]
async fn the_async_runtime_hands_the_future_back_untouched() {
    assert_eq!(Async::drive::<Sh, _>(async { Ok(5) }).await.unwrap(), 5);
    let error = Async::drive::<Sh, ()>(async { Err(Error::NoTargets) })
        .await
        .unwrap_err();
    assert!(matches!(error, Error::NoTargets));
}

#[cfg(feature = "blocking")]
#[test]
fn the_blocking_runtime_drives_a_future_to_its_result() {
    assert_eq!(Blocking::drive::<Sh, _>(async { Ok(5) }).unwrap(), 5);
    let error = Blocking::drive::<Sh, ()>(async { Err(Error::NoTargets) }).unwrap_err();
    assert!(matches!(error, Error::NoTargets));
}

/// The runtime enables I/O and timers, which the process run needs.
#[cfg(feature = "blocking")]
#[test]
fn the_blocking_runtime_can_spawn_a_process() {
    let output = Blocking::drive::<Sh, _>(async {
        Ok(tokio::process::Command::new("true").status().await.unwrap())
    })
    .unwrap();

    assert!(output.success());
}
