use super::*;
use crate::codesign::extract_certificates;

/// A run leaves its scratch directory, counter and prefixes in the
/// options; a copy made afterwards must not inherit or share any of them.
#[test]
fn a_clone_starts_without_the_run_state_of_its_original() {
    let original = extract_certificates("a").options;
    original.validate().unwrap();
    let targets = [PathBuf::from("a")];
    original.to_args(&targets);
    {
        let state = original.state();
        assert!(state.dir.is_some());
        assert_eq!(state.next, 1);
        assert_eq!(state.prefixes.len(), 1);
    }

    let copy = original.clone();

    let state = copy.state();
    assert!(state.dir.is_none());
    assert_eq!(state.next, 0);
    assert!(state.prefixes.is_empty());
    assert!(original.state().dir.is_some());
}

/// The chains of several targets come from separate runs, so there is no
/// shared run to opt into. Resolves only while `ExtractCertificates` is
/// not `SharedRun`.
#[test]
fn the_action_cannot_share_a_run() {
    trait AmbiguousIfShared<A> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfShared<()> for T {}
    impl<T: ?Sized + crate::engine::SharedRun> AmbiguousIfShared<u8> for T {}

    <ExtractCertificates as AmbiguousIfShared<_>>::check();
}

#[test]
fn save_to_keeps_the_last_directory() {
    let options = extract_certificates("a")
        .save_to("first")
        .save_to("second")
        .options;

    assert_eq!(options.save_to, Some(PathBuf::from("second")));
}

#[test]
fn the_arguments_extract_into_the_run_directory_and_list_the_targets_last() {
    let options = extract_certificates("a").options;
    options.validate().unwrap();
    let targets = [PathBuf::from("a"), PathBuf::from("-b")];

    let args = options.to_args(&targets);

    let prefix = options.state().dir.as_ref().unwrap().path().join("0-");
    let mut expected = OsString::from("--extract-certificates=");
    expected.push(prefix);
    assert_eq!(args[0], OsStr::new("--display"));
    assert_eq!(args[1], expected);
    assert_eq!(&args[2..], ["--", "a", "-b"].map(OsStr::new));
}

#[test]
fn every_run_gets_its_own_prefix() {
    let options = extract_certificates("a").options;
    options.validate().unwrap();
    let (first, second) = ([PathBuf::from("a")], [PathBuf::from("a")]);

    let one = options.to_args(&first)[1].to_string_lossy().into_owned();
    let two = options.to_args(&second)[1].to_string_lossy().into_owned();

    assert!(one.ends_with("/0-"), "{one}");
    assert!(two.ends_with("/1-"), "{two}");
}
