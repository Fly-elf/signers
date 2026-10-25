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
