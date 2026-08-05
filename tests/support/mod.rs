//! Shared harness for the integration suites.
//!
//! Not a cargo target of its own (no `main.rs`): each test binary pulls it in
//! with `#[path = "../support/mod.rs"] mod support;` and compiles its own copy,
//! which is why unused items are allowed here.
//!
//! The split is deliberate — [`fixture`] produces the *inputs* (a real Mach-O
//! binary, bundles, plists) and [`inspect`] checks the *outputs* by shelling out
//! to the macOS `codesign` CLI. Nothing in a test asserts on `signers` using
//! `signers`, so the library can never certify its own bugs.

#![allow(dead_code, reason = "every test binary uses a different subset")]

pub mod fixture;
pub mod inspect;

/// Whether the tests run as root, who is exempt from the permission bits a few
/// tests rely on — those skip themselves rather than assert something false.
pub fn running_as_root() -> bool {
    let uid = std::process::Command::new("id")
        .arg("-u")
        .output()
        .expect("could not run `id -u`");
    String::from_utf8_lossy(&uid.stdout).trim() == "0"
}
