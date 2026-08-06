//! `Codesign::sign`, end to end — one submodule per test category, named for
//! what it covers; see each submodule's own doc comment for the detail.
//!
//! Every test drives the public builder and then asks the `codesign` CLI what
//! actually landed on disk, so nothing here can pass because the library and
//! the test agree on a mistake.

mod builder_and_future;
mod bundles;
mod entitlements_and_requirements;
mod kitchen_sink;
mod preflight;
mod preserve_metadata;
mod rejected_by_codesign;
mod resigning;
mod signing;
mod signing_behaviour;
mod signing_flags;

/// The bit `codesign` sets on every ad-hoc signature. It is not in
/// `SigningFlags` because it is not something a caller asks for.
const ADHOC: u32 = 0x2;
