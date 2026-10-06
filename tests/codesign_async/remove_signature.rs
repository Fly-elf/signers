//! `remove_signature`, end to end — one submodule per test category,
//! named for what it covers; see each submodule's own doc comment for the
//! detail.
//!
//! Every test drives the public builder and then asks the `codesign` CLI what
//! actually landed on disk, so nothing here can pass because the library and
//! the test agree on a mistake.
//!
//! Note what is *not* asserted anywhere: that a stripped binary still runs.
//! Apple Silicon refuses to execute an unsigned Mach-O, so making a target
//! unrunnable is this action working, not failing.

mod bundles;
mod per_target;
mod preflight;
mod rejected_by_codesign;
mod removing;
