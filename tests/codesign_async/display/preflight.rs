//! What the builder rejects before it ever spawns `codesign`: only the checks
//! every action shares.

use signers::Codesign;

use crate::preflight::preflight_tests;

preflight_tests!(Codesign::display);
