//! What the builder rejects before it ever spawns `codesign`: only the checks
//! every action shares. They matter most here, since a removal cannot be undone.

use signers::Codesign;

use crate::preflight::preflight_tests;

preflight_tests!(Codesign::remove_signature);
