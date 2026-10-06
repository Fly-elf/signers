//! What the builder rejects before it ever spawns `codesign`: only the checks
//! every action shares. They matter most here, since a removal cannot be undone.

use signers::codesign::remove_signature;

use crate::preflight::preflight_tests;

preflight_tests!(remove_signature);
