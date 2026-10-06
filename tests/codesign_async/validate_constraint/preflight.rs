//! What the builder rejects before it ever spawns `codesign`: only the checks
//! every action shares.

use signers::codesign::validate_constraint;

use crate::preflight::preflight_tests;

preflight_tests!(validate_constraint);
