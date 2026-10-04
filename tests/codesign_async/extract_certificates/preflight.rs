//! What the builder rejects before it ever spawns `codesign`: only the checks
//! every action shares.

use signers::Codesign;

use crate::preflight::preflight_tests;

preflight_tests!(Codesign::extract_certificates, one_process_per_target);
