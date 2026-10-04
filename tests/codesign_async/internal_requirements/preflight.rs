//! What the builder rejects before it ever spawns `codesign`: only the checks
//! every action shares. The action always runs one process per target.

use signers::Codesign;

use crate::preflight::preflight_tests;

preflight_tests!(Codesign::internal_requirements, one_process_per_target);
