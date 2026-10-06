//! ReleaseVerity ShipCheck Engine: installs and runs a release in a clean environment
//! and reports what actually happened.

// RunnerError carries both English text and catalog keys for localization; it is only returned on
// the (rare, slow) failure path of a multi-second environment run, so its size is irrelevant.
#![allow(clippy::result_large_err)]

pub mod agent_msgs;
pub mod checks;
pub mod docs;
pub mod runner;

pub use checks::{build_spec, checks, env_checks, resolve_env};
pub use runner::{find_agent, EnvRunner, HostRunner, SandboxRunner};
