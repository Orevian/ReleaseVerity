//! ReleaseVerity core. Independent of any CLI or GUI.

pub mod check;
pub mod config;
pub mod db;
pub mod hash;
pub mod i18n;
pub mod logging;
pub mod model;
pub mod proc;
pub mod report;
pub mod scoring;

/// The one product version, inherited from the workspace `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
