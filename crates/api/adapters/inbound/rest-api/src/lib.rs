//! The REST adapter: axum routes that turn HTTP requests into core Commands.
//!
//! - [`app`]: assembles the application: its state, dependencies and middleware
//! - [`server`]: runs it
//! - [`auth`], [`command`], [`error`]: machinery every resource shares
//! - one module per resource, e.g. [`organization`], with a file per endpoint

pub mod app;
pub mod auth;
pub mod command;
pub mod error;
pub mod health;
pub mod organization;
pub mod server;

pub use app::AppState;
pub use server::run;
