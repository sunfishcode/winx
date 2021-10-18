#![deny(
    // missing_docs,
    trivial_numeric_casts,
    unused_extern_crates,
    unstable_features
)]
#![warn(unused_import_braces)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::new_without_default))]
#![cfg_attr(
    feature = "cargo-clippy",
    warn(
        clippy::float_arithmetic,
        clippy::mut_mut,
        clippy::nonminimal_bool,
        clippy::map_unwrap_or,
        clippy::clippy::unicode_not_nfc,
        clippy::use_self
    )
)]
#![cfg(windows)]
#![cfg_attr(io_lifetimes_use_std, feature(io_safety))]

/// Re-export `io_lifetimes` since we use its types in our public API, so
/// that our users don't need to do anything special to use the same version.
pub use io_lifetimes;

mod cvt;
pub mod file;
mod ntdll;
pub mod time;
