//! Checks of debbuild-rs's output: `diff-stage` compares staged trees, `check` compares an
//! installation by `debbuild-rs install` with dpkg's, and with the installer it replaced.
//!
//! A verification harness, run by hand as root: string building and long scenario
//! functions are its style.
#![allow(
    clippy::format_collect,
    clippy::format_push_string,
    clippy::many_single_char_names,
    clippy::too_many_lines
)]

pub mod ck;
pub mod diffstage;
mod fixtures;
pub mod inspect;
mod manifest;
mod mounts;
pub mod oracle;
mod util;

pub use util::Error;
