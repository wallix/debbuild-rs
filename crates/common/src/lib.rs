//! What the build and install sides of debbuild-rs share: deb822 control data, Debian
//! versions and relations, with dpkg's semantics, the checks dpkg-deb makes of a package
//! tree, the error type, and the lock readers of a staged output take.

pub mod deb822;
pub mod error;
pub mod py;
pub mod relation;
pub mod staged_lock;
pub mod validate;
pub mod version;

pub use error::{Error, IoContext, Kind, Result};
