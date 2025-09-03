//! Unified error handling for the gateway.
//!
//! This module defines a local `ProxErr` enum that captures gateway-domain
//! failure modes while remaining *compatible* with Pingora’s boxed error
//! (`pingora::Error`).
//!
//! ### Compatibility strategy
//! * **Internal API** – your helper functions return `ProxResult<T>` where the
//!   error variant is **`ProxErr`**, keeping granular insight.
//! * **Pingora traits** – implementations such as `request_filter` expect
//!   `Result<_, Box<pingora::Error>>`.  When bridging, call
//!   `to_pg_error(err)` (defined below) or `map_err(ProxErr::into_pg)` to turn a
//!   rich `ProxErr` into the boxed Pingora form without violating Rust’s orphan
//!   rules.
//!
//! The orphan-rule violations you observed earlier arose from attempts to write
//! `impl From<io::Error> for Box<pingora::Error>`.  This revision removes those
//! impls and instead offers an explicit helper.

use pingora::{Error as PgErr, ErrorType};
use std::{error::Error, fmt, io, sync::Arc};

/* ---------- ProxErr definition ---------- */
#[derive(Debug)]
pub enum ProxErr {
    Io(Arc<io::Error>),
    AddrResolve(String),
    NoAddress,
    Pingora(PgErr),
    Transport(String),
    Http(String),
    Other(String),
}

/* ---------- Display ---------- */
impl fmt::Display for ProxErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxErr::Io(e) => write!(f, "I/O: {e}"),
            ProxErr::AddrResolve(s) => write!(f, "address resolution: {s}"),
            ProxErr::NoAddress => write!(f, "resolved 0 addresses"),
            ProxErr::Pingora(e) => write!(f, "pingora: {e}"),
            ProxErr::Transport(s) => write!(f, "transport: {s}"),
            ProxErr::Http(s) => write!(f, "http: {s}"),
            ProxErr::Other(s) => write!(f, "{s}"),
        }
    }
}

impl Error for ProxErr {}

/* ---------- Into ProxErr ---------- */
impl From<io::Error> for ProxErr {
    fn from(e: io::Error) -> Self {
        Self::Io(Arc::new(e))
    }
}
impl From<PgErr> for ProxErr {
    fn from(e: PgErr) -> Self {
        Self::Pingora(e)
    }
}
impl From<Box<PgErr>> for ProxErr {
    fn from(e: Box<PgErr>) -> Self {
        Self::Pingora(*e)
    }
}
impl From<String> for ProxErr {
    fn from(s: String) -> Self {
        Self::Other(s)
    }
}
impl From<&str> for ProxErr {
    fn from(s: &str) -> Self {
        Self::Other(s.to_owned())
    }
}

/* ---------- Into Pingora Error ---------- */
impl From<ProxErr> for Box<PgErr> {
    fn from(e: ProxErr) -> Self {
        // Preserve details and attach the original error as the cause.
        PgErr::because(ErrorType::InternalError, e.to_string(), e)
    }
}

/* ---------- Direct conversions (handy for `?`) ---------- */
// Implementations like `impl From<io::Error> for Box<PgErr>` violate Rust's
// orphan rules.  Instead provide a helper method to convert our local
// `ProxErr` into the boxed Pingora error type.
impl ProxErr {
    /// Convert into Pingora's boxed error.
    pub fn into_pg(self) -> Box<PgErr> {
        to_pg_error(self)
    }
}
/* ---------- Bridging to Pingora ---------- */
pub fn to_pg_error(e: ProxErr) -> Box<PgErr> {
    // Tag as internal; attach full display string as context.
    PgErr::because(ErrorType::InternalError, e.to_string(), e)
}

/* ---------- Convenience alias ---------- */
pub type ProxResult<T> = std::result::Result<T, ProxErr>;
