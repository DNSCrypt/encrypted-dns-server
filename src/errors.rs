pub use failure::{bail, ensure, Error};
use std::io;
use std::net::AddrParseError;

#[derive(Debug, Fail)]
pub enum ProxyError {
    #[fail(display = "Internal error: [{}]", _0)]
    InternalError(String),
    #[fail(display = "I/O error: [{}]", _0)]
    Io(#[cause] io::Error),
    #[fail(display = "Unable to parse address: [{}]", _0)]
    AddrParseError(#[cause] AddrParseError),
}