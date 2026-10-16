//! Current startup DTO; every variable JSON child retains its physical owner.
use super::{value::Value, Text};
use crate::{allocation::ordered_map::PaidOrderedMapV1, oidc::retained::RetainedOidcConfig};
/// Existing startup defaults, shared by the current decoder and its independent oracle.
pub const DEFAULT_PORT: u16 = 443;
pub const DEFAULT_BACKLOG: i32 = 128;
/// Parsed configuration. The host input may be released immediately after parsing.
pub struct EnclaveConfig {
    pub port: u16,
    pub backlog: i32,
    pub oidc: Option<RetainedOidcConfig>,
    pub extra: PaidOrderedMapV1<Text<'static>, Value<'static>>,
}
