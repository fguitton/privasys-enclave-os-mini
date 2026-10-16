// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Core attestation server storage.
//!
//! Provides a centralised, thread-safe store for attestation server
//! endpoints and their optional bearer tokens.  Both the enclave core
//! (startup configuration, `SetAttestationServers` API) and module
//! crates (egress quote verification) access this store.
//!
//! ## Hashing
//!
//! The canonical form is the sorted, newline-joined URL list (tokens
//! are excluded — they are runtime secrets and must never enter the
//! Merkle tree).  The SHA-256 hash of this canonical form is exposed
//! via OID `1.3.6.1.4.1.65230.2.7` in RA-TLS certificates.

use std::vec::Vec;
use std::{
    fmt,
    sync::{Arc, RwLock},
};

use ring::digest;

use crate::{
    allocation::AllocationPoolV1,
    protocol::AttestationServer,
    request_json::{sequence::Sequence, Refusal, Text},
};
/// Current retained server list; text and sequence backing retain their original pool.
pub type Servers = Sequence<AttestationServer<Text<'static>>>;

// ---------------------------------------------------------------------------
//  State
// ---------------------------------------------------------------------------

struct State {
    servers: Option<Servers>,
    /// SHA-256 of the canonical URL list.  `None` when no servers are
    /// configured.
    hash: Option<[u8; 32]>,
    /// Sorted, newline-joined URL list.  `None` when empty.
    canonical: Option<Text<'static>>,
}

impl State {
    const fn empty() -> Self {
        Self {
            servers: None,
            hash: None,
            canonical: None,
        }
    }
}

static SERVERS: RwLock<State> = RwLock::new(State::empty());

// ---------------------------------------------------------------------------
//  Helpers
// ---------------------------------------------------------------------------

/// Compute the canonical form and SHA-256 hash from a list of servers.
fn compute(
    pool: &Arc<AllocationPoolV1>,
    servers: &Servers,
) -> Result<(Option<Text<'static>>, Option<[u8; 32]>), Refusal> {
    if servers.as_slice().is_empty() {
        return Ok((None, None));
    }
    let mut urls = Sequence::new(Arc::clone(pool));
    for server in servers.as_slice() {
        urls.try_push(server.url.as_str())?;
    }
    // Equal URLs produce identical canonical bytes; unstable sorting needs no
    // additional temporary allocation beyond the explicitly admitted reference buffer.
    urls.as_mut_slice().sort_unstable();
    struct Canonical<'a>(&'a [&'a str]);
    impl fmt::Display for Canonical<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for (index, url) in self.0.iter().enumerate() {
                if index != 0 {
                    f.write_str("\n")?;
                }
                f.write_str(url)?;
            }
            Ok(())
        }
    }
    let canonical = Text::display(pool, &Canonical(urls.as_slice()))?;
    let d = digest::digest(&digest::SHA256, canonical.as_bytes());
    let mut h = [0u8; 32];
    h.copy_from_slice(d.as_ref());
    Ok((Some(canonical), Some(h)))
}

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------

/// Initialise the attestation server list.
///
/// Typically called once during enclave startup with the configuration
/// provided by the operator.  May be called again via the
/// [`SetAttestationServers`](crate::protocol::Request::SetAttestationServers)
/// core API.
/// # Errors
/// Refuses canonical/reference backing before replacing the previous live state.
pub fn set(
    pool: &Arc<AllocationPoolV1>,
    servers: Servers,
) -> Result<(usize, Option<[u8; 32]>), Refusal> {
    let (canonical, hash) = compute(pool, &servers)?;
    let count = servers.as_slice().len();
    let mut state = SERVERS.write().unwrap();
    state.servers = Some(servers);
    state.hash = hash;
    state.canonical = canonical;
    Ok((count, hash))
}

/// Get a snapshot of the current attestation server URL list.
pub fn server_urls() -> Vec<String> {
    SERVERS
        .read()
        .unwrap()
        .servers
        .as_ref()
        .map_or(&[][..], |servers| servers.as_slice())
        .iter()
        .map(|s| s.url.as_str().to_owned())
        .collect()
}

/// Look up the bearer token for a given attestation server URL.
///
/// Returns `None` when no token has been configured for that URL.
pub fn token_for(url: &str) -> Option<String> {
    SERVERS
        .read()
        .unwrap()
        .servers
        .as_ref()
        .map_or(&[][..], |servers| servers.as_slice())
        .iter()
        .find(|s| s.url.as_str() == url)
        .and_then(|s| s.token.as_ref().map(|token| token.as_str().to_owned()))
}

/// Update the bearer token for a given server URL (in-place).
pub fn update_token(url: &str, token: Text<'static>) {
    let mut state = SERVERS.write().unwrap();
    if let Some(srv) = state
        .servers
        .as_mut()
        .map_or(&mut [][..], |servers| servers.as_mut_slice())
        .iter_mut()
        .find(|s| s.url.as_str() == url)
    {
        srv.token = Some(token);
    }
}

/// Current SHA-256 hash of the canonical URL list, or `None` if empty.
pub fn hash() -> Option<[u8; 32]> {
    SERVERS.read().unwrap().hash
}

/// Canonical (sorted, newline-joined) URL list, or `None` if empty.
pub fn canonical_form() -> Option<Vec<u8>> {
    SERVERS
        .read()
        .unwrap()
        .canonical
        .as_ref()
        .map(|text| text.as_bytes().to_vec())
}

/// Take the already-admitted startup field. Invalid semantic shapes retain the
/// original startup behavior (an empty list); resource refusal is never defaulted.
/// No parsed String or old backing is cloned during this current typed projection.
/// # Errors
/// Refuses a separately admitted destination sequence backing.
pub fn from_configuration(
    pool: &Arc<AllocationPoolV1>,
    value: Option<crate::request_json::value::Value<'static>>,
) -> Result<Servers, Refusal> {
    use crate::request_json::value::Value;
    let mut servers = Sequence::new(Arc::clone(pool));
    let Some(Value::Array(values)) = value else {
        return Ok(servers);
    };
    for value in values {
        let Some(server) = configuration_server(value) else {
            return Ok(Sequence::new(Arc::clone(pool)));
        };
        servers.try_push(server)?;
    }
    Ok(servers)
}
fn configuration_server(
    value: crate::request_json::value::Value<'static>,
) -> Option<AttestationServer<Text<'static>>> {
    use crate::request_json::value::Value;
    let (url, token) = match value {
        Value::Object(mut map) => (map.remove("url")?, map.remove("token")),
        Value::Array(values) => {
            let mut values = values.into_iter();
            let url = values.next()?;
            let token = values.next();
            if values.next().is_some() {
                return None;
            }
            (url, token)
        }
        _ => return None,
    };
    let Value::String(url) = url else { return None };
    let token = match token {
        None | Some(Value::Null) => None,
        Some(Value::String(token)) => Some(token),
        _ => return None,
    };
    Some(AttestationServer { url, token })
}
