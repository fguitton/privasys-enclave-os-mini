// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! RA-TLS (Remote Attestation - Transport Layer Security) module.
//!
//! Provides mutual attestation after the standard TLS 1.3 handshake using
//! connection-bound evidence and reusable identity certificates.

pub mod attestation;
pub mod cert_store;
mod client_auth;
pub mod server;
pub mod session;
