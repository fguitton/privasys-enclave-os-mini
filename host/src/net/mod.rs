// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! Host-side networking: TCP listener, accept, connect, send, recv via OS sockets.

pub mod listener;
mod readiness;
pub(crate) use readiness::{receive as execution_receive, send as execution_send};

pub use listener::*;

#[cfg(all(test, unix))]
pub(crate) use readiness::check as check_execution_readiness;
