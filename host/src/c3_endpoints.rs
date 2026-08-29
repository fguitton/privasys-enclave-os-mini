// Copyright (c) Florian Guitton. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

use std::collections::BTreeSet;
use std::net::SocketAddrV4;

/// Smallest voter population admitting a Byzantine-fault-tolerant quorum
/// (`n >= 3f + 1` at `f = 1`).
const MIN_C3_DEVELOPMENT_ENDPOINTS: usize = 4;
/// Largest roster the replicated execution set carries.
const MAX_C3_DEVELOPMENT_ENDPOINTS: usize = 16;

pub(crate) fn validate_c3_development_endpoints(
    node_id: u64,
    endpoints: &[String],
) -> Result<(), String> {
    let cardinality = endpoints.len();
    if !(MIN_C3_DEVELOPMENT_ENDPOINTS..=MAX_C3_DEVELOPMENT_ENDPOINTS).contains(&cardinality) {
        return Err(format!(
            "--c3-development-peer-endpoints requires {MIN_C3_DEVELOPMENT_ENDPOINTS}..={MAX_C3_DEVELOPMENT_ENDPOINTS} entries, observed {cardinality}"
        ));
    }
    if node_id == 0 || node_id > cardinality as u64 {
        return Err(format!(
            "--c3-development-node-id must be in 1..={cardinality}, observed {node_id}"
        ));
    }

    let mut socket_addresses = BTreeSet::new();
    for (offset, entry) in endpoints.iter().enumerate() {
        let expected_id = offset + 1;
        let (member_id, address) = entry.split_once('=').ok_or_else(|| {
            format!("C3 endpoint {expected_id} must use canonical node-id=IPv4:port encoding")
        })?;
        if member_id != expected_id.to_string() {
            return Err(format!(
                "C3 endpoints must be ordered contiguously from member 1; entry {expected_id} declared '{member_id}'"
            ));
        }
        let socket: SocketAddrV4 = address.parse().map_err(|_| {
            format!("C3 endpoint {expected_id} must contain one canonical IPv4:port address")
        })?;
        if socket.port() == 0 || socket.to_string() != address {
            return Err(format!(
                "C3 endpoint {expected_id} must contain one canonical IPv4 address and nonzero port"
            ));
        }
        if !socket_addresses.insert(socket) {
            return Err("C3 peer socket addresses must be unique".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_c3_development_endpoints;

    fn endpoints(cardinality: usize) -> Vec<String> {
        (1..=cardinality)
            .map(|member| format!("{member}=192.0.2.{member}:{}", 8400 + member))
            .collect()
    }

    #[test]
    fn accepts_canonical_minimum_mid_and_maximum_rosters() {
        assert!(validate_c3_development_endpoints(1, &endpoints(4)).is_ok());
        assert!(validate_c3_development_endpoints(5, &endpoints(5)).is_ok());
        assert!(validate_c3_development_endpoints(16, &endpoints(16)).is_ok());
    }

    #[test]
    fn rejects_cardinalities_outside_supported_range() {
        assert!(validate_c3_development_endpoints(1, &endpoints(2)).is_err());
        assert!(validate_c3_development_endpoints(1, &endpoints(17)).is_err());
    }

    #[test]
    fn rejects_node_id_cardinality_mismatch() {
        assert!(validate_c3_development_endpoints(0, &endpoints(4)).is_err());
        assert!(validate_c3_development_endpoints(5, &endpoints(4)).is_err());
    }

    #[test]
    fn rejects_duplicate_peer_socket() {
        let mut values = endpoints(3);
        values[2] = "3=192.0.2.2:8402".to_string();
        assert!(validate_c3_development_endpoints(1, &values).is_err());
    }

    #[test]
    fn rejects_reordered_gapped_or_noncanonical_member_ids() {
        let mut reordered = endpoints(3);
        reordered.swap(0, 1);
        assert!(validate_c3_development_endpoints(1, &reordered).is_err());

        let mut gapped = endpoints(3);
        gapped[1] = "4=192.0.2.2:8402".to_string();
        assert!(validate_c3_development_endpoints(1, &gapped).is_err());

        let mut noncanonical = endpoints(3);
        noncanonical[0] = "01=192.0.2.1:8401".to_string();
        assert!(validate_c3_development_endpoints(1, &noncanonical).is_err());
    }

    #[test]
    fn rejects_invalid_or_noncanonical_socket_addresses() {
        for replacement in [
            "1=192.0.2.1",
            "1=[2001:db8::1]:8401",
            "1=192.0.2.1:0",
            "1=192.0.2.01:8401",
            "1=192.0.2.1:08401",
            "1=192.0.2.1:8401=extra",
        ] {
            let mut values = endpoints(3);
            values[0] = replacement.to_string();
            assert!(
                validate_c3_development_endpoints(1, &values).is_err(),
                "unexpectedly accepted {replacement}"
            );
        }
    }
}
