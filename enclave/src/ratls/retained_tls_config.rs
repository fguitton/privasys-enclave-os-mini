//! Top-level rustls config allocation and its opaque cached/session owner.
//! Provider, certificate/signing and handshake children have separate owners.
use enclave_os_common::allocation::{
    shared_allocation_bytes, AllocationPoolV1, SharedAllocationReservationV1, SharedAllocationV1,
};
use rustls::{ServerConfig, ServerConnection};
use std::sync::Arc;

type Payload = Arc<ServerConfig>;
#[derive(Clone)]
pub(crate) struct RetainedTlsConfig(SharedAllocationV1<Payload>);
pub(crate) struct ConfigReservation(SharedAllocationReservationV1<Payload>);

impl RetainedTlsConfig {
    #[cfg(test)]
    pub(crate) fn required_bytes() -> Option<usize> {
        SharedAllocationV1::<Payload>::required_bytes(shared_allocation_bytes::<ServerConfig>()?)
    }
    pub(crate) fn reserve(pool: &Arc<AllocationPoolV1>) -> Option<ConfigReservation> {
        SharedAllocationV1::<Payload>::reserve(pool, shared_allocation_bytes::<ServerConfig>()?)
            .map(ConfigReservation)
    }
    #[cfg(target_vendor = "teaclave")]
    pub(crate) fn accept(
        self,
        accepted: rustls::server::Accepted,
    ) -> Result<RetainedConnection, (rustls::Error, rustls::server::AcceptedAlert)> {
        let connection = accepted.into_connection(Arc::clone(&self.0))?;
        Ok(RetainedConnection {
            connection,
            _retained: self,
        })
    }
    #[cfg(test)]
    pub(crate) fn connect(self) -> Result<RetainedConnection, rustls::Error> {
        let connection = ServerConnection::new(Arc::clone(&self.0))?;
        Ok(RetainedConnection {
            connection,
            _retained: self,
        })
    }
}
impl ConfigReservation {
    pub(crate) fn finish(self, config: ServerConfig) -> Option<RetainedTlsConfig> {
        #[cfg(feature = "fallible-allocation-v1")]
        let config = Arc::try_new(config).ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let config = Arc::new(config);
        #[cfg(feature = "fallible-allocation-v1")]
        let retained = self.0.try_finish(config).ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let retained = self.0.finish(config);
        Some(RetainedTlsConfig(retained))
    }
}

// Field order is deliberate: all private rustls aliases die with the connection
// before the paired owner can release the actual config Arc and its credit.
// No owned config Arc or Weak is exposed by this interface.
pub(crate) struct RetainedConnection {
    connection: ServerConnection,
    _retained: RetainedTlsConfig,
}
impl core::ops::Deref for RetainedConnection {
    type Target = ServerConnection;
    fn deref(&self) -> &ServerConnection {
        &self.connection
    }
}
impl core::ops::DerefMut for RetainedConnection {
    fn deref_mut(&mut self) -> &mut ServerConnection {
        &mut self.connection
    }
}
#[cfg(test)]
impl RetainedConnection {
    pub(super) fn alias(&self) -> RetainedTlsConfig {
        self._retained.clone()
    }
}
