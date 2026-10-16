//! Top-level rustls config allocation and its opaque cached/session owner.
//! The selected provider Arc and its two default-list Vec backings share this
//! config lifetime. Certificate/signing and handshake children remain separate.
use enclave_os_common::allocation::{
    shared_allocation_bytes, AllocationPoolV1, SharedAllocationReservationV1, SharedAllocationV1,
};
use rustls::{ServerConfig, ServerConnection};
use std::sync::Arc;

type Payload = Arc<ServerConfig>;

#[derive(Clone, Copy)]
pub(crate) enum ClientAuthentication {
    Attested {
        required: bool,
    },
    #[cfg(test)]
    Anonymous,
}
impl ClientAuthentication {
    fn allocation_bytes(self) -> Option<usize> {
        match self {
            Self::Attested { .. } => {
                shared_allocation_bytes::<crate::ratls::client_auth::AttestedClientAuth>()
            }
            #[cfg(test)]
            Self::Anonymous => shared_allocation_bytes::<rustls::server::NoClientAuth>(),
        }
    }
}

fn retained_children_bytes(authentication: ClientAuthentication) -> Option<usize> {
    use rustls::crypto::{ring, CryptoProvider, SupportedKxGroup};
    let suites = core::alloc::Layout::array::<rustls::SupportedCipherSuite>(
        ring::DEFAULT_CIPHER_SUITES.len(),
    )
    .ok()?;
    let groups =
        core::alloc::Layout::array::<&'static dyn SupportedKxGroup>(ring::DEFAULT_KX_GROUPS.len())
            .ok()?;
    shared_allocation_bytes::<ServerConfig>()?
        .checked_add(shared_allocation_bytes::<CryptoProvider>()?)?
        .checked_add(suites.size())?
        .checked_add(groups.size())?
        .checked_add(shared_allocation_bytes::<
            rustls::time_provider::DefaultTimeProvider,
        >()?)?
        .checked_add(authentication.allocation_bytes()?)
}
#[derive(Clone)]
pub(crate) struct RetainedTlsConfig(SharedAllocationV1<Payload>);
pub(crate) struct ConfigReservation(SharedAllocationReservationV1<Payload>, ClientAuthentication);

impl RetainedTlsConfig {
    #[cfg(test)]
    pub(crate) fn required_bytes(authentication: ClientAuthentication) -> Option<usize> {
        SharedAllocationV1::<Payload>::required_bytes(retained_children_bytes(authentication)?)
    }
    pub(crate) fn reserve(
        pool: &Arc<AllocationPoolV1>,
        authentication: ClientAuthentication,
    ) -> Option<ConfigReservation> {
        SharedAllocationV1::<Payload>::reserve(pool, retained_children_bytes(authentication)?)
            .map(|reservation| ConfigReservation(reservation, authentication))
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
    pub(crate) fn configure(
        self,
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<RetainedTlsConfig, String> {
        let builder = self.builder()?;
        let config = builder
            .with_single_cert(certs, key)
            .map_err(|e| format!("cert chain error: {:?}", e))?;
        self.finish(config).ok_or_else(String::new)
    }
    fn builder(
        &self,
    ) -> Result<rustls::ConfigBuilder<ServerConfig, rustls::server::WantsServerCert>, String> {
        let provider = self.provider().ok_or_else(String::new)?;
        #[cfg(feature = "fallible-allocation-v1")]
        let time =
            Arc::try_new(rustls::time_provider::DefaultTimeProvider).map_err(|_| String::new())?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let time = Arc::new(rustls::time_provider::DefaultTimeProvider);
        let builder = ServerConfig::builder_with_details(provider.clone(), time)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| format!("TLS config error: {:?}", e))?;
        match self.1 {
            ClientAuthentication::Attested { required } => {
                let verifier =
                    crate::ratls::client_auth::AttestedClientAuth::new(required, provider);
                #[cfg(feature = "fallible-allocation-v1")]
                let verifier = Arc::try_new(verifier).map_err(|_| String::new())?;
                #[cfg(not(feature = "fallible-allocation-v1"))]
                let verifier = Arc::new(verifier);
                Ok(builder.with_client_cert_verifier(verifier))
            }
            #[cfg(test)]
            ClientAuthentication::Anonymous => {
                #[cfg(feature = "fallible-allocation-v1")]
                let verifier =
                    Arc::try_new(rustls::server::NoClientAuth).map_err(|_| String::new())?;
                #[cfg(not(feature = "fallible-allocation-v1"))]
                let verifier = Arc::new(rustls::server::NoClientAuth);
                Ok(builder.with_client_cert_verifier(verifier))
            }
        }
    }
    fn provider(&self) -> Option<Arc<rustls::crypto::CryptoProvider>> {
        #[cfg(feature = "fallible-allocation-v1")]
        let provider = rustls::crypto::ring::try_default_provider().ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let provider = rustls::crypto::ring::default_provider();
        #[cfg(feature = "fallible-allocation-v1")]
        let provider = Arc::try_new(provider).ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let provider = Arc::new(provider);
        Some(provider)
    }

    fn finish(self, config: ServerConfig) -> Option<RetainedTlsConfig> {
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
impl RetainedConnection {
    pub(crate) fn read_tls(&mut self, reader: &mut dyn std::io::Read) -> std::io::Result<usize> {
        self.connection.read_tls(reader)
    }
    pub(crate) fn write_tls(&mut self, writer: &mut dyn std::io::Write) -> std::io::Result<usize> {
        self.connection.write_tls(writer)
    }
    pub(crate) fn process_new_packets(&mut self) -> Result<rustls::IoState, rustls::Error> {
        self.connection.process_new_packets()
    }
    pub(crate) fn reader(&mut self) -> rustls::Reader<'_> {
        self.connection.reader()
    }
    pub(crate) fn writer(&mut self) -> rustls::Writer<'_> {
        self.connection.writer()
    }
    pub(crate) fn send_close_notify(&mut self) {
        self.connection.send_close_notify();
    }
}
#[cfg(test)]
impl RetainedConnection {
    pub(super) fn alias(&self) -> RetainedTlsConfig {
        self._retained.clone()
    }
}

#[cfg(all(test, feature = "fallible-allocation-v1"))]
pub(crate) fn check_provider_allocation_refusals() {
    provider_refusal::check();
}

// This native fixture changes no production allocator. A thread-local arm
// refuses one exact provider request and counts only that constructor's scope.
#[cfg(all(test, feature = "fallible-allocation-v1"))]
mod provider_refusal {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::atomic::AtomicUsize;

    #[derive(Clone, Copy)]
    struct Arm {
        expected: Layout,
        refused: bool,
        live: usize,
    }
    thread_local! {
        static ARM: Cell<Option<Arm>> = const { Cell::new(None) };
    }
    struct ProviderTestAllocator;
    #[global_allocator]
    static ALLOCATOR: ProviderTestAllocator = ProviderTestAllocator;

    unsafe impl GlobalAlloc for ProviderTestAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let refuse = ARM
                .try_with(|cell| {
                    let Some(mut arm) = cell.get() else {
                        return false;
                    };
                    if !arm.refused && arm.expected == layout {
                        arm.refused = true;
                        cell.set(Some(arm));
                        return true;
                    }
                    false
                })
                .unwrap_or(false);
            if refuse {
                return core::ptr::null_mut();
            }
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                let _ = ARM.try_with(|cell| {
                    if let Some(mut arm) = cell.get() {
                        arm.live += 1;
                        cell.set(Some(arm));
                    }
                });
            }
            pointer
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) };
            let _ = ARM.try_with(|cell| {
                if let Some(mut arm) = cell.get() {
                    arm.live -= 1;
                    cell.set(Some(arm));
                }
            });
        }
    }

    pub(super) fn check() {
        use rustls::crypto::{ring, CryptoProvider, SupportedKxGroup};
        // Same acquired ArcInner geometry quoted by Common; validate its size
        // against the real production quote before arming the exact request.
        #[repr(C, align(2))]
        struct ArcHeader {
            strong: AtomicUsize,
            weak: AtomicUsize,
        }
        let arc = Layout::new::<ArcHeader>()
            .extend(Layout::new::<CryptoProvider>())
            .unwrap()
            .0
            .pad_to_align();
        assert_eq!(
            Some(arc.size()),
            shared_allocation_bytes::<CryptoProvider>()
        );
        let time = Layout::new::<ArcHeader>()
            .extend(Layout::new::<rustls::time_provider::DefaultTimeProvider>())
            .unwrap()
            .0
            .pad_to_align();
        let verifier = Layout::new::<ArcHeader>()
            .extend(Layout::new::<crate::ratls::client_auth::AttestedClientAuth>())
            .unwrap()
            .0
            .pad_to_align();
        let authentication = ClientAuthentication::Attested { required: true };
        let layouts = [
            Layout::array::<rustls::SupportedCipherSuite>(ring::DEFAULT_CIPHER_SUITES.len())
                .unwrap(),
            Layout::array::<&'static dyn SupportedKxGroup>(ring::DEFAULT_KX_GROUPS.len()).unwrap(),
            arc,
            time,
            verifier,
        ];
        for expected in layouts {
            let pool =
                AllocationPoolV1::new(RetainedTlsConfig::required_bytes(authentication).unwrap())
                    .unwrap();
            let reservation = RetainedTlsConfig::reserve(&pool, authentication).unwrap();
            ARM.with(|cell| {
                cell.set(Some(Arm {
                    expected,
                    refused: false,
                    live: 0,
                }))
            });
            let result = reservation.builder();
            let arm = ARM.with(|cell| cell.take()).unwrap();
            assert!(
                arm.refused,
                "actual provider request must hit the selected refusal"
            );
            assert!(result.is_err());
            assert_eq!(arm.live, 0, "all prepared provider backing must be freed");
            assert_eq!(
                pool.used(),
                RetainedTlsConfig::required_bytes(authentication).unwrap()
            );
            drop(reservation);
            assert_eq!(pool.used(), 0);
        }
    }
}
