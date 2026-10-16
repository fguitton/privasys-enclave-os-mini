//! Top-level rustls config allocation and its opaque cached/session owner.
//! The selected provider Arc and its two default-list Vec backings share this
//! config lifetime. The selected P256 key/signature is included; certificate
//! buffers, rcgen startup and handshake record children remain separate.
use enclave_os_common::allocation::{
    shared_allocation_bytes, AllocationPoolV1, SharedAllocationReservationV1, SharedAllocationV1,
};
use rustls::{ServerConfig, ServerConnection};
use std::sync::Arc;

#[cfg(test)]
#[path = "record_owner_check.rs"]
mod record_owner_check;

struct Payload {
    config: Arc<ServerConfig>,
    // Every config/connection alias precedes the certificate byte/outer-Vec
    // credit. The final shared payload owns both until the final alias drops.
    _certificates: Option<enclave_os_common::allocation::AllocationLeaseV1>,
    _key_spki: Option<enclave_os_common::allocation::AllocationLeaseV1>,
}

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
        .checked_add(authentication.allocation_bytes()?)?
        .checked_add(default_children_bytes()?)
}
fn default_children_bytes() -> Option<usize> {
    #[cfg(feature = "fallible-allocation-v1")]
    {
        let mut bytes = 0_usize;
        for layout in rustls::server::server_config_default_payload_layouts()
            .into_iter()
            .chain(rustls::server::server_config_certificate_payload_layouts())
        {
            bytes = bytes.checked_add(
                enclave_os_common::allocation::shared_allocation_bytes_for_layout(layout)?,
            )?;
        }
        for layout in rustls::server::server_config_default_buffer_layouts().ok()? {
            bytes = bytes.checked_add(layout.size())?;
        }
        Some(bytes)
    }
    #[cfg(not(feature = "fallible-allocation-v1"))]
    {
        Some(0)
    }
}
#[derive(Clone)]
pub(crate) struct RetainedTlsConfig(SharedAllocationV1<Payload>);
pub(crate) struct ConfigReservation {
    allocation: SharedAllocationReservationV1<Payload>,
    authentication: ClientAuthentication,
    pool: Arc<AllocationPoolV1>,
}

impl RetainedTlsConfig {
    #[cfg(test)]
    pub(crate) fn required_bytes(authentication: ClientAuthentication) -> Option<usize> {
        SharedAllocationV1::<Payload>::required_bytes(retained_children_bytes(authentication)?)
    }
    pub(crate) fn reserve(
        pool: &Arc<AllocationPoolV1>,
        authentication: ClientAuthentication,
    ) -> Option<ConfigReservation> {
        SharedAllocationV1::<Payload>::reserve(pool, retained_children_bytes(authentication)?).map(
            |allocation| ConfigReservation {
                allocation,
                authentication,
                pool: pool.clone(),
            },
        )
    }
    #[cfg(target_vendor = "teaclave")]
    pub(crate) fn accept(
        self,
        accepted: rustls::server::Accepted,
    ) -> Result<RetainedConnection, (rustls::Error, rustls::server::AcceptedAlert)> {
        let connection = accepted.into_connection(Arc::clone(&self.0.config))?;
        Ok(RetainedConnection {
            connection,
            _retained: self,
        })
    }
    #[cfg(test)]
    pub(crate) fn connect(self) -> Result<RetainedConnection, rustls::Error> {
        let connection = ServerConnection::new(Arc::clone(&self.0.config))?;
        Ok(RetainedConnection {
            connection,
            _retained: self,
        })
    }
}
impl ConfigReservation {
    pub(crate) fn certificate_bytes(
        certificates: &[rustls::pki_types::CertificateDer<'_>],
    ) -> Option<usize> {
        let mut bytes = core::alloc::Layout::array::<rustls::pki_types::CertificateDer<'static>>(
            certificates.len(),
        )
        .ok()?
        .size();
        for certificate in certificates {
            bytes = bytes.checked_add(
                core::alloc::Layout::array::<u8>(certificate.len())
                    .ok()?
                    .size(),
            )?;
        }
        Some(bytes)
    }
    #[cfg(test)]
    pub(crate) fn factory_bytes(
        certificates: &[rustls::pki_types::CertificateDer<'_>],
        key: &rustls::pki_types::PrivateKeyDer<'_>,
    ) -> Option<(usize, usize)> {
        let bytes = Self::certificate_bytes(certificates)?;
        #[cfg(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave")))]
        {
            let layouts =
                rustls::crypto::ring::sign::retained_p256_spki_layouts_for_key(key).ok()?;
            let retained = bytes.checked_add(layouts.last()?.size())?;
            let peak = layouts
                .into_iter()
                .try_fold(bytes, |sum, layout| sum.checked_add(layout.size()))?;
            Some((peak, retained))
        }
        #[cfg(not(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave"))))]
        {
            let _ = key;
            Some((bytes, bytes))
        }
    }
    pub(crate) fn configure(
        self,
        certificates: &[rustls::pki_types::CertificateDer<'_>],
        key: rustls::pki_types::PrivateKeyDer<'_>,
    ) -> Result<RetainedTlsConfig, String> {
        let certificate_bytes = Self::certificate_bytes(certificates).ok_or_else(String::new)?;
        let certificate_credit = self
            .pool
            .reserve_unpublished(certificate_bytes)
            .ok_or_else(String::new)?;
        let mut certs = Vec::new();
        certs
            .try_reserve_exact(certificates.len())
            .map_err(|_| String::new())?;
        if certs.capacity() != certificates.len() {
            return Err(String::new());
        }
        for certificate in certificates {
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(certificate.len())
                .map_err(|_| String::new())?;
            if bytes.capacity() != certificate.len() {
                return Err(String::new());
            }
            bytes.extend_from_slice(certificate.as_ref());
            certs.push(rustls::pki_types::CertificateDer::from(bytes));
        }
        #[cfg(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave")))]
        let (key_spki_credit, working_credit) = {
            let [algorithm, bits, retained] =
                rustls::crypto::ring::sign::retained_p256_spki_layouts_for_key(&key)
                    .map_err(|_| String::new())?;
            let retained = self
                .pool
                .reserve_unpublished(retained.size())
                .ok_or_else(String::new)?;
            let working = self
                .pool
                .reserve_unpublished(
                    algorithm
                        .size()
                        .checked_add(bits.size())
                        .ok_or_else(String::new)?,
                )
                .ok_or_else(String::new)?;
            (Some(retained), working)
        };
        #[cfg(not(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave"))))]
        let key_spki_credit = None;
        let builder = self.builder()?;
        #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
        let origin =
            enclave_os_common::allocation::LoanAllocator::from_pool_unpublished(&self.pool)
                .map_err(|_| String::new())?;
        #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
        let allocator = origin.owned_allocator();
        #[cfg(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave")))]
        let allocator = rustls::RetainedAllocator::default();
        #[cfg(feature = "fallible-allocation-v1")]
        let config = builder
            .try_with_p256_single_cert_in(certs, key, allocator)
            .map_err(|error| match error {
                rustls::server::ServerConfigAllocationError::Allocation => String::new(),
                rustls::server::ServerConfigAllocationError::PrivateKey => {
                    String::from("cert chain error: invalid current PKCS8 P256 private key")
                }
                rustls::server::ServerConfigAllocationError::Certificate(error) => {
                    format!("cert chain error: {:?}", error)
                }
            })?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let config = builder
            .with_single_cert(certs, key.clone_key())
            .map_err(|e| format!("cert chain error: {:?}", e))?;
        #[cfg(all(feature = "fallible-allocation-v1", not(target_vendor = "teaclave")))]
        drop(working_credit);
        let config = self
            .finish(config, Some(certificate_credit), key_spki_credit)
            .ok_or_else(String::new)?;
        #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
        origin.activate_release_notification();
        Ok(config)
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
        match self.authentication {
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

    fn finish(
        self,
        config: ServerConfig,
        certificates: Option<enclave_os_common::allocation::AllocationLeaseV1>,
        key_spki: Option<enclave_os_common::allocation::AllocationLeaseV1>,
    ) -> Option<RetainedTlsConfig> {
        #[cfg(feature = "fallible-allocation-v1")]
        let config = Arc::try_new(config).ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let config = Arc::new(config);
        #[cfg(feature = "fallible-allocation-v1")]
        let retained = self
            .allocation
            .try_finish(Payload {
                config,
                _certificates: certificates,
                _key_spki: key_spki,
            })
            .ok()?;
        #[cfg(not(feature = "fallible-allocation-v1"))]
        let retained = self.allocation.finish(Payload {
            config,
            _certificates: certificates,
            _key_spki: key_spki,
        });
        if let Some(credit) = &retained._certificates {
            credit.activate_release_notification();
        }
        if let Some(credit) = &retained._key_spki {
            credit.activate_release_notification();
        }
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

#[cfg(all(test, feature = "fallible-allocation-v1"))]
pub(crate) fn client_config_backing_check(
    layout: core::alloc::Layout,
    skip: Option<usize>,
    action: impl FnOnce(),
) -> usize {
    provider_refusal::client_config_backing_check(layout, skip, action)
}
#[cfg(all(test, feature = "fallible-allocation-v1"))]
pub(crate) fn client_config_arc_layout(payload: core::alloc::Layout) -> core::alloc::Layout {
    provider_refusal::client_config_arc_layout(payload)
}

/// Native-only observation: the supplied action must use its explicit allocator.
/// This arm never refuses an allocation or substitutes an allocator.
#[cfg(all(test, feature = "fallible-allocation-v1"))]
pub(crate) fn check_no_global_children<T>(action: impl FnOnce() -> T) -> T {
    provider_refusal::without_global_children(action)
}

/// Native generic payload oracle: permit only the explicit native hash context.
/// This observes exactly one dynamic context Layout, not a trusted pool fallback.
#[cfg(all(test, feature = "fallible-allocation-v1"))]
pub(crate) fn check_one_native_context<T>(
    layout: std::alloc::Layout,
    action: impl FnOnce() -> T,
) -> T {
    provider_refusal::one_native_context(layout, action)
}

/// Observe real traffic processing without refusing any allocation. Other named
/// record/buffer children are outside this state-backing assertion.
#[cfg(all(test, feature = "fallible-allocation-v1"))]
pub(crate) fn check_no_native_state_backing<T>(
    layout: std::alloc::Layout,
    action: impl FnOnce() -> T,
) -> T {
    provider_refusal::no_state_backing(layout, action)
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
        allocations: usize,
        matching_allocations: usize,
        skip_matching: usize,
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
                        if arm.skip_matching == 0 {
                            arm.refused = true;
                            cell.set(Some(arm));
                            return true;
                        }
                        arm.skip_matching -= 1;
                        cell.set(Some(arm));
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
                        arm.allocations += 1;
                        arm.matching_allocations += usize::from(layout == arm.expected);
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

    pub(super) fn without_global_children<T>(action: impl FnOnce() -> T) -> T {
        ARM.with(|cell| {
            assert!(cell.get().is_none());
            cell.set(Some(Arm {
                expected: Layout::new::<u8>(),
                refused: false,
                live: 0,
                allocations: 0,
                matching_allocations: 0,
                skip_matching: usize::MAX,
            }));
        });
        let result = action();
        let arm = ARM.with(|cell| cell.take()).unwrap();
        assert!(!arm.refused);
        assert_eq!(
            arm.allocations, 0,
            "parsed children must use the supplied origin"
        );
        assert_eq!(arm.live, 0);
        result
    }

    pub(super) fn one_native_context<T>(layout: Layout, action: impl FnOnce() -> T) -> T {
        ARM.with(|cell| {
            assert!(cell.get().is_none());
            cell.set(Some(Arm {
                expected: layout,
                refused: false,
                live: 0,
                allocations: 0,
                matching_allocations: 0,
                skip_matching: usize::MAX,
            }));
        });
        let result = action();
        let arm = ARM.with(|cell| cell.take()).unwrap();
        assert!(!arm.refused);
        assert_eq!(
            arm.allocations, 1,
            "only the explicit native context may use Global"
        );
        assert_eq!(
            arm.matching_allocations, 1,
            "the allocation must match the dynamic context Layout"
        );
        assert_eq!(arm.live, 0, "temporary context must be freed on refusal");
        result
    }

    pub(super) fn no_state_backing<T>(layout: Layout, action: impl FnOnce() -> T) -> T {
        ARM.with(|cell| {
            assert!(cell.get().is_none());
            cell.set(Some(Arm {
                expected: layout,
                refused: false,
                live: 0,
                allocations: 0,
                matching_allocations: 0,
                skip_matching: usize::MAX,
            }));
        });
        let result = action();
        let arm = ARM.with(|cell| cell.take()).unwrap();
        assert!(!arm.refused);
        assert_eq!(
            arm.matching_allocations, 0,
            "steady traffic must not request another state slot"
        );
        result
    }

    #[repr(C, align(2))]
    struct ArcHeader {
        strong: AtomicUsize,
        weak: AtomicUsize,
    }
    pub(super) fn client_config_arc_layout(payload: Layout) -> Layout {
        let layout = Layout::new::<ArcHeader>()
            .extend(payload)
            .unwrap()
            .0
            .pad_to_align();
        assert_eq!(
            Some(layout.size()),
            enclave_os_common::allocation::shared_allocation_bytes_for_layout(payload)
        );
        layout
    }
    pub(super) fn client_config_backing_check(
        layout: Layout,
        skip: Option<usize>,
        action: impl FnOnce(),
    ) -> usize {
        ARM.with(|cell| {
            assert!(cell.get().is_none());
            cell.set(Some(Arm {
                expected: layout,
                refused: false,
                live: 0,
                allocations: 0,
                matching_allocations: 0,
                skip_matching: skip.unwrap_or(usize::MAX),
            }));
        });
        action();
        let arm = ARM.with(|cell| cell.take()).unwrap();
        assert_eq!(
            arm.refused,
            skip.is_some(),
            "exact selected config backend refusal"
        );
        assert_eq!(
            arm.live, 0,
            "all actual config backing must free before quote refund"
        );
        arm.matching_allocations
    }

    pub(super) fn check() {
        use rustls::crypto::{ring, CryptoProvider, SupportedKxGroup};
        // Same acquired ArcInner geometry quoted by Common; validate its size
        // against the real production quote before arming the exact request.
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
                    allocations: 0,
                    matching_allocations: 0,
                    skip_matching: 0,
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
        check_default_arcs();
        check_p256_constructor();
        check_input_buffer();
        check_inline_record_keys();
    }
    fn check_inline_record_keys() {
        use rustls::crypto::cipher::{AeadKey, Iv};
        for (suite, independent) in [
            (
                rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
                &ring::aead::AES_256_GCM,
            ),
            (
                rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                &ring::aead::CHACHA20_POLY1305,
            ),
        ] {
            let cipher = suite.tls13().unwrap().aead_alg;
            ARM.with(|cell| {
                cell.set(Some(Arm {
                    expected: Layout::new::<rustls::crypto::cipher::SelectedEncrypter>(),
                    refused: false,
                    live: 0,
                    allocations: 0,
                    matching_allocations: 0,
                    skip_matching: usize::MAX,
                }))
            });
            let enc = cipher.encrypter(AeadKey::from([7; 32]), Iv::from([0; 12]));
            let dec = cipher.decrypter(AeadKey::from([7; 32]), Iv::from([0; 12]));
            drop(enc);
            drop(dec);
            let arm = ARM.with(|cell| cell.take()).unwrap();
            assert!(!arm.refused);
            assert_eq!(
                arm.allocations, 0,
                "actual ring record keys must stay inline"
            );
            assert_eq!(arm.live, 0);
            super::record_owner_check::check_record_wire(
                suite,
                independent,
                rustls::RetainedAllocator::default(),
            );
        }
    }

    fn check_input_buffer() {
        use rustls::server::Acceptor;
        use std::io::{Cursor, ErrorKind};
        let first = Acceptor::initial_read_layout();
        let input = vec![7; first.size()];
        for growth in [false, true] {
            ARM.with(|cell| {
                cell.set(Some(Arm {
                    expected: first,
                    refused: false,
                    live: 0,
                    allocations: 0,
                    matching_allocations: 0,
                    skip_matching: if growth { usize::MAX } else { 0 },
                }))
            });
            let mut acceptor = Acceptor::new_in(rustls::RetainedAllocator::default());
            if growth {
                assert_eq!(
                    acceptor
                        .read_tls(&mut Cursor::new(input.as_slice()))
                        .unwrap(),
                    first.size()
                );
                ARM.with(|cell| {
                    let mut arm = cell.get().unwrap();
                    arm.expected =
                        Layout::array::<u8>(first.size().checked_mul(2).unwrap()).unwrap();
                    arm.skip_matching = 0;
                    cell.set(Some(arm));
                });
            }
            let mut cursor = Cursor::new([8]);
            let error = acceptor.read_tls(&mut cursor).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::OutOfMemory);
            drop(error);
            assert_eq!(cursor.position(), 0);
            drop(acceptor);
            let arm = ARM.with(|cell| cell.take()).unwrap();
            assert!(arm.refused);
            assert_eq!(arm.live, 0);
        }
    }

    fn check_p256_constructor() {
        use rustls::crypto::ring::sign::{any_ecdsa_type, try_p256_signing_key_in};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::server::ServerConfigAllocationError;
        let original = rcgen::KeyPair::generate().unwrap();
        let der = original.serialize_der();
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der.as_slice()));
        // The exact new Arc payload geometry comes from the private supplier
        // types; no guessed payload/header size or blanket OOM injection.
        for payload in rustls::server::server_config_certificate_payload_layouts()
            .into_iter()
            .skip(2)
        {
            let expected = Layout::new::<ArcHeader>()
                .extend(payload)
                .unwrap()
                .0
                .pad_to_align();
            ARM.with(|cell| {
                cell.set(Some(Arm {
                    expected,
                    refused: false,
                    live: 0,
                    allocations: 0,
                    matching_allocations: 0,
                    skip_matching: 0,
                }))
            });
            let result = try_p256_signing_key_in(&private, rustls::RetainedAllocator::default());
            let refused = matches!(result, Err(ServerConfigAllocationError::Allocation));
            drop(result);
            let arm = ARM.with(|cell| cell.take()).unwrap();
            assert!(
                arm.refused && refused,
                "actual P256 Arc refusal must propagate"
            );
            assert_eq!(arm.live, 0, "all key metadata and SPKI free on refusal");
        }
        for refuse in 1..=3 {
            let counts = Arc::new(P256Counts::default());
            counts
                .refuse
                .store(refuse, std::sync::atomic::Ordering::SeqCst);
            let result = try_p256_signing_key_in(&private, P256Allocator(counts.clone()));
            assert!(matches!(
                result,
                Err(ServerConfigAllocationError::Allocation)
            ));
            drop(result);
            assert_eq!(
                counts.calls.load(std::sync::atomic::Ordering::SeqCst),
                refuse
            );
            assert_eq!(counts.live.load(std::sync::atomic::Ordering::SeqCst), 0);
            assert_eq!(Arc::strong_count(&counts), 1);
        }
        let counts = Arc::new(P256Counts::default());
        let creator = P256Allocator(counts.clone());
        let retained = try_p256_signing_key_in(&private, creator.clone()).unwrap();
        let ordinary = any_ecdsa_type(&private).unwrap();
        let expected = ordinary.public_key().unwrap().as_ref().to_vec();
        assert_eq!(retained.public_key().unwrap().as_ref(), expected);
        assert!(retained
            .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP384_SHA384])
            .is_none());
        // Actual selected scheme/sign/clone scope: the original pair/key is
        // retained, and the test counter arms without refusing any request.
        ARM.with(|cell| {
            cell.set(Some(Arm {
                expected: Layout::new::<rustls::sign::Signature>(),
                refused: false,
                live: 0,
                allocations: 0,
                matching_allocations: 0,
                skip_matching: usize::MAX,
            }))
        });
        let signer = retained
            .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap();
        let message = b"current retained P256 signature";
        let signature = signer.sign(message).unwrap();
        let copied_signature = signature.clone();
        let refusal = rustls::Error::SigningFailed;
        let cloned_refusal = refusal.clone();
        drop(signer);
        let arm = ARM.with(|cell| cell.take()).unwrap();
        assert!(!arm.refused);
        assert_eq!(
            arm.allocations, 0,
            "selected signer/signature/clone must allocate nothing"
        );
        assert_eq!(arm.live, 0);
        assert_eq!(refusal, cloned_refusal);
        assert_eq!(format!("{refusal}"), "unexpected error: signing failed");
        assert_eq!(signature.as_ref(), copied_signature.as_ref());
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            original.public_key_raw(),
        )
        .verify(message, signature.as_ref())
        .unwrap();
        let mut corrupted = signature.as_ref().to_vec();
        corrupted[0] ^= 1;
        assert!(ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            original.public_key_raw()
        )
        .verify(message, &corrupted)
        .is_err());
        let alias = retained.clone();
        drop(creator);
        drop(retained);
        assert!(counts.live.load(std::sync::atomic::Ordering::SeqCst) > 0);
        std::thread::spawn(move || {
            assert_eq!(alias.public_key().unwrap().as_ref(), expected);
            drop(alias);
        })
        .join()
        .unwrap();
        assert_eq!(counts.live.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&counts), 1);
        // Inline signature bytes remain valid after the key/SPKI origin is gone.
        assert_eq!(signature.as_ref(), copied_signature.as_ref());
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            original.public_key_raw(),
        )
        .verify(message, copied_signature.as_ref())
        .unwrap();
        let malformed = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(&[0_u8][..]));
        assert!(matches!(
            try_p256_signing_key_in(&malformed, std::alloc::Global),
            Err(ServerConfigAllocationError::PrivateKey)
        ));
        check_mismatched_p256_certificate(&original);
    }
    fn check_mismatched_p256_certificate(original: &rcgen::KeyPair) {
        let cert = rcgen::CertificateParams::new(vec!["mismatch.test".into()])
            .unwrap()
            .self_signed(original)
            .unwrap()
            .der()
            .to_vec();
        let different = rcgen::KeyPair::generate().unwrap();
        let authentication = ClientAuthentication::Anonymous;
        let certificates = [rustls::pki_types::CertificateDer::from(cert)];
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(different.serialize_der()),
        );
        let (certificate_bytes, _) =
            ConfigReservation::factory_bytes(&certificates, &private_key).unwrap();
        let pool = AllocationPoolV1::new(
            RetainedTlsConfig::required_bytes(authentication)
                .unwrap()
                .checked_add(certificate_bytes)
                .unwrap(),
        )
        .unwrap();
        let result = RetainedTlsConfig::reserve(&pool, authentication)
            .unwrap()
            .configure(&certificates, private_key);
        assert!(
            result.is_err(),
            "original keys_match must still reject a different key"
        );
        drop(result);
        assert_eq!(pool.used(), 0);
    }
    #[derive(Default)]
    struct P256Counts {
        calls: AtomicUsize,
        live: AtomicUsize,
        refuse: AtomicUsize,
    }
    #[derive(Clone)]
    struct P256Allocator(Arc<P256Counts>);
    unsafe impl std::alloc::Allocator for P256Allocator {
        fn allocate(
            &self,
            layout: Layout,
        ) -> Result<core::ptr::NonNull<[u8]>, std::alloc::AllocError> {
            use std::sync::atomic::Ordering::SeqCst;
            let call = self.0.calls.fetch_add(1, SeqCst) + 1;
            if call == self.0.refuse.load(SeqCst) {
                return Err(std::alloc::AllocError);
            }
            let block = std::alloc::Global.allocate(layout)?;
            self.0.live.fetch_add(layout.size(), SeqCst);
            Ok(block)
        }
        unsafe fn deallocate(&self, pointer: core::ptr::NonNull<u8>, layout: Layout) {
            unsafe { std::alloc::Global.deallocate(pointer, layout) };
            self.0
                .live
                .fetch_sub(layout.size(), std::sync::atomic::Ordering::SeqCst);
        }
    }
    fn check_default_arcs() {
        let payloads = rustls::server::server_config_default_payload_layouts();
        let layouts: Vec<_> = payloads
            .iter()
            .map(|payload| {
                Layout::new::<ArcHeader>()
                    .extend(*payload)
                    .unwrap()
                    .0
                    .pad_to_align()
            })
            .collect();
        for (index, expected) in layouts.iter().copied().enumerate() {
            let skip_matching = layouts[..index]
                .iter()
                .filter(|layout| **layout == expected)
                .count();
            ARM.with(|cell| {
                cell.set(Some(Arm {
                    expected,
                    refused: false,
                    live: 0,
                    allocations: 0,
                    matching_allocations: 0,
                    skip_matching,
                }))
            });
            let result = rustls::server::ServerConfigDefaults::try_new_in(
                rustls::RetainedAllocator::default(),
            );
            let refused = result.is_err();
            drop(result);
            let arm = ARM.with(|cell| cell.take()).unwrap();
            assert!(
                arm.refused,
                "actual selected default Arc must hit the chosen request"
            );
            assert!(refused);
            assert_eq!(
                arm.live, 0,
                "every prepared default/cache backing must free on refusal"
            );
        }
    }
}
