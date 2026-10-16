//! Private single-connection config graph. Exact Global-backed Arc/DER/vector
//! layouts are admitted before their fallible constructors; the inline owner
//! outlives the connection and every private resolver/config alias.
use super::*;
#[cfg(feature = "fallible-allocation-v1")]
use core::alloc::Layout;
use enclave_os_common::allocation::{AllocationLeaseV1, AllocationPoolV1};

#[cfg(feature = "fallible-allocation-v1")]
use enclave_os_common::allocation::{shared_allocation_bytes, shared_allocation_bytes_for_layout};
type Pool = Arc<AllocationPoolV1>;
#[cfg(feature = "fallible-allocation-v1")]
const REFUSED: &str = "TLS config allocation refused";

pub(crate) struct RetainedClientConfig {
    config: Arc<ClientConfig>,
    identity: Option<Arc<IdentityClientAuth>>,
    name_bytes: usize,
    // All config/resolver aliases precede credit. The caller keeps this owner
    // after its connection field; no owned config Arc is publicly exposed.
    credit: Option<AllocationLeaseV1>,
    #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
    origin: Option<enclave_os_common::allocation::LoanAllocator>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NameError {
    Allocation,
    Invalid,
}
impl RetainedClientConfig {
    pub(crate) fn config(&self) -> Arc<ClientConfig> {
        self.config.clone()
    }
    pub(super) fn identity(&self) -> Option<&Arc<IdentityClientAuth>> {
        self.identity.as_ref()
    }
    pub(crate) fn server_name(&self, source: &str) -> Result<ServerName<'static>, NameError> {
        if source.len() != self.name_bytes {
            return Err(NameError::Allocation);
        }
        let mut value = String::new();
        value
            .try_reserve_exact(source.len())
            .map_err(|_| NameError::Allocation)?;
        if value.capacity() != source.len() {
            return Err(NameError::Allocation);
        }
        value.push_str(source);
        ServerName::try_from(value).map_err(|_| NameError::Invalid)
    }
    pub(crate) fn publish(&self) {
        if let Some(credit) = &self.credit {
            credit.activate_release_notification();
        }
        #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
        if let Some(origin) = &self.origin {
            origin.activate_release_notification();
        }
    }
}

#[cfg(feature = "fallible-allocation-v1")]
fn try_arc<T>(value: T) -> Result<Arc<T>, &'static str> {
    #[cfg(feature = "fallible-allocation-v1")]
    {
        Arc::try_new(value).map_err(|_| REFUSED)
    }
    #[cfg(not(feature = "fallible-allocation-v1"))]
    {
        Ok(Arc::new(value))
    }
}
#[cfg(feature = "fallible-allocation-v1")]
fn copy<T: Copy>(source: &[T]) -> Result<Vec<T>, &'static str> {
    let mut target = Vec::new();
    target
        .try_reserve_exact(source.len())
        .map_err(|_| REFUSED)?;
    if target.capacity() != source.len() {
        return Err(REFUSED);
    }
    target.extend_from_slice(source);
    Ok(target)
}
#[cfg(feature = "fallible-allocation-v1")]
fn text(source: &str) -> Result<String, &'static str> {
    // The input was already a valid String; this moves its exact copied Vec.
    String::from_utf8(copy(source.as_bytes())?).map_err(|_| REFUSED)
}
#[cfg(feature = "fallible-allocation-v1")]
fn identity_bytes(identity: &ClientCertIdentity) -> Option<usize> {
    identity
        .code_hash
        .len()
        .checked_add(identity.app_id.as_ref().map_or(0, Vec::len))
}
#[cfg(feature = "fallible-allocation-v1")]
fn clone_identity(identity: &ClientCertIdentity) -> Result<ClientCertIdentity, &'static str> {
    Ok(ClientCertIdentity {
        code_hash: copy(&identity.code_hash)?,
        app_id: identity
            .app_id
            .as_ref()
            .map(|value| copy(value))
            .transpose()?,
    })
}
#[cfg(feature = "fallible-allocation-v1")]
fn strings_bytes(values: &[String]) -> Option<usize> {
    values.iter().try_fold(
        Layout::array::<String>(values.len()).ok()?.size(),
        |bytes, value| bytes.checked_add(value.len()),
    )
}
#[cfg(feature = "fallible-allocation-v1")]
fn clone_strings(values: &[String]) -> Result<Vec<String>, &'static str> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| REFUSED)?;
    if result.capacity() != values.len() {
        return Err(REFUSED);
    }
    for value in values {
        result.push(text(value)?);
    }
    Ok(result)
}
#[cfg(feature = "fallible-allocation-v1")]
fn policy_bytes(policy: &RaTlsPolicy) -> Option<usize> {
    let mut bytes = Layout::array::<ExpectedOid>(policy.expected_oids.len())
        .ok()?
        .size();
    for expected in &policy.expected_oids {
        bytes = bytes
            .checked_add(expected.oid.len())?
            .checked_add(expected.expected_value.len())?;
    }
    bytes = bytes
        .checked_add(strings_bytes(&policy.attestation_servers)?)?
        .checked_add(strings_bytes(&policy.acceptable_tcb_statuses)?)?
        .checked_add(policy.dependencies.as_ref().map_or(0, Vec::len))?;
    if let ReportDataBinding::ChallengeResponse { nonce } = &policy.report_data {
        bytes = bytes.checked_add(nonce.len())?;
    }
    if let Some(identity) = &policy.client_identity {
        bytes = bytes.checked_add(identity_bytes(identity)?)?;
    }
    Some(bytes)
}
#[cfg(feature = "fallible-allocation-v1")]
fn clone_policy(policy: &RaTlsPolicy) -> Result<RaTlsPolicy, &'static str> {
    let mut expected_oids = Vec::new();
    expected_oids
        .try_reserve_exact(policy.expected_oids.len())
        .map_err(|_| REFUSED)?;
    if expected_oids.capacity() != policy.expected_oids.len() {
        return Err(REFUSED);
    }
    for expected in &policy.expected_oids {
        expected_oids.push(ExpectedOid {
            oid: text(&expected.oid)?,
            expected_value: copy(&expected.expected_value)?,
        });
    }
    Ok(RaTlsPolicy {
        tee: policy.tee,
        mr_enclave: policy.mr_enclave,
        mr_signer: policy.mr_signer,
        mr_td: policy.mr_td,
        report_data: match &policy.report_data {
            ReportDataBinding::Deterministic => ReportDataBinding::Deterministic,
            ReportDataBinding::ChallengeResponse { nonce } => {
                ReportDataBinding::ChallengeResponse {
                    nonce: copy(nonce)?,
                }
            }
        },
        expected_oids,
        attestation_servers: clone_strings(&policy.attestation_servers)?,
        acceptable_tcb_statuses: clone_strings(&policy.acceptable_tcb_statuses)?,
        client_identity: policy
            .client_identity
            .as_ref()
            .map(clone_identity)
            .transpose()?,
        dependencies: policy
            .dependencies
            .as_ref()
            .map(|value| copy(value))
            .transpose()?,
    })
}

#[cfg(feature = "fallible-allocation-v1")]
fn required_bytes(
    name: &str,
    roots: Option<&RootCertStore>,
    policy: Option<&RaTlsPolicy>,
    attested: bool,
) -> Option<usize> {
    use rustls::crypto::{ring, SupportedKxGroup};
    let mut bytes = shared_allocation_bytes::<ClientConfig>()?
        .checked_add(name.len())?
        .checked_add(shared_allocation_bytes::<CryptoProvider>()?)?
        .checked_add(
            Layout::array::<rustls::SupportedCipherSuite>(ring::DEFAULT_CIPHER_SUITES.len())
                .ok()?
                .size(),
        )?
        .checked_add(
            Layout::array::<&'static dyn SupportedKxGroup>(ring::DEFAULT_KX_GROUPS.len())
                .ok()?
                .size(),
        )?
        .checked_add(shared_allocation_bytes::<
            rustls::time_provider::DefaultTimeProvider,
        >()?)?;
    for layout in rustls::client::client_config_single_use_payload_layouts() {
        bytes = bytes.checked_add(shared_allocation_bytes_for_layout(layout)?)?;
    }
    for layout in rustls::client::client_config_default_buffer_layouts().ok()? {
        bytes = bytes.checked_add(layout.size())?;
    }
    if let Some(roots) = roots {
        bytes = bytes
            .checked_add(shared_allocation_bytes::<RootCertStore>()?)?
            .checked_add(roots.clone_allocation_bytes()?)?
            .checked_add(shared_allocation_bytes::<WebPkiServerVerifier>()?)?;
    }
    if let Some(policy) = policy {
        bytes = bytes.checked_add(policy_bytes(policy)?)?;
        #[cfg(not(feature = "sgx-sim-attestation"))]
        {
            bytes = bytes.checked_add(if attested {
                shared_allocation_bytes::<AttestedRaTlsVerifier>()?
            } else {
                shared_allocation_bytes::<RaTlsVerifier>()?
            })?;
        }
        #[cfg(feature = "sgx-sim-attestation")]
        {
            bytes = bytes.checked_add(shared_allocation_bytes::<AttestedRaTlsVerifier>()?)?;
        }
        if let Some(identity) = &policy.client_identity {
            bytes = bytes
                .checked_add(shared_allocation_bytes::<IdentityClientAuth>()?)?
                .checked_add(identity_bytes(identity)?)?;
        } else {
            bytes = bytes.checked_add(shared_allocation_bytes_for_layout(
                rustls::client::client_config_no_auth_payload_layout(),
            )?)?;
        }
    } else {
        bytes = bytes.checked_add(shared_allocation_bytes_for_layout(
            rustls::client::client_config_no_auth_payload_layout(),
        )?)?;
    }
    #[cfg(not(target_vendor = "teaclave"))]
    {
        bytes = bytes.checked_add(
            rustls::client::client_config_default_owned_buffer_layout()
                .ok()?
                .size(),
        )?;
    }
    if attested {
        bytes = bytes
            .checked_add(Layout::array::<Vec<u8>>(1).ok()?.size())?
            .checked_add(b"honest-local-control/1".len())?;
    }
    Some(bytes)
}

#[cfg(feature = "fallible-allocation-v1")]
pub(super) fn required_pool_bytes(
    name: &str,
    roots: Option<&RootCertStore>,
    policy: Option<&RaTlsPolicy>,
    attested: bool,
) -> Option<usize> {
    let bytes = required_bytes(name, roots, policy, attested)?;
    #[cfg(target_vendor = "teaclave")]
    {
        use enclave_os_common::allocation::LoanAllocator;
        let layout = rustls::client::client_config_default_owned_buffer_layout().ok()?;
        bytes
            .checked_add(LoanAllocator::required_origin_bytes()?)?
            .checked_add(LoanAllocator::required_backend_bytes(layout).ok()?)
    }
    #[cfg(not(target_vendor = "teaclave"))]
    {
        Some(bytes)
    }
}

#[cfg(feature = "fallible-allocation-v1")]
pub(super) fn build(
    name: &str,
    roots: Option<&RootCertStore>,
    policy: Option<&RaTlsPolicy>,
    attested: bool,
    pool: Option<&Pool>,
) -> Result<RetainedClientConfig, &'static str> {
    #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
    if pool.is_none() {
        return Err("trusted TLS config requires the original allocation pool");
    }
    // RA validation already ran in the public current factory, before this quote.
    let bytes = required_bytes(name, roots, policy, attested).ok_or(REFUSED)?;
    let credit = pool
        .map(|pool| pool.reserve_unpublished(bytes).ok_or(REFUSED))
        .transpose()?;
    #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
    let origin = pool
        .map(enclave_os_common::allocation::LoanAllocator::from_pool_unpublished)
        .transpose()
        .map_err(|_| REFUSED)?;
    #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
    let allocator = origin.as_ref().ok_or(REFUSED)?.owned_allocator();
    #[cfg(not(all(feature = "fallible-allocation-v1", target_vendor = "teaclave")))]
    let allocator = rustls::RetainedAllocator::default();

    let provider = try_arc(rustls::crypto::ring::try_default_provider().map_err(|_| REFUSED)?)?;
    let time = try_arc(rustls::time_provider::DefaultTimeProvider)?;
    let builder = ClientConfig::builder_with_details(provider.clone(), time)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS config error")?;
    let verifier: Arc<dyn ServerCertVerifier> = if let Some(policy) = policy {
        if attested {
            try_arc(AttestedRaTlsVerifier {
                provider: provider.clone(),
                policy: clone_policy(policy)?,
            })?
        } else {
            #[cfg(not(feature = "sgx-sim-attestation"))]
            {
                let roots = roots.ok_or("WebPKI verifier build error")?;
                if roots.is_empty() {
                    return Err("WebPKI verifier build error");
                }
                let roots = try_arc(roots.try_clone().map_err(|_| REFUSED)?)?;
                let inner = WebPkiServerVerifier::try_new_without_revocation(
                    roots,
                    provider.signature_verification_algorithms,
                )
                .map_err(|_| REFUSED)?;
                try_arc(RaTlsVerifier {
                    inner,
                    policy: clone_policy(policy)?,
                })?
            }
            #[cfg(feature = "sgx-sim-attestation")]
            {
                try_arc(AttestedRaTlsVerifier {
                    provider: provider.clone(),
                    policy: clone_policy(policy)?,
                })?
            }
        }
    } else {
        let roots = roots.ok_or("TLS root store missing")?;
        let roots = try_arc(roots.try_clone().map_err(|_| REFUSED)?)?;
        WebPkiServerVerifier::try_new_without_revocation(
            roots,
            provider.signature_verification_algorithms,
        )
        .map_err(|_| REFUSED)?
    };
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut identity = None;
    let mut config = if let Some(source) = policy.and_then(|policy| policy.client_identity.as_ref())
    {
        let auth = try_arc(IdentityClientAuth {
            identity: clone_identity(source)?,
            pool: pool.cloned(),
            credentials: std::sync::Mutex::new(super::credential::Credentials::Empty),
        })?;
        identity = Some(auth.clone());
        builder
            .try_with_client_cert_resolver_for_connection(auth, allocator)
            .map_err(|_| REFUSED)?
    } else {
        builder
            .try_with_no_client_auth_for_connection(allocator)
            .map_err(|_| REFUSED)?
    };
    if attested {
        config
            .alpn_protocols
            .try_reserve_exact(1)
            .map_err(|_| REFUSED)?;
        if config.alpn_protocols.capacity() != 1 {
            return Err(REFUSED);
        }
        config.alpn_protocols.push(copy(b"honest-local-control/1")?);
    }
    let config = try_arc(config)?;
    Ok(RetainedClientConfig {
        config,
        identity,
        name_bytes: name.len(),
        credit,
        #[cfg(all(feature = "fallible-allocation-v1", target_vendor = "teaclave"))]
        origin,
    })
}

// The unselected standard-library capability keeps ordinary Rustls defaults.
// It is not used as a fallback after selected original-pool refusal.
#[cfg(not(feature = "fallible-allocation-v1"))]
pub(super) fn build(
    name: &str,
    roots: Option<&RootCertStore>,
    policy: Option<&RaTlsPolicy>,
    attested: bool,
    pool: Option<&Pool>,
) -> Result<RetainedClientConfig, &'static str> {
    let _ = pool;
    let provider = Arc::new(default_provider());
    let verifier: Arc<dyn ServerCertVerifier> = if let Some(policy) = policy {
        if attested {
            Arc::new(AttestedRaTlsVerifier {
                provider: provider.clone(),
                policy: policy.clone(),
            })
        } else {
            #[cfg(not(feature = "sgx-sim-attestation"))]
            {
                let roots = roots.ok_or("WebPKI verifier build error")?;
                let inner = WebPkiServerVerifier::builder_with_provider(
                    Arc::new(roots.clone()),
                    provider.clone(),
                )
                .build()
                .map_err(|_| "WebPKI verifier build error")?;
                Arc::new(RaTlsVerifier {
                    inner,
                    policy: policy.clone(),
                })
            }
            #[cfg(feature = "sgx-sim-attestation")]
            {
                Arc::new(AttestedRaTlsVerifier {
                    provider: provider.clone(),
                    policy: policy.clone(),
                })
            }
        }
    } else {
        let roots = roots.ok_or("TLS root store missing")?;
        // Preserve ordinary empty-root validation timing.
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| "TLS config error")?;
        let config = builder
            .with_root_certificates(roots.clone())
            .with_no_client_auth();
        return Ok(RetainedClientConfig {
            config: Arc::new(config),
            identity: None,
            name_bytes: name.len(),
            credit: None,
        });
    };
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| "TLS config error")?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut identity = None;
    let mut config = if let Some(source) = policy.and_then(|policy| policy.client_identity.as_ref())
    {
        let auth = Arc::new(IdentityClientAuth {
            identity: source.clone(),
            pool: pool.cloned(),
            #[cfg(not(feature = "fallible-allocation-v1"))]
            credentials: std::sync::Mutex::new(Vec::new()),
        });
        identity = Some(auth.clone());
        builder.with_client_cert_resolver(auth)
    } else {
        builder.with_no_client_auth()
    };
    if attested {
        config.alpn_protocols = vec![b"honest-local-control/1".to_vec()];
    }
    Ok(RetainedClientConfig {
        config: Arc::new(config),
        identity,
        name_bytes: name.len(),
        credit: None,
    })
}

#[cfg(all(test, feature = "fallible-allocation-v1"))]
pub(crate) fn check(roots: &RootCertStore) {
    use crate::session::retained_tls_config::{
        client_config_arc_layout as arc_layout, client_config_backing_check as backend,
    };
    use core::sync::atomic::{AtomicUsize, Ordering};
    static WAKES: AtomicUsize = AtomicUsize::new(0);
    fn released() {
        WAKES.fetch_add(1, Ordering::AcqRel);
    }
    let policy = RaTlsPolicy {
        tee: TeeType::Sgx,
        mr_enclave: Some([7; 32]),
        mr_signer: None,
        mr_td: None,
        report_data: ReportDataBinding::ChallengeResponse { nonce: vec![3; 32] },
        expected_oids: vec![ExpectedOid {
            oid: "1.2.3".into(),
            expected_value: vec![4; 9],
        }],
        attestation_servers: vec!["https://appraiser.invalid/".into()],
        acceptable_tcb_statuses: vec!["OutOfDate".into()],
        client_identity: Some(ClientCertIdentity {
            code_hash: vec![5; 32],
            app_id: Some(vec![6; 32]),
        }),
        dependencies: Some(vec![8; 11]),
    };
    for (policy, attested) in [(None, false), (Some(&policy), false), (Some(&policy), true)] {
        #[cfg(not(feature = "sgx-sim-attestation"))]
        let selected_roots = (!attested).then_some(roots);
        #[cfg(feature = "sgx-sim-attestation")]
        let selected_roots = (policy.is_none() && !attested).then_some(roots);
        let quote =
            required_pool_bytes("retained.invalid", selected_roots, policy, attested).unwrap();
        let wakes = WAKES.load(Ordering::Acquire);
        let short = AllocationPoolV1::new_with_release(quote - 1, Some(released)).unwrap();
        crate::session::retained_tls_config::check_no_global_children(|| {
            assert!(build(
                "retained.invalid",
                selected_roots,
                policy,
                attested,
                Some(&short)
            )
            .is_err());
        });
        assert_eq!(short.used(), 0);
        assert_eq!(WAKES.load(Ordering::Acquire), wakes);
        for extra in [0, 1] {
            let pool = AllocationPoolV1::new_with_release(quote + extra, Some(released)).unwrap();
            let owner = build(
                "retained.invalid",
                selected_roots,
                policy,
                attested,
                Some(&pool),
            )
            .unwrap();
            let name = owner.server_name("retained.invalid").unwrap();
            assert_eq!(pool.used(), quote);
            assert!(!owner.config.resumption.stores_sessions());
            if attested {
                assert_eq!(
                    owner.config.alpn_protocols,
                    [b"honest-local-control/1".to_vec()]
                );
            }
            assert_eq!(WAKES.load(Ordering::Acquire), wakes + extra);
            owner.publish();
            drop(name);
            drop(owner);
            assert_eq!(pool.used(), 0);
            assert_eq!(WAKES.load(Ordering::Acquire), wakes + extra + 1);
        }
        let pool = AllocationPoolV1::new(quote).unwrap();
        {
            let owner = build(
                "retained.invalid",
                selected_roots,
                policy,
                attested,
                Some(&pool),
            )
            .unwrap();
            let layout = Layout::array::<u8>("retained.invalid".len()).unwrap();
            assert_eq!(
                backend(layout, None, || drop(
                    owner.server_name("retained.invalid").unwrap()
                )),
                1
            );
            backend(layout, Some(0), || {
                assert_eq!(
                    owner.server_name("retained.invalid").err(),
                    Some(NameError::Allocation)
                )
            });
            assert_eq!(pool.used(), quote);
            let retry = owner.server_name("retained.invalid").unwrap();
            drop(retry);
            drop(owner);
            assert_eq!(pool.used(), 0);
        }
        let mut layouts = vec![
            Layout::array::<rustls::SupportedCipherSuite>(
                rustls::crypto::ring::DEFAULT_CIPHER_SUITES.len(),
            )
            .unwrap(),
            Layout::array::<&'static dyn rustls::crypto::SupportedKxGroup>(
                rustls::crypto::ring::DEFAULT_KX_GROUPS.len(),
            )
            .unwrap(),
            arc_layout(Layout::new::<CryptoProvider>()),
            arc_layout(Layout::new::<ClientConfig>()),
            arc_layout(Layout::new::<rustls::time_provider::DefaultTimeProvider>()),
            rustls::client::client_config_default_owned_buffer_layout().unwrap(),
        ];
        layouts.extend(rustls::client::client_config_single_use_payload_layouts().map(arc_layout));
        layouts.extend(rustls::client::client_config_default_buffer_layouts().unwrap());
        if let Some(roots) = selected_roots {
            layouts.push(
                Layout::array::<rustls::pki_types::TrustAnchor<'static>>(roots.roots.len())
                    .unwrap(),
            );
            layouts.push(arc_layout(Layout::new::<RootCertStore>()));
            layouts.push(arc_layout(Layout::new::<WebPkiServerVerifier>()));
            for root in &roots.roots {
                layouts.push(Layout::array::<u8>(root.subject.as_ref().len()).unwrap());
                layouts.push(
                    Layout::array::<u8>(root.subject_public_key_info.as_ref().len()).unwrap(),
                );
            }
        }
        if let Some(policy) = policy {
            layouts.push(Layout::array::<ExpectedOid>(policy.expected_oids.len()).unwrap());
            layouts.push(Layout::array::<String>(policy.attestation_servers.len()).unwrap());
            layouts.push(arc_layout(Layout::new::<IdentityClientAuth>()));
            layouts.push(
                Layout::array::<u8>(policy.client_identity.as_ref().unwrap().code_hash.len())
                    .unwrap(),
            );
            if attested {
                layouts.push(arc_layout(Layout::new::<AttestedRaTlsVerifier>()));
                layouts.push(Layout::array::<Vec<u8>>(1).unwrap());
                layouts.push(Layout::array::<u8>(b"honest-local-control/1".len()).unwrap());
            } else {
                #[cfg(not(feature = "sgx-sim-attestation"))]
                layouts.push(arc_layout(Layout::new::<RaTlsVerifier>()));
                #[cfg(feature = "sgx-sim-attestation")]
                layouts.push(arc_layout(Layout::new::<AttestedRaTlsVerifier>()));
            }
        } else {
            layouts.push(arc_layout(
                rustls::client::client_config_no_auth_payload_layout(),
            ));
        }
        layouts.retain(|layout| layout.size() != 0);
        layouts.sort_unstable_by_key(|layout| (layout.size(), layout.align()));
        layouts.dedup();
        for layout in layouts {
            let requests = backend(layout, None, || {
                drop(
                    build(
                        "retained.invalid",
                        selected_roots,
                        policy,
                        attested,
                        Some(&pool),
                    )
                    .unwrap(),
                )
            });
            assert!(
                requests > 0,
                "selected config layout must be physically requested"
            );
            for skip in 0..requests {
                backend(layout, Some(skip), || {
                    assert!(build(
                        "retained.invalid",
                        selected_roots,
                        policy,
                        attested,
                        Some(&pool)
                    )
                    .is_err())
                });
                assert_eq!(pool.used(), 0);
            }
        }
    }
}
