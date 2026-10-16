//! One retained current OIDC configuration; field backing is moved, never cloned.
use super::OidcConfig;
use crate::{
    allocation::AllocationLeaseV1,
    request_json::{OwnedText, Refusal, Text},
};

/// Named field credits follow the current DTO's typed members, not a numeric count.
struct FieldCredits {
    _issuer: Option<AllocationLeaseV1>,
    _audience: Option<AllocationLeaseV1>,
    _jwks_uri: Option<AllocationLeaseV1>,
    _role_claim: Option<AllocationLeaseV1>,
    _manager_role: Option<AllocationLeaseV1>,
    _monitoring_role: Option<AllocationLeaseV1>,
}
/// Immutable current config. The payload is destroyed before any field credit.
/// Sharing this owner aliases the same strings; no owned inner value can escape.
pub struct RetainedOidcConfig {
    config: OidcConfig,
    _credits: FieldCredits,
}
impl RetainedOidcConfig {
    /// Move each admitted current DTO field into the retained configuration.
    /// # Errors
    /// Refuses borrowed nonempty fields: retaining them would require a new,
    /// separately admitted copy rather than silently allocating one here.
    pub fn new(
        issuer: Text<'static>,
        audience: Text<'static>,
        jwks_uri: Text<'static>,
        role_claim: Text<'static>,
        manager_role: Text<'static>,
        monitoring_role: Text<'static>,
    ) -> Result<Self, Refusal> {
        // During every fallible conversion, each original String and credit
        // remain in one backing-first owner. No naked String outlives its payer.
        let issuer = issuer.into_owned()?;
        let audience = audience.into_owned()?;
        let jwks_uri = jwks_uri.into_owned()?;
        let role_claim = role_claim.into_owned()?;
        let manager_role = manager_role.into_owned()?;
        let monitoring_role = monitoring_role.into_owned()?;
        let OwnedText {
            value: issuer,
            credit: issuer_credit,
        } = issuer;
        let OwnedText {
            value: audience,
            credit: audience_credit,
        } = audience;
        let OwnedText {
            value: jwks_uri,
            credit: jwks_uri_credit,
        } = jwks_uri;
        let OwnedText {
            value: role_claim,
            credit: role_claim_credit,
        } = role_claim;
        let OwnedText {
            value: manager_role,
            credit: manager_role_credit,
        } = manager_role;
        let OwnedText {
            value: monitoring_role,
            credit: monitoring_role_credit,
        } = monitoring_role;
        Ok(Self {
            config: OidcConfig {
                issuer,
                audience,
                jwks_uri,
                role_claim,
                manager_role,
                monitoring_role,
            },
            _credits: FieldCredits {
                _issuer: issuer_credit,
                _audience: audience_credit,
                _jwks_uri: jwks_uri_credit,
                _role_claim: role_claim_credit,
                _manager_role: manager_role_credit,
                _monitoring_role: monitoring_role_credit,
            },
        })
    }
}
impl core::ops::Deref for RetainedOidcConfig {
    type Target = OidcConfig;
    fn deref(&self) -> &Self::Target {
        &self.config
    }
}
