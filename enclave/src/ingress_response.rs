//! Bounded response shape shared with the actual native TLS fixture.
pub struct HonestIngressResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: crate::HttpResponsePayload,
}
