//! RFC 8555 wire types -- just the fields this client actually reads or
//! writes. Deliberately not exhaustive of the spec (e.g. `meta`,
//! `externalAccountRequired`, `wildcard` aren't modeled) since nothing
//! here uses them yet.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Directory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewAccountPayload {
    #[serde(rename = "termsOfServiceAgreed")]
    pub terms_of_service_agreed: bool,
    pub contact: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub typ: String,
    pub value: String,
}

impl Identifier {
    pub fn dns(domain: impl Into<String>) -> Self {
        Self {
            typ: "dns".to_string(),
            value: domain.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NewOrderPayload {
    pub identifiers: Vec<Identifier>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Order {
    pub status: OrderStatus,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
    /// Per RFC 8555 §7.1.4, a wildcard identifier's `value` here is
    /// already the bare apex (`example.com`, never `*.example.com`) --
    /// a combined wildcard+apex order's two authorizations (see
    /// `acme::domains_for_issuance`) report the identical
    /// `identifier.value` and are otherwise indistinguishable, but
    /// nothing here needs to tell them apart: each is fulfilled
    /// identically (its own dns-01 challenge, its own TXT record at the
    /// same `_acme-challenge.<apex>` name).
    pub identifier: Identifier,
    pub status: AuthorizationStatus,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub typ: String,
    pub url: String,
    pub status: ChallengeStatus,
    pub token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct FinalizePayload {
    pub csr: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub typ: Option<String>,
    pub detail: Option<String>,
    pub status: Option<u16>,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}): {}",
            self.typ.as_deref().unwrap_or("about:blank"),
            self.status.unwrap_or(0),
            self.detail.as_deref().unwrap_or("no detail")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_real_shaped_directory_response() {
        let raw = r#"{
            "newNonce": "https://acme.example.invalid/acme/new-nonce",
            "newAccount": "https://acme.example.invalid/acme/new-account",
            "newOrder": "https://acme.example.invalid/acme/new-order",
            "revokeCert": "https://acme.example.invalid/acme/revoke-cert",
            "keyChange": "https://acme.example.invalid/acme/key-change",
            "meta": { "termsOfService": "https://acme.example.invalid/terms" }
        }"#;
        let dir: Directory = serde_json::from_str(raw).unwrap();
        assert_eq!(dir.new_nonce, "https://acme.example.invalid/acme/new-nonce");
        assert_eq!(dir.new_order, "https://acme.example.invalid/acme/new-order");
    }

    #[test]
    fn parses_order_with_all_status_variants() {
        for (raw_status, expected) in [
            ("pending", OrderStatus::Pending),
            ("ready", OrderStatus::Ready),
            ("processing", OrderStatus::Processing),
            ("valid", OrderStatus::Valid),
            ("invalid", OrderStatus::Invalid),
        ] {
            let raw = format!(
                r#"{{"status":"{raw_status}","authorizations":["https://a.example.invalid/1"],"finalize":"https://a.example.invalid/finalize","certificate":null}}"#
            );
            let order: Order = serde_json::from_str(&raw).unwrap();
            assert_eq!(order.status, expected);
        }
    }

    #[test]
    fn parses_authorization_with_dns01_challenge() {
        let raw = r#"{
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "pending",
            "challenges": [
                {
                    "type": "dns-01",
                    "url": "https://acme.example.invalid/chall/abc",
                    "status": "pending",
                    "token": "the-token-value"
                }
            ]
        }"#;
        let auth: Authorization = serde_json::from_str(raw).unwrap();
        assert_eq!(auth.identifier.value, "example.com");
        assert_eq!(auth.challenges.len(), 1);
        assert_eq!(auth.challenges[0].typ, "dns-01");
        assert_eq!(auth.challenges[0].token, "the-token-value");
    }

    #[test]
    fn identifier_dns_helper_produces_correct_type() {
        let id = Identifier::dns("example.com");
        assert_eq!(id.typ, "dns");
        assert_eq!(id.value, "example.com");
    }

    #[test]
    fn problem_document_formats_readably() {
        let raw = r#"{"type":"urn:ietf:params:acme:error:malformed","detail":"bad request","status":400}"#;
        let problem: Problem = serde_json::from_str(raw).unwrap();
        let msg = problem.to_string();
        assert!(msg.contains("malformed"));
        assert!(msg.contains("bad request"));
        assert!(msg.contains("400"));
    }
}
