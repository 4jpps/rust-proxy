//! http-01 challenge fulfillment (RFC 8555 §8.3) -- the alternative to
//! dns-01 that needs no DNS provider credentials at all, at the cost of
//! requiring port 80 to be reachable on the host's own domain (never
//! valid for wildcard identifiers, which always use dns-01 -- see
//! `acme::resolve_challenge_type`).
//!
//! Unlike dns-01's TXT record (a SHA-256 digest of the key
//! authorization), http-01 serves the key authorization itself, in the
//! clear, at a well-known path -- fulfillment here is just "hold this
//! string in memory until validation is done" (`state::AppState`'s
//! `http01_challenges` map), not an API call to a third party.

use super::jws::AccountKey;

/// Every http-01 challenge is validated at
/// `http://<domain>/.well-known/acme-challenge/<token>` -- this is the
/// path prefix `proxy::mod`'s port-80 listener checks incoming requests
/// against before falling through to its normal redirect behavior.
pub const CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge/";

/// RFC 8555 §8.1: `keyAuthorization = token || "." || jwkThumbprint`.
/// This exact string (not a digest of it, unlike dns-01's TXT record
/// content) is what the CA expects to fetch back over plain HTTP.
pub fn key_authorization(token: &str, account_key: &AccountKey) -> String {
    format!("{token}.{}", account_key.jwk_thumbprint())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_authorization_is_deterministic_for_the_same_token_and_key() {
        let (key, _) = AccountKey::generate().unwrap();
        let a = key_authorization("token-abc", &key);
        let b = key_authorization("token-abc", &key);
        assert_eq!(a, b);
        assert_eq!(a, format!("token-abc.{}", key.jwk_thumbprint()));
    }

    #[test]
    fn key_authorization_differs_for_different_tokens() {
        let (key, _) = AccountKey::generate().unwrap();
        let a = key_authorization("token-one", &key);
        let b = key_authorization("token-two", &key);
        assert_ne!(a, b);
    }
}
