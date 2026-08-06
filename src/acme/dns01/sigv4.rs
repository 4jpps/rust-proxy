//! Minimal AWS Signature Version 4 request signing -- HMAC-SHA256
//! canonical-request signing per AWS's documented algorithm
//! (https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html),
//! implemented directly rather than depending on an aws-sdk-* crate --
//! same "thin direct reqwest client, no SDK" philosophy as every DNS
//! provider in this module. Used by `route53`; general enough to reuse
//! for another AWS-signed provider later without changes.
//!
//! Deliberately signs only `host` and `x-amz-date` (not a separate
//! `x-amz-content-sha256` header) -- that header is only required by
//! S3, not Route53, and keeping the signed-header set to exactly
//! `host;x-amz-date` is what makes this implementation directly
//! verifiable against AWS's own published SigV4 test vectors (see the
//! test module below). The payload hash is still computed and folded
//! into the canonical request's `HashedPayload` component either way --
//! that part of the algorithm is not S3-specific.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub struct SigV4Signer {
    access_key_id: String,
    secret_access_key: String,
    region: String,
    service: String,
}

pub struct SignedHeaders {
    pub x_amz_date: String,
    pub authorization: String,
}

impl SigV4Signer {
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        region: String,
        service: String,
    ) -> Self {
        Self {
            access_key_id,
            secret_access_key,
            region,
            service,
        }
    }

    /// Signs one request. `canonical_uri` is the already-URI-encoded
    /// absolute path (e.g. `/2013-04-01/hostedzonesbyname`);
    /// `query_pairs` are the *unencoded* query key/value pairs (encoded
    /// and sorted here, per AWS's canonical query string rules); `body`
    /// is the exact bytes that will be sent. `now` is injected so tests
    /// are deterministic.
    pub fn sign(
        &self,
        method: &str,
        host: &str,
        canonical_uri: &str,
        query_pairs: &[(&str, &str)],
        body: &[u8],
        now: chrono::DateTime<chrono::Utc>,
    ) -> SignedHeaders {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let hashed_payload = hex_encode(&Sha256::digest(body));

        let canonical_query = canonical_query_string(query_pairs);
        let canonical_headers = format!("host:{host}\nx-amz-date:{amz_date}\n");
        let signed_headers = "host;x-amz-date";
        let canonical_request =
            format!("{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}");
        let hashed_canonical_request = hex_encode(&Sha256::digest(canonical_request.as_bytes()));

        let credential_scope =
            format!("{date_stamp}/{}/{}/aws4_request", self.region, self.service);
        let string_to_sign =
            format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashed_canonical_request}");

        let signing_key = self.derive_signing_key(&date_stamp);
        let signature = hex_encode(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key_id
        );

        SignedHeaders {
            x_amz_date: amz_date,
            authorization,
        }
    }

    fn derive_signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date = hmac_sha256(
            format!("AWS4{}", self.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = hmac_sha256(&k_region, self.service.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// AWS's canonical query string: URI-encode each key/value with
/// `uri_encode`, then sort entries by encoded key. Empty when there are
/// no query parameters.
fn canonical_query_string(pairs: &[(&str, &str)]) -> String {
    let mut encoded: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (uri_encode(k, true), uri_encode(v, true)))
        .collect();
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// AWS's URI-encoding rules: every byte except unreserved characters
/// (`A-Za-z0-9-_.~`) is percent-encoded, uppercase hex. When
/// `encode_slash` is false (used only for a canonical URI path, never a
/// query string), `/` is also left unencoded.
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real AWS-published SigV4 test vectors -- the "get-vanilla",
    // "get-vanilla-query-order-key-case", and "post-vanilla" cases from
    // AWS's own aws4_testsuite, retrieved from
    // https://github.com/saibotsivad/aws-sig-v4-test-suite (a mirror of
    // AWS's originally-published test suite), fixed test credentials
    // AKIDEXAMPLE / wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, region
    // us-east-1, service "service", date 2015-08-30T12:36:00Z. These are
    // real published test vectors, not self-consistency checks -- a
    // signing bug here would otherwise only surface as a silent 403
    // against the real Route53 API.

    fn test_signer() -> SigV4Signer {
        SigV4Signer::new(
            "AKIDEXAMPLE".to_string(),
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            "us-east-1".to_string(),
            "service".to_string(),
        )
    }

    fn fixed_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2015-08-30T12:36:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn matches_the_aws_get_vanilla_test_vector() {
        let signed = test_signer().sign("GET", "example.amazonaws.com", "/", &[], b"", fixed_now());
        assert_eq!(signed.x_amz_date, "20150830T123600Z");
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn matches_the_aws_post_vanilla_test_vector() {
        let signed =
            test_signer().sign("POST", "example.amazonaws.com", "/", &[], b"", fixed_now());
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
        );
    }

    #[test]
    fn matches_the_aws_get_vanilla_query_order_key_case_test_vector() {
        // Input query params deliberately out of alphabetical order and
        // with mixed case in the key names -- the canonical query string
        // must still come out sorted (Param1 before Param2).
        let signed = test_signer().sign(
            "GET",
            "example.amazonaws.com",
            "/",
            &[("Param2", "value2"), ("Param1", "value1")],
            b"",
            fixed_now(),
        );
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    #[test]
    fn uri_encode_leaves_unreserved_characters_alone_and_percent_encodes_everything_else() {
        assert_eq!(uri_encode("abcXYZ019-_.~", true), "abcXYZ019-_.~");
        assert_eq!(uri_encode("a b", true), "a%20b");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("a/b", false), "a/b");
    }

    #[test]
    fn canonical_query_string_sorts_by_encoded_key() {
        assert_eq!(canonical_query_string(&[("b", "2"), ("a", "1")]), "a=1&b=2");
        assert_eq!(canonical_query_string(&[]), "");
    }
}
