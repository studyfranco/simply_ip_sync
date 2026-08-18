//! At-rest encryption and request signing.
//!
//! [`SecretCipher`] seals `vault_endpoints.signing_secret` and `api_keys.signing_secret` at rest
//! using XChaCha20-Poly1305 when `SYNC_ENCRYPTION_KEY` is configured, and falls back to a
//! hex-encoded plaintext envelope otherwise (so a fresh install without the env var still has a
//! single, self-describing storage format). [`canonical_v1_payload`], [`compute_signature`], and
//! [`verify_signature`] implement the `CANONICAL_V1` HMAC-SHA256 scheme shared by inbound request
//! authentication (`middleware.rs`) and outbound signed calls to remote vaults (`client.rs`).
//!
//! `SecretCipher::open` is strictly fail-closed: a stored value without a recognised prefix is an
//! error, never returned verbatim. This must not hold key *hashing* for lookup (that lives in
//! `api/support.rs::hash_key`) or any policy about who may use a secret.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::Sha256;

/// Maximum permitted clock skew, in seconds, for the symmetric freshness window used both by
/// inbound request timestamp validation and the anti-replay guard's tracking window.
pub const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Environment variable carrying the 64 hex character XChaCha20-Poly1305 key. Unset means secrets
/// are stored under the `v1.plain.` envelope instead of being encrypted.
pub const ENCRYPTION_KEY_ENV: &str = "SYNC_ENCRYPTION_KEY";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const PLAINTEXT_PREFIX: &str = "v1.plain.";
const SEALED_PREFIX: &str = "v1.xchacha20poly1305.";

/// Required prefix on the `X-Signature-256` header value.
pub const SIGNATURE_PREFIX: &str = "sha256=";

/// Failure modes for [`SecretCipher`] operations. Never surfaced to a caller with detail; always
/// mapped to a generic `500` via `AppError::Internal`.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// `SYNC_ENCRYPTION_KEY` was set but is not exactly 64 hex characters.
    #[error("invalid encryption key")]
    InvalidKey,
    /// A stored secret does not carry a recognised envelope prefix, or its contents are corrupt.
    #[error("malformed ciphertext")]
    MalformedCiphertext,
    /// AEAD decryption failed (wrong key, or tampered ciphertext/tag).
    #[error("decryption failed")]
    DecryptionFailed,
    /// AEAD encryption failed.
    #[error("encryption failed")]
    EncryptionFailed,
}

/// Generates a fresh 256-bit HMAC signing secret, hex-encoded.
pub fn generate_signing_secret() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Builds the `CANONICAL_V1` byte string: `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`, newline
/// delimited, no trailing newline. `TARGET` must be the full request path plus query string.
pub fn canonical_v1_payload(method: &str, target: &str, timestamp: &str, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(method.len() + target.len() + timestamp.len() + body.len() + 3);
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(target.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(body);
    message
}

/// Computes `sha256=<hex>` over the `CANONICAL_V1` payload using `secret`.
pub fn compute_signature(
    secret: &str,
    method: &str,
    target: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<String, CryptoError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| {
        tracing::error!("failed to build HMAC from signing secret: {e}");
        CryptoError::EncryptionFailed
    })?;
    mac.update(&canonical_v1_payload(method, target, timestamp, body));
    Ok(format!("{SIGNATURE_PREFIX}{}", hex::encode(mac.finalize().into_bytes())))
}

/// Verifies a provided `X-Signature-256` value in constant time. Returns the raw decoded digest
/// bytes on success (for the replay guard to key on), `None` on any failure. Must only be called
/// on the way to authenticating a request; the returned digest must not be recorded via the
/// replay guard until verification has actually succeeded.
pub fn verify_signature(
    secret: &str,
    method: &str,
    target: &str,
    timestamp: &str,
    body: &[u8],
    provided: &str,
) -> Option<Vec<u8>> {
    let provided_bytes = hex::decode(provided.trim().strip_prefix(SIGNATURE_PREFIX)?.trim()).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(&canonical_v1_payload(method, target, timestamp, body));
    mac.verify_slice(&provided_bytes).ok()?;
    Some(provided_bytes)
}

/// Seals and opens secrets at rest. `Plaintext` when `SYNC_ENCRYPTION_KEY` is unset; `Sealed` when
/// it is set to a valid 64 hex character key.
pub enum SecretCipher {
    /// No encryption key configured; secrets are stored hex-encoded under `v1.plain.`.
    Plaintext,
    /// XChaCha20-Poly1305 sealing is active. Boxed: the cipher schedule is comparatively large.
    Sealed(Box<XChaCha20Poly1305>),
}

impl SecretCipher {
    /// Builds a cipher from `SYNC_ENCRYPTION_KEY`. `Ok(Plaintext)` if unset or empty;
    /// `Err(InvalidKey)` if set but not exactly 64 hex characters.
    pub fn from_env() -> Result<Self, CryptoError> {
        let configured = std::env::var(ENCRYPTION_KEY_ENV)
            .ok()
            .filter(|raw| !raw.trim().is_empty());
        match configured {
            Some(raw) => Self::from_hex_key(raw.trim()),
            None => Ok(Self::Plaintext),
        }
    }

    /// Builds a `Sealed` cipher directly from a 64 hex character key. Exposed for tests.
    pub fn from_hex_key(hex_key: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_key).map_err(|_| CryptoError::InvalidKey)?;
        if bytes.len() != KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let key = chacha20poly1305::Key::try_from(bytes.as_slice()).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::Sealed(Box::new(XChaCha20Poly1305::new(&key))))
    }

    /// True when this cipher actually encrypts (i.e. `SYNC_ENCRYPTION_KEY` was configured).
    pub fn is_encrypting(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }

    /// Seals `plaintext` into its stored envelope.
    pub fn seal(&self, plaintext: &str) -> Result<String, CryptoError> {
        match self {
            Self::Plaintext => Ok(format!("{PLAINTEXT_PREFIX}{}", hex::encode(plaintext))),
            Self::Sealed(cipher) => {
                let nonce_bytes: [u8; NONCE_LEN] = rand::rng().random();
                let nonce = XNonce::from(nonce_bytes);
                let ciphertext = cipher
                    .encrypt(&nonce, plaintext.as_bytes())
                    .map_err(|_| CryptoError::EncryptionFailed)?;
                Ok(format!(
                    "{SEALED_PREFIX}{}.{}",
                    hex::encode(nonce_bytes),
                    hex::encode(ciphertext)
                ))
            }
        }
    }

    /// Opens a stored envelope back into plaintext. Fail-closed: only the two shapes `seal()` can
    /// produce are accepted; anything else is `MalformedCiphertext`, never returned verbatim.
    pub fn open(&self, stored: &str) -> Result<String, CryptoError> {
        if let Some(encoded) = stored.strip_prefix(PLAINTEXT_PREFIX) {
            let bytes = hex::decode(encoded).map_err(|_| CryptoError::MalformedCiphertext)?;
            return String::from_utf8(bytes).map_err(|_| CryptoError::MalformedCiphertext);
        }
        if let Some(body) = stored.strip_prefix(SEALED_PREFIX) {
            let (nonce_hex, ciphertext_hex) =
                body.split_once('.').ok_or(CryptoError::MalformedCiphertext)?;
            let nonce_bytes = hex::decode(nonce_hex).map_err(|_| CryptoError::MalformedCiphertext)?;
            if nonce_bytes.len() != NONCE_LEN {
                return Err(CryptoError::MalformedCiphertext);
            }
            let ciphertext = hex::decode(ciphertext_hex).map_err(|_| CryptoError::MalformedCiphertext)?;
            let Self::Sealed(cipher) = self else {
                return Err(CryptoError::DecryptionFailed);
            };
            let nonce =
                XNonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::MalformedCiphertext)?;
            let plaintext = cipher
                .decrypt(&nonce, ciphertext.as_ref())
                .map_err(|_| CryptoError::DecryptionFailed)?;
            return String::from_utf8(plaintext).map_err(|_| CryptoError::MalformedCiphertext);
        }
        Err(CryptoError::MalformedCiphertext)
    }
}

/// Result of the boot-time encryption-key canary.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyCanary {
    /// Nothing sealed exists yet (fresh database): there is nothing to check the key against.
    NoSealedSecrets,
    /// A stored secret was opened successfully; the configured key matches the data at rest.
    Verified,
}

/// Boot-time canary: proves the configured `SYNC_ENCRYPTION_KEY` is the key the data at rest was
/// actually sealed under, by opening one known-stored secret.
///
/// A syntactically valid but *wrong* key is otherwise indistinguishable from a correct one until
/// the first request that needs a signing secret — by which time the service is live, is
/// advertising readiness, and every outbound sync silently fails to authenticate. Failing at boot
/// converts that into a refusal to start, which is the recoverable outcome: the operator still has
/// the old key, and no partial writes have happened under the wrong one.
///
/// `sample` is any stored envelope (`api_key.signing_secret`); `None` means the database holds no
/// sealed secrets yet. Pure and infallible-by-inspection so it can be unit-tested without a
/// database.
pub fn check_key_canary(cipher: &SecretCipher, sample: Option<&str>) -> Result<KeyCanary, CryptoError> {
    let Some(stored) = sample else {
        return Ok(KeyCanary::NoSealedSecrets);
    };
    cipher.open(stored)?;
    Ok(KeyCanary::Verified)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_plaintext() {
        let cipher = SecretCipher::Plaintext;
        let sealed = cipher.seal("hello-secret").expect("seal");
        assert!(sealed.starts_with(PLAINTEXT_PREFIX));
        assert_eq!(cipher.open(&sealed).expect("open"), "hello-secret");
    }

    #[test]
    fn seal_open_round_trip_encrypted() {
        let key = generate_signing_secret();
        let cipher = SecretCipher::from_hex_key(&key).expect("valid key");
        assert!(cipher.is_encrypting());
        let sealed = cipher.seal("hello-secret").expect("seal");
        assert!(sealed.starts_with(SEALED_PREFIX));
        assert_eq!(cipher.open(&sealed).expect("open"), "hello-secret");
    }

    #[test]
    fn open_rejects_unrecognised_prefix() {
        let cipher = SecretCipher::Plaintext;
        assert!(matches!(
            cipher.open("legacy-unprefixed-value"),
            Err(CryptoError::MalformedCiphertext)
        ));
    }

    #[test]
    fn open_rejects_sealed_value_without_key() {
        let key = generate_signing_secret();
        let sealing_cipher = SecretCipher::from_hex_key(&key).expect("valid key");
        let sealed = sealing_cipher.seal("hello").expect("seal");
        let plaintext_cipher = SecretCipher::Plaintext;
        assert!(matches!(
            plaintext_cipher.open(&sealed),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn from_hex_key_rejects_wrong_length() {
        assert!(matches!(
            SecretCipher::from_hex_key("abcd"),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn compute_and_verify_signature_round_trip() {
        let secret = "test-secret";
        let sig = compute_signature(secret, "POST", "/api/records/batch", "1700000000", b"{}")
            .expect("compute");
        assert!(sig.starts_with(SIGNATURE_PREFIX));
        let digest = verify_signature(secret, "POST", "/api/records/batch", "1700000000", b"{}", &sig);
        assert!(digest.is_some());
    }

    #[test]
    fn verify_signature_rejects_tampered_body() {
        let secret = "test-secret";
        let sig = compute_signature(secret, "POST", "/api/records/batch", "1700000000", b"{}")
            .expect("compute");
        let digest = verify_signature(
            secret,
            "POST",
            "/api/records/batch",
            "1700000000",
            b"{\"tampered\":true}",
            &sig,
        );
        assert!(digest.is_none());
    }

    #[test]
    fn verify_signature_rejects_missing_prefix() {
        let secret = "test-secret";
        let digest = verify_signature(secret, "POST", "/x", "1", b"{}", "deadbeef");
        assert!(digest.is_none());
    }

    /// Adapted from a pattern audited in `example/simply_ip_vault/tests/security_tests.rs`
    /// (2026-08-17 cross-project test audit — see `AGENT_NOTES.MD`): flip every one of a valid
    /// tag's 256 bits individually and confirm every single mutation fails verification. A hex
    /// tamper test (like `verify_signature_rejects_tampered_body`, which changes the *body*, not
    /// the tag) only ever samples 4 of a nibble's 16 possible values and can't isolate a
    /// short-circuit or word-boundary bug in the comparison itself; a full bit sweep can.
    #[test]
    fn every_single_bit_flip_of_a_valid_tag_fails_verification() {
        let secret = "test-secret";
        let method = "POST";
        let target = "/api/records/batch";
        let timestamp = "1700000000";
        let body = b"{\"records\":[]}";

        let valid_sig = compute_signature(secret, method, target, timestamp, body).expect("compute");
        let valid_hex = valid_sig.strip_prefix(SIGNATURE_PREFIX).expect("has prefix");
        let valid_bytes = hex::decode(valid_hex).expect("valid hex");
        assert_eq!(valid_bytes.len(), 32, "HMAC-SHA256 tag must be exactly 32 bytes");

        for byte_index in 0..valid_bytes.len() {
            for bit in 0..8u8 {
                let mut mutated = valid_bytes.clone();
                mutated[byte_index] ^= 1 << bit;
                let mutated_sig = format!("{SIGNATURE_PREFIX}{}", hex::encode(&mutated));
                let digest = verify_signature(secret, method, target, timestamp, body, &mutated_sig);
                assert!(
                    digest.is_none(),
                    "flipping bit {bit} of byte {byte_index} produced a tag that still verified — constant-time comparison bug?"
                );
            }
        }
    }

    /// Every wrong tag *length* (not just wrong content) must also fail cleanly — a length
    /// mismatch is exactly the class of input a naive byte-by-byte comparison loop (rather than
    /// `subtle`/`hmac`'s fixed-length `verify_slice`) could mishandle (e.g. reading out of bounds,
    /// or truncating instead of rejecting).
    #[test]
    fn every_wrong_tag_length_fails_verification() {
        let secret = "test-secret";
        let method = "GET";
        let target = "/api/auth/me";
        let timestamp = "1700000000";
        let body = b"";

        for len in 0..64usize {
            if len == 32 {
                continue; // the one correct length, covered by the round-trip test separately
            }
            let wrong_length_bytes = vec![0xABu8; len];
            let wrong_length_sig = format!("{SIGNATURE_PREFIX}{}", hex::encode(&wrong_length_bytes));
            let digest = verify_signature(secret, method, target, timestamp, body, &wrong_length_sig);
            assert!(digest.is_none(), "a {len}-byte tag must never verify (only 32 bytes is a valid HMAC-SHA256 length)");
        }
    }

    #[test]
    fn canary_reports_no_sealed_secrets_on_an_empty_database() {
        let cipher = SecretCipher::from_hex_key(&generate_signing_secret()).expect("valid key");
        let result = check_key_canary(&cipher, None).expect("infallible on the empty-database branch");
        assert!(matches!(result, KeyCanary::NoSealedSecrets));
    }

    #[test]
    fn canary_verifies_a_secret_sealed_under_the_same_key() {
        let key = generate_signing_secret();
        let cipher = SecretCipher::from_hex_key(&key).expect("valid key");
        let sealed = cipher.seal("vault-signing-secret").expect("seal");

        let result = check_key_canary(&cipher, Some(&sealed)).expect("the same key must open its own ciphertext");
        assert!(matches!(result, KeyCanary::Verified));
    }

    /// The property the canary exists for: a syntactically valid but *wrong* key must fail loudly
    /// at this check, not open (or worse, silently corrupt) a secret sealed under a different key.
    #[test]
    fn canary_fails_closed_when_the_configured_key_does_not_match_the_sealed_secret() {
        let original_cipher = SecretCipher::from_hex_key(&generate_signing_secret()).expect("valid key");
        let sealed = original_cipher.seal("vault-signing-secret").expect("seal");

        let wrong_cipher = SecretCipher::from_hex_key(&generate_signing_secret()).expect("valid key");
        let result = check_key_canary(&wrong_cipher, Some(&sealed));
        assert!(result.is_err(), "a wrong-but-well-formed key must fail the canary, not silently pass");
    }

    /// A plaintext-mode deployment (no `SYNC_ENCRYPTION_KEY` configured) has no key to be wrong
    /// about — `Plaintext::open` never fails on a `v1.plain.`-prefixed value — so the canary must
    /// still report success rather than a spurious failure with nothing actually misconfigured.
    #[test]
    fn canary_passes_trivially_in_plaintext_mode() {
        let cipher = SecretCipher::Plaintext;
        let sealed = cipher.seal("vault-signing-secret").expect("seal");
        let result = check_key_canary(&cipher, Some(&sealed)).expect("plaintext mode has no key to mismatch");
        assert!(matches!(result, KeyCanary::Verified));
    }
}
