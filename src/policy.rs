use sha2::{Digest, Sha256};

use crate::PolicyInput;

const DOMAIN: &[u8] = b"crowsi-policy-input-v1\0";

impl PolicyInput<'_> {
    /// Computes the digest that binds the versioned risk restrictions.
    #[must_use]
    pub fn computed_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update([self.max_risk_score, self.step_up_risk_score]);
        encode_digest(hasher.finalize().as_slice())
    }
}

fn encode_digest(bytes: &[u8]) -> String {
    let alphabet = b"0123456789abcdef";
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in bytes {
        value.push(alphabet[usize::from(byte >> 4)] as char);
        value.push(alphabet[usize::from(byte & 0x0f)] as char);
    }
    value
}
