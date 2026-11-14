use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::vault::{
    ARGON2_SALT_LEN, VAULT_KEY_LEN, VaultError, VaultKey, XCHACHA_NONCE_LEN, bytes_to_hex,
    derive_kek,
};
use crate::crypto::{ExposeSecret, Secret, SecretString, fill_random_bytes};

pub const VAULT_SLOT_LEN: usize = 88;
pub const ENC_FILE_MIN_LEN: usize = 48;

impl VaultKey {
    pub fn encrypt_file(&self, plaintext: &[u8]) -> Result<EncryptedFile, VaultError> {
        let mut nonce = [0u8; XCHACHA_NONCE_LEN];
        fill_random_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.0.expose_secret()));
        let x_nonce = XNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(x_nonce, plaintext)
            .map_err(|e| VaultError::EncryptionFailed(format!("File encryption failed: {e}")))?;

        Ok(EncryptedFile {
            vault_id: self.vault_id_bytes(),
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt_file(&self, enc: &EncryptedFile) -> Result<Secret<Vec<u8>>, VaultError> {
        if enc.vault_id != self.vault_id_bytes() {
            return Err(VaultError::VaultIdMismatch {
                expected: self.vault_id(),
                actual: bytes_to_hex(&enc.vault_id),
            });
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.0.expose_secret()));
        let x_nonce = XNonce::from_slice(&enc.nonce);

        let plaintext = cipher
            .decrypt(x_nonce, enc.ciphertext.as_ref())
            .map_err(|e| {
                VaultError::DecryptionFailed(format!("Decryption tag check failed: {e}"))
            })?;

        Ok(Secret::new(plaintext))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VaultSlot {
    pub salt: [u8; ARGON2_SALT_LEN],
    pub nonce: [u8; XCHACHA_NONCE_LEN],
    pub ciphertext: [u8; 48],
}

impl std::fmt::Debug for VaultSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSlot")
            .field("salt", &bytes_to_hex(&self.salt))
            .field("nonce", &bytes_to_hex(&self.nonce))
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl VaultSlot {
    pub fn wrap(secret: &SecretString, vault_key: &VaultKey) -> Result<Self, VaultError> {
        let mut salt = [0u8; ARGON2_SALT_LEN];
        let mut nonce = [0u8; XCHACHA_NONCE_LEN];
        fill_random_bytes(&mut salt);
        fill_random_bytes(&mut nonce);

        let kek = derive_kek(secret, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.expose_secret()));
        let x_nonce = XNonce::from_slice(&nonce);

        let encrypted = cipher
            .encrypt(x_nonce, vault_key.0.expose_secret().as_ref())
            .map_err(|e| VaultError::EncryptionFailed(format!("Slot encryption failed: {e}")))?;

        if encrypted.len() != 48 {
            return Err(VaultError::EncryptionFailed(format!(
                "Unexpected encrypted key length: {} (expected 48)",
                encrypted.len()
            )));
        }

        let mut ciphertext = [0u8; 48];
        ciphertext.copy_from_slice(&encrypted);

        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }

    pub fn unwrap(
        &self,
        secret: &SecretString,
        expected_vault_id: Option<&str>,
    ) -> Result<VaultKey, VaultError> {
        let kek = derive_kek(secret, &self.salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(kek.expose_secret()));
        let x_nonce = XNonce::from_slice(&self.nonce);

        let mut decrypted = Zeroizing::new(
            cipher
                .decrypt(x_nonce, self.ciphertext.as_ref())
                .map_err(|_| VaultError::InvalidSecret)?,
        );

        if decrypted.len() != VAULT_KEY_LEN {
            return Err(VaultError::InvalidSecret);
        }

        let mut key_bytes = [0u8; VAULT_KEY_LEN];
        key_bytes.copy_from_slice(&decrypted);
        decrypted.zeroize();
        let vault_key = VaultKey::from_bytes(key_bytes);

        if let Some(expected) = expected_vault_id {
            let actual = vault_key.vault_id();
            if actual != expected {
                return Err(VaultError::VaultIdMismatch {
                    expected: expected.to_string(),
                    actual,
                });
            }
        }

        Ok(vault_key)
    }

    pub fn to_bytes(&self) -> [u8; VAULT_SLOT_LEN] {
        let mut bytes = [0u8; VAULT_SLOT_LEN];
        bytes[0..16].copy_from_slice(&self.salt);
        bytes[16..40].copy_from_slice(&self.nonce);
        bytes[40..88].copy_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, VaultError> {
        if slice.len() != VAULT_SLOT_LEN {
            return Err(VaultError::InvalidSlotFormat(format!(
                "Invalid slot length: {} bytes (expected {} bytes)",
                slice.len(),
                VAULT_SLOT_LEN
            )));
        }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        let mut ciphertext = [0u8; 48];
        salt.copy_from_slice(&slice[0..16]);
        nonce.copy_from_slice(&slice[16..40]);
        ciphertext.copy_from_slice(&slice[40..88]);
        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }

    pub fn to_base64(&self) -> String {
        base64_encode(&self.to_bytes())
    }

    pub fn from_base64(s: &str) -> Result<Self, VaultError> {
        let bytes = base64_decode(s.trim())
            .map_err(|e| VaultError::InvalidSlotFormat(format!("Base64 decode error: {e}")))?;
        Self::from_bytes(&bytes)
    }
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(B64_ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn decode_b64_byte(b: u8) -> Result<u8, &'static str> {
    match b {
        b'A'..=b'Z' => Ok(b - b'A'),
        b'a'..=b'z' => Ok(b - b'a' + 26),
        b'0'..=b'9' => Ok(b - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("invalid Base64 character"),
    }
}

pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("invalid Base64 length");
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    let num_chunks = bytes.len() / 4;
    for (idx, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let is_last = idx + 1 == num_chunks;
        let v0 = decode_b64_byte(chunk[0])? as u32;
        let v1 = decode_b64_byte(chunk[1])? as u32;

        match (chunk[2], chunk[3]) {
            (b'=', b'=') if is_last => {
                if (v1 & 0x0f) != 0 {
                    return Err("non-canonical Base64 padding bits");
                }
                out.push(((v0 << 2) | (v1 >> 4)) as u8);
            }
            (c2, b'=') if is_last && c2 != b'=' => {
                let v2 = decode_b64_byte(c2)? as u32;
                if (v2 & 0x03) != 0 {
                    return Err("non-canonical Base64 padding bits");
                }
                let triple = (v0 << 18) | (v1 << 12) | (v2 << 6);
                out.push(((triple >> 16) & 0xff) as u8);
                out.push(((triple >> 8) & 0xff) as u8);
            }
            (c2, c3) if c2 != b'=' && c3 != b'=' => {
                let v2 = decode_b64_byte(c2)? as u32;
                let v3 = decode_b64_byte(c3)? as u32;
                let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
                out.push(((triple >> 16) & 0xff) as u8);
                out.push(((triple >> 8) & 0xff) as u8);
                out.push((triple & 0xff) as u8);
            }
            _ => return Err("invalid Base64 padding"),
        }
    }
    Ok(out)
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedFile {
    pub vault_id: [u8; 8],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for EncryptedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedFile")
            .field("vault_id", &bytes_to_hex(&self.vault_id))
            .field("nonce", &bytes_to_hex(&self.nonce))
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl EncryptedFile {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 24 + self.ciphertext.len());
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, VaultError> {
        if slice.len() < ENC_FILE_MIN_LEN {
            return Err(VaultError::InvalidEncFormat(format!(
                "Encrypted file is too short: {} bytes (minimum {} bytes)",
                slice.len(),
                ENC_FILE_MIN_LEN
            )));
        }
        let mut vault_id = [0u8; 8];
        let mut nonce = [0u8; 24];
        vault_id.copy_from_slice(&slice[0..8]);
        nonce.copy_from_slice(&slice[8..32]);
        let ciphertext = slice[32..].to_vec();

        Ok(Self {
            vault_id,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_slot_wrap_and_unwrap_success() {
        let passphrase = SecretString::new("test-passphrase-123".to_string());
        let vault_key = VaultKey::generate().unwrap();
        let expected_id = vault_key.vault_id();

        let slot = VaultSlot::wrap(&passphrase, &vault_key).unwrap();
        assert_eq!(slot.salt.len(), 16);
        assert_eq!(slot.nonce.len(), 24);
        assert_eq!(slot.ciphertext.len(), 48);
        assert_eq!(slot.to_bytes().len(), 88);

        let recovered = slot.unwrap(&passphrase, Some(&expected_id)).unwrap();
        assert_eq!(recovered.expose(), vault_key.expose());
        assert_eq!(recovered.vault_id(), expected_id);
    }

    #[test]
    fn test_vault_slot_unwrap_wrong_passphrase_and_id_mismatch_fail() {
        let passphrase = SecretString::new("correct-password".to_string());
        let wrong_passphrase = SecretString::new("wrong-password".to_string());
        let vault_key = VaultKey::generate().unwrap();

        let slot = VaultSlot::wrap(&passphrase, &vault_key).unwrap();
        assert!(matches!(
            slot.unwrap(&wrong_passphrase, None),
            Err(VaultError::InvalidSecret)
        ));

        let err = slot
            .unwrap(&passphrase, Some("0123456789abcdef"))
            .unwrap_err();
        assert!(matches!(
            err,
            VaultError::VaultIdMismatch { expected, actual }
                if expected == "0123456789abcdef" && actual == vault_key.vault_id()
        ));
    }

    #[test]
    fn test_vault_slot_base64_roundtrip_and_invalid_inputs() {
        let passphrase = SecretString::new("my-secret-vault".to_string());
        let vault_key = VaultKey::generate().unwrap();
        let slot = VaultSlot::wrap(&passphrase, &vault_key).unwrap();

        let decoded_slot = VaultSlot::from_base64(&slot.to_base64()).unwrap();
        assert_eq!(slot, decoded_slot);
        assert_eq!(
            decoded_slot.unwrap(&passphrase, None).unwrap().expose(),
            vault_key.expose()
        );

        for bad in [
            &base64_encode(&[0u8; 87]),
            &base64_encode(&[0u8; 89]),
            "not-valid-base64!@#$",
        ] {
            assert!(matches!(
                VaultSlot::from_base64(bad),
                Err(VaultError::InvalidSlotFormat(_))
            ));
        }
    }

    #[test]
    fn test_encrypted_file_roundtrip_and_zero_length() {
        let vault_key = VaultKey::generate().unwrap();
        let plaintext =
            b"export SECRET_KEY=\"sk_live_1234567890\"\nexport DB_PASSWORD=\"supersecret\"";

        let enc = vault_key.encrypt_file(plaintext).unwrap();
        assert_eq!(enc.vault_id, vault_key.vault_id_bytes());
        assert_eq!(enc.nonce.len(), 24);
        assert_eq!(enc.ciphertext.len(), plaintext.len() + 16);

        let serialized = enc.to_bytes();
        assert_eq!(serialized.len(), 8 + 24 + plaintext.len() + 16);
        let deserialized = EncryptedFile::from_bytes(&serialized).unwrap();
        assert_eq!(enc, deserialized);
        assert_eq!(
            vault_key
                .decrypt_file(&deserialized)
                .unwrap()
                .expose_secret()
                .as_slice(),
            plaintext
        );

        let empty_enc = vault_key.encrypt_file(b"").unwrap();
        assert_eq!(empty_enc.ciphertext.len(), 16);
        let empty_bytes = empty_enc.to_bytes();
        assert_eq!(empty_bytes.len(), 48);
        let empty_dec = vault_key
            .decrypt_file(&EncryptedFile::from_bytes(&empty_bytes).unwrap())
            .unwrap();
        assert_eq!(empty_dec.expose_secret().as_slice(), b"");
    }

    #[test]
    fn test_encrypted_file_tamper_truncation_and_wrong_key_fail() {
        let vault_key1 = VaultKey::generate().unwrap();
        let vault_key2 = VaultKey::generate().unwrap();
        let mut enc = vault_key1.encrypt_file(b"Hello, secret world!").unwrap();

        assert!(matches!(
            vault_key2.decrypt_file(&enc),
            Err(VaultError::VaultIdMismatch { .. })
        ));

        enc.ciphertext[0] ^= 0x01;
        assert!(matches!(
            vault_key1.decrypt_file(&enc),
            Err(VaultError::DecryptionFailed(_))
        ));

        enc.vault_id[0] ^= 0x01;
        assert!(matches!(
            vault_key1.decrypt_file(&enc),
            Err(VaultError::VaultIdMismatch { .. })
        ));

        assert!(matches!(
            EncryptedFile::from_bytes(&[0u8; 47]),
            Err(VaultError::InvalidEncFormat(_))
        ));
    }

    #[test]
    fn test_rfc4648_base64_vectors_and_non_canonical_rejection() {
        for &(raw, expected_b64) in &[
            (b"".as_slice(), ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(raw), expected_b64);
            assert_eq!(base64_decode(expected_b64).unwrap(), raw);
        }
        assert!(base64_decode("Zg=A").is_err());
        assert!(base64_decode("Zm9=").is_err());
        assert!(base64_decode("Zg==Zg==").is_err());
    }
}
