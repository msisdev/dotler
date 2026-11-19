use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::vault::{
    ARGON2_SALT_LEN, VAULT_KEY_LEN, VaultError, VaultKey, XCHACHA_NONCE_LEN, bytes_to_hex,
    derive_kek, normalize_full_enc_rel_path,
};
use crate::crypto::{ExposeSecret, Secret, SecretString, fill_random_bytes};

pub const VAULT_SLOT_LEN: usize = 88;
pub const ENC_FILE_MIN_LEN: usize = 48;
pub const FENC_FILE_MIN_LEN: usize = 53;
pub const FULL_ENC_TOKEN_HEX_LEN: usize = 32;
pub const FULL_ENC_AAD_DOMAIN: &[u8] = b"dotler-fenc-v1";
pub const FULL_ENC_MAX_PATH_BYTES: usize = 4096;

pub fn parse_fenc_filename_stem(name_or_stem: &str) -> Option<&str> {
    let stem = name_or_stem.strip_suffix(".fenc")?;
    if stem.len() == FULL_ENC_TOKEN_HEX_LEN
        && stem.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Some(stem)
    } else {
        None
    }
}

fn decode_hex_16(stem: &str) -> Result<[u8; 16], VaultError> {
    if stem.len() != FULL_ENC_TOKEN_HEX_LEN {
        return Err(VaultError::InvalidEncFormat(format!(
            "Invalid full-encrypted filename token length: {} (expected {})",
            stem.len(),
            FULL_ENC_TOKEN_HEX_LEN
        )));
    }
    let hex_nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 16];
    for (idx, chunk) in stem.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_nibble(chunk[0]).ok_or_else(|| {
            VaultError::InvalidEncFormat(
                "Full-encrypted filename token must be lowercase hexadecimal".to_string(),
            )
        })?;
        let lo = hex_nibble(chunk[1]).ok_or_else(|| {
            VaultError::InvalidEncFormat(
                "Full-encrypted filename token must be lowercase hexadecimal".to_string(),
            )
        })?;
        out[idx] = (hi << 4) | lo;
    }
    Ok(out)
}

fn build_full_enc_aad(vault_id: &[u8; 8], token_bytes: &[u8; 16]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FULL_ENC_AAD_DOMAIN.len() + 8 + 16);
    aad.extend_from_slice(FULL_ENC_AAD_DOMAIN);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(token_bytes);
    aad
}

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

    pub fn encrypt_full_file(
        &self,
        rel_path: &str,
        plaintext: &[u8],
    ) -> Result<(String, FullEncryptedFile), VaultError> {
        let norm_rel = normalize_full_enc_rel_path(rel_path);
        if norm_rel.is_empty() || norm_rel.contains('\0') {
            return Err(VaultError::EncryptionFailed(
                "Full-encrypted relative path cannot be empty or contain NUL bytes".to_string(),
            ));
        }
        if norm_rel.len() > FULL_ENC_MAX_PATH_BYTES {
            return Err(VaultError::EncryptionFailed(format!(
                "Full-encrypted relative path exceeds {} bytes",
                FULL_ENC_MAX_PATH_BYTES
            )));
        }

        let vault_id = self.vault_id_bytes();
        let token_bytes = self.derive_full_enc_token_bytes(&norm_rel);
        let filename = format!("{}.fenc", bytes_to_hex(&token_bytes));
        let aad = build_full_enc_aad(&vault_id, &token_bytes);

        let mut envelope = Zeroizing::new(Vec::with_capacity(4 + norm_rel.len() + plaintext.len()));
        envelope.extend_from_slice(&(norm_rel.len() as u32).to_be_bytes());
        envelope.extend_from_slice(norm_rel.as_bytes());
        envelope.extend_from_slice(plaintext);

        let mut nonce = [0u8; XCHACHA_NONCE_LEN];
        fill_random_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.0.expose_secret()));
        let x_nonce = XNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(
                x_nonce,
                Payload {
                    msg: envelope.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|e| {
                VaultError::EncryptionFailed(format!("Full file encryption failed: {e}"))
            })?;

        Ok((
            filename,
            FullEncryptedFile {
                vault_id,
                nonce,
                ciphertext,
            },
        ))
    }

    pub fn decrypt_full_file(
        &self,
        file_name_or_stem: &str,
        fenc: &FullEncryptedFile,
    ) -> Result<(String, Secret<Vec<u8>>), VaultError> {
        if fenc.vault_id != self.vault_id_bytes() {
            return Err(VaultError::VaultIdMismatch {
                expected: self.vault_id(),
                actual: bytes_to_hex(&fenc.vault_id),
            });
        }

        let stem = file_name_or_stem
            .strip_suffix(".fenc")
            .unwrap_or(file_name_or_stem);
        let token_bytes = decode_hex_16(stem)?;
        let aad = build_full_enc_aad(&fenc.vault_id, &token_bytes);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.0.expose_secret()));
        let x_nonce = XNonce::from_slice(&fenc.nonce);

        let decrypted = Zeroizing::new(
            cipher
                .decrypt(
                    x_nonce,
                    Payload {
                        msg: fenc.ciphertext.as_slice(),
                        aad: &aad,
                    },
                )
                .map_err(|e| {
                    VaultError::DecryptionFailed(format!(
                        "Full decryption tag or filename binding check failed: {e}"
                    ))
                })?,
        );

        if decrypted.len() < 5 {
            return Err(VaultError::InvalidEncFormat(
                "Decrypted full-encrypted envelope is truncated".to_string(),
            ));
        }
        let path_len =
            u32::from_be_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]]) as usize;
        if path_len == 0 || path_len > FULL_ENC_MAX_PATH_BYTES || 4 + path_len > decrypted.len() {
            return Err(VaultError::InvalidEncFormat(
                "Invalid embedded path length in full-encrypted file".to_string(),
            ));
        }

        let rel_path = std::str::from_utf8(&decrypted[4..4 + path_len])
            .map_err(|_| {
                VaultError::InvalidEncFormat(
                    "Embedded relative path in full-encrypted file is not valid UTF-8".to_string(),
                )
            })?
            .to_string();
        if rel_path.contains('\0') {
            return Err(VaultError::InvalidEncFormat(
                "Embedded relative path contains NUL byte".to_string(),
            ));
        }
        if self.derive_full_enc_token_bytes(&rel_path) != token_bytes {
            return Err(VaultError::DecryptionFailed(
                "Full-encrypted filename token does not match embedded relative path".to_string(),
            ));
        }

        let content = decrypted[4 + path_len..].to_vec();
        Ok((rel_path, Secret::new(content)))
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

#[derive(Clone, PartialEq, Eq)]
pub struct FullEncryptedFile {
    pub vault_id: [u8; 8],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl std::fmt::Debug for FullEncryptedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FullEncryptedFile")
            .field("vault_id", &bytes_to_hex(&self.vault_id))
            .field("nonce", &bytes_to_hex(&self.nonce))
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

impl FullEncryptedFile {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 24 + self.ciphertext.len());
        bytes.extend_from_slice(&self.vault_id);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(slice: &[u8]) -> Result<Self, VaultError> {
        if slice.len() < FENC_FILE_MIN_LEN {
            return Err(VaultError::InvalidEncFormat(format!(
                "Full-encrypted file is too short: {} bytes (minimum {} bytes)",
                slice.len(),
                FENC_FILE_MIN_LEN
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

    #[test]
    fn test_full_encrypted_file_roundtrip_swap_and_cross_format_rejection() {
        let key1 = VaultKey::generate().unwrap();
        let key2 = VaultKey::generate().unwrap();

        let (fname_a, fenc_a) = key1
            .encrypt_full_file("clients/acme-prod/api.key", b"sk_live_secret")
            .unwrap();
        let (fname_a2, _) = key1
            .encrypt_full_file("./clients/acme-prod/api.key", b"updated")
            .unwrap();
        assert_eq!(fname_a, fname_a2, "path token must be deterministic");
        assert_eq!(fname_a.len(), FULL_ENC_TOKEN_HEX_LEN + 5);
        assert!(parse_fenc_filename_stem(&fname_a).is_some());
        assert!(!fname_a.contains("acme"));

        let raw_a = fenc_a.to_bytes();
        assert!(!String::from_utf8_lossy(&raw_a).contains("acme"));
        let parsed_a = FullEncryptedFile::from_bytes(&raw_a).unwrap();
        let (dec_rel, dec_plain) = key1.decrypt_full_file(&fname_a, &parsed_a).unwrap();
        assert_eq!(dec_rel, "clients/acme-prod/api.key");
        assert_eq!(dec_plain.expose_secret().as_slice(), b"sk_live_secret");

        // Swapping filename token between two .fenc files must fail AAD authentication
        let (fname_b, _) = key1
            .encrypt_full_file("clients/other/api.key", b"x")
            .unwrap();
        assert_ne!(fname_a, fname_b);
        assert!(matches!(
            key1.decrypt_full_file(&fname_b, &parsed_a),
            Err(VaultError::DecryptionFailed(_))
        ));

        // Cross-format confusion (.enc bytes parsed as .fenc or vice versa) must fail
        let content_enc = key1.encrypt_file(&[0u8; 64]).unwrap().to_bytes();
        let fake_fenc = FullEncryptedFile::from_bytes(&content_enc).unwrap();
        assert!(matches!(
            key1.decrypt_full_file(&fname_a, &fake_fenc),
            Err(VaultError::DecryptionFailed(_))
        ));
        let fake_enc = EncryptedFile::from_bytes(&raw_a).unwrap();
        assert!(matches!(
            key1.decrypt_file(&fake_enc),
            Err(VaultError::DecryptionFailed(_))
        ));

        // Different vault key produces a different filename token and rejects decryption
        assert_ne!(
            fname_a,
            key2.derive_full_enc_filename("clients/acme-prod/api.key")
        );
        assert!(matches!(
            key2.decrypt_full_file(&fname_a, &parsed_a),
            Err(VaultError::VaultIdMismatch { .. })
        ));
    }
}
