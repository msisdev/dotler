use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::config::repo::VaultConfig;
use crate::crypto::{ExposeSecret, Secret, SecretString, bip39_words::WORDS, fill_random_bytes};

pub const VAULT_KEY_LEN: usize = 32;
pub const VAULT_SLOT_LEN: usize = 88;
pub const ENC_FILE_MIN_LEN: usize = 48;
pub const VAULT_ID_INFO: &[u8] = b"dotler-vault-id-v1";
pub const ARGON2_M_COST_KIB: u32 = 65536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;
pub const ARGON2_SALT_LEN: usize = 16;
pub const XCHACHA_NONCE_LEN: usize = 24;
pub const POLY1305_TAG_LEN: usize = 16;
pub const BIP39_ENTROPY_BITS: usize = 128;

#[derive(Debug)]
pub enum VaultError {
    WeakPassphrase(String),
    RngError(String),
    InvalidSecret,
    VaultIdMismatch { expected: String, actual: String },
    InvalidMnemonic(String),
    EncryptionFailed(String),
    InvalidEncFormat(String),
    DecryptionFailed(String),
    InvalidSlotFormat(String),
    Io(std::io::Error),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WeakPassphrase(m) => write!(f, "Weak passphrase: {m}"),
            Self::RngError(m) => write!(f, "RNG error: {m}"),
            Self::InvalidSecret => write!(
                f,
                "Invalid secret or passphrase: authentication tag check failed"
            ),
            Self::VaultIdMismatch { expected, actual } => write!(
                f,
                "Vault ID mismatch: expected '{expected}', found '{actual}'"
            ),
            Self::InvalidMnemonic(m) => write!(f, "Invalid mnemonic: {m}"),
            Self::EncryptionFailed(m) => write!(f, "Encryption failed: {m}"),
            Self::InvalidEncFormat(m) => write!(f, "Invalid encrypted file format: {m}"),
            Self::DecryptionFailed(m) => write!(f, "Decryption failed: {m}"),
            Self::InvalidSlotFormat(m) => write!(f, "Invalid slot format: {m}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl VaultError {
    pub fn exit_code(&self) -> i32 {
        match self {
            VaultError::InvalidSecret => 4,
            VaultError::VaultIdMismatch { .. } => 4,
            VaultError::DecryptionFailed(_) => 4,
            _ => 2,
        }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn derive_kek(
    passphrase: &SecretString,
    salt: &[u8; ARGON2_SALT_LEN],
) -> Result<Secret<[u8; VAULT_KEY_LEN]>, VaultError> {
    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_P_COST,
        Some(VAULT_KEY_LEN),
    )
    .map_err(|e| VaultError::EncryptionFailed(format!("Invalid Argon2 parameters: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = [0u8; VAULT_KEY_LEN];
    let mut blocks = vec![argon2::Block::default(); ARGON2_M_COST_KIB as usize];
    argon2
        .hash_password_into_with_memory(
            passphrase.expose_secret().as_bytes(),
            salt,
            &mut kek,
            &mut blocks,
        )
        .map_err(|e| {
            VaultError::EncryptionFailed(format!("Argon2 key derivation failed: {}", e))
        })?;

    Ok(Secret::new(kek))
}

pub struct VaultKey(pub Secret<[u8; VAULT_KEY_LEN]>);

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("VaultKey").field(&"[REDACTED]").finish()
    }
}

impl VaultKey {
    pub fn generate() -> Result<Self, VaultError> {
        let mut bytes = [0u8; VAULT_KEY_LEN];
        fill_random_bytes(&mut bytes);
        Ok(Self::from_bytes(bytes))
    }

    pub fn from_bytes(bytes: [u8; VAULT_KEY_LEN]) -> Self {
        Self(Secret::new(bytes))
    }

    pub fn expose(&self) -> &[u8; VAULT_KEY_LEN] {
        self.0.expose_secret()
    }

    pub fn vault_id_bytes(&self) -> [u8; 8] {
        let hk = Hkdf::<Sha256>::new(None, self.0.expose_secret());
        let mut okm = [0u8; 8];
        hk.expand(VAULT_ID_INFO, &mut okm)
            .expect("HKDF expand 8 bytes cannot fail with SHA-256");
        okm
    }

    pub fn vault_id(&self) -> String {
        bytes_to_hex(&self.vault_id_bytes())
    }

    pub fn encrypt_file(&self, plaintext: &[u8]) -> Result<EncryptedFile, VaultError> {
        let mut nonce = [0u8; XCHACHA_NONCE_LEN];
        fill_random_bytes(&mut nonce);

        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.0.expose_secret()));
        let x_nonce = XNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(x_nonce, plaintext)
            .map_err(|e| VaultError::EncryptionFailed(format!("File encryption failed: {}", e)))?;

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
                VaultError::DecryptionFailed(format!("Decryption tag check failed: {}", e))
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
            .map_err(|e| VaultError::EncryptionFailed(format!("Slot encryption failed: {}", e)))?;

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
        use base64::prelude::*;
        BASE64_STANDARD.encode(self.to_bytes())
    }

    pub fn from_base64(s: &str) -> Result<Self, VaultError> {
        use base64::prelude::*;
        let bytes = BASE64_STANDARD
            .decode(s.trim())
            .map_err(|e| VaultError::InvalidSlotFormat(format!("Base64 decode error: {}", e)))?;
        Self::from_bytes(&bytes)
    }
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

pub struct RecoveryMnemonic(pub SecretString);

impl std::fmt::Debug for RecoveryMnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RecoveryMnemonic")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl RecoveryMnemonic {
    pub fn generate() -> Result<Self, VaultError> {
        let mut entropy = [0u8; 16];
        fill_random_bytes(&mut entropy);
        let checksum_byte = Sha256::digest(entropy)[0] & 0xF0;
        let mut buf = [0u8; 17];
        buf[0..16].copy_from_slice(&entropy);
        buf[16] = checksum_byte;

        let mut words = Vec::with_capacity(12);
        for i in 0..12 {
            let mut idx: usize = 0;
            for b in 0..11 {
                let pos = i * 11 + b;
                let bit = (buf[pos / 8] >> (7 - (pos % 8))) & 1;
                idx = (idx << 1) | (bit as usize);
            }
            words.push(WORDS[idx]);
        }
        Ok(Self(SecretString::new(words.join(" "))))
    }

    pub fn validate(phrase: &str) -> Result<(), VaultError> {
        let words: Vec<&str> = phrase.split_whitespace().collect();
        if words.len() != 12 {
            return Err(VaultError::InvalidMnemonic(format!(
                "Mnemonic phrase must contain exactly 12 words, found {}",
                words.len()
            )));
        }
        let mut buf = [0u8; 17];
        for (i, &word) in words.iter().enumerate() {
            let idx = WORDS.binary_search(&word).map_err(|_| {
                VaultError::InvalidMnemonic(format!("Invalid mnemonic word: '{word}'"))
            })?;
            for b in 0..11 {
                if ((idx >> (10 - b)) & 1) == 1 {
                    let pos = i * 11 + b;
                    buf[pos / 8] |= 1 << (7 - (pos % 8));
                }
            }
        }
        let expected_cs = Sha256::digest(&buf[0..16])[0] & 0xF0;
        if buf[16] != expected_cs {
            return Err(VaultError::InvalidMnemonic(
                "Invalid mnemonic phrase: checksum mismatch".to_string(),
            ));
        }
        Ok(())
    }

    pub fn phrase(&self) -> &str {
        self.0.expose_secret()
    }
}

pub fn init_vault(
    passphrase: &SecretString,
) -> Result<(VaultConfig, VaultKey, RecoveryMnemonic), VaultError> {
    if passphrase.expose_secret().trim().is_empty() {
        return Err(VaultError::WeakPassphrase(
            "Passphrase cannot be empty".to_string(),
        ));
    }

    let vault_key = VaultKey::generate()?;
    let password_slot = VaultSlot::wrap(passphrase, &vault_key)?;

    let recovery_mnemonic = RecoveryMnemonic::generate()?;
    let recovery_slot = VaultSlot::wrap(&recovery_mnemonic.0, &vault_key)?;

    let config = VaultConfig {
        vault_id: vault_key.vault_id(),
        password_slot: password_slot.to_base64(),
        recovery_slot: recovery_slot.to_base64(),
        hint: None,
    };

    Ok((config, vault_key, recovery_mnemonic))
}

pub fn change_password(
    config: &VaultConfig,
    old_passphrase: &SecretString,
    new_passphrase: &SecretString,
) -> Result<VaultConfig, VaultError> {
    if new_passphrase.expose_secret().trim().is_empty() {
        return Err(VaultError::WeakPassphrase(
            "New passphrase cannot be empty".to_string(),
        ));
    }

    let old_slot = VaultSlot::from_base64(&config.password_slot)?;
    let vault_key = old_slot.unwrap(old_passphrase, Some(&config.vault_id))?;

    let new_slot = VaultSlot::wrap(new_passphrase, &vault_key)?;

    Ok(VaultConfig {
        vault_id: config.vault_id.clone(),
        password_slot: new_slot.to_base64(),
        recovery_slot: config.recovery_slot.clone(),
        hint: config.hint.clone(),
    })
}

pub fn recover_vault(
    config: &VaultConfig,
    mnemonic_phrase: &SecretString,
    new_passphrase: &SecretString,
) -> Result<(VaultConfig, RecoveryMnemonic), VaultError> {
    if new_passphrase.expose_secret().trim().is_empty() {
        return Err(VaultError::WeakPassphrase(
            "New passphrase cannot be empty".to_string(),
        ));
    }

    let words: Vec<&str> = mnemonic_phrase.expose_secret().split_whitespace().collect();
    if words.len() != 12 {
        return Err(VaultError::InvalidMnemonic(format!(
            "Mnemonic phrase must contain exactly 12 words, found {}",
            words.len()
        )));
    }
    let normalized_phrase = words.join(" ");
    RecoveryMnemonic::validate(&normalized_phrase)?;

    let normalized_secret = SecretString::new(normalized_phrase);
    let recovery_slot = VaultSlot::from_base64(&config.recovery_slot)?;
    let vault_key = recovery_slot.unwrap(&normalized_secret, Some(&config.vault_id))?;

    let new_password_slot = VaultSlot::wrap(new_passphrase, &vault_key)?;
    let new_mnemonic = RecoveryMnemonic::generate()?;
    let new_recovery_slot = VaultSlot::wrap(&new_mnemonic.0, &vault_key)?;

    let new_config = VaultConfig {
        vault_id: config.vault_id.clone(),
        password_slot: new_password_slot.to_base64(),
        recovery_slot: new_recovery_slot.to_base64(),
        hint: config.hint.clone(),
    };

    Ok((new_config, new_mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_key_generation_and_fingerprint() {
        let key1 = VaultKey::generate().expect("key generation should succeed");
        let key2 = VaultKey::generate().expect("key generation should succeed");

        assert_eq!(key1.expose().len(), VAULT_KEY_LEN);
        assert_eq!(key2.expose().len(), VAULT_KEY_LEN);
        assert_ne!(key1.expose(), key2.expose());

        let id1 = key1.vault_id();
        let id2 = key2.vault_id();

        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
        assert_ne!(id1, id2);
        assert!(id1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_vault_key_debug_redacted() {
        let key = VaultKey::generate().unwrap();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&key.vault_id()));
    }

    #[test]
    fn test_argon2id_derivation_parameters() {
        let passphrase = SecretString::new("correct-horse-battery-staple".to_string());
        let salt = [0x42u8; ARGON2_SALT_LEN];

        let kek1 = derive_kek(&passphrase, &salt).unwrap();
        let kek2 = derive_kek(&passphrase, &salt).unwrap();
        assert_eq!(kek1.expose_secret(), kek2.expose_secret());

        let different_salt = [0x43u8; ARGON2_SALT_LEN];
        let kek3 = derive_kek(&passphrase, &different_salt).unwrap();
        assert_ne!(kek1.expose_secret(), kek3.expose_secret());
    }

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
    fn test_vault_slot_unwrap_wrong_passphrase_fails() {
        let passphrase = SecretString::new("correct-password".to_string());
        let wrong_passphrase = SecretString::new("wrong-password".to_string());
        let vault_key = VaultKey::generate().unwrap();

        let slot = VaultSlot::wrap(&passphrase, &vault_key).unwrap();
        let err = slot.unwrap(&wrong_passphrase, None).unwrap_err();
        match err {
            VaultError::InvalidSecret => {}
            other => panic!("Expected InvalidSecret, got: {:?}", other),
        }
    }

    #[test]
    fn test_vault_slot_unwrap_vault_id_mismatch_fails() {
        let passphrase = SecretString::new("correct-password".to_string());
        let vault_key = VaultKey::generate().unwrap();

        let slot = VaultSlot::wrap(&passphrase, &vault_key).unwrap();
        let err = slot
            .unwrap(&passphrase, Some("0123456789abcdef"))
            .unwrap_err();
        match err {
            VaultError::VaultIdMismatch { expected, actual } => {
                assert_eq!(expected, "0123456789abcdef");
                assert_eq!(actual, vault_key.vault_id());
            }
            other => panic!("Expected VaultIdMismatch, got: {:?}", other),
        }
    }

    #[test]
    fn test_vault_slot_base64_roundtrip() {
        let passphrase = SecretString::new("my-secret-vault".to_string());
        let vault_key = VaultKey::generate().unwrap();
        let slot = VaultSlot::wrap(&passphrase, &vault_key).unwrap();

        let b64 = slot.to_base64();
        let decoded_slot = VaultSlot::from_base64(&b64).unwrap();
        assert_eq!(slot, decoded_slot);

        let recovered = decoded_slot.unwrap(&passphrase, None).unwrap();
        assert_eq!(recovered.expose(), vault_key.expose());
    }

    #[test]
    fn test_vault_slot_from_base64_invalid_lengths_and_corruptions() {
        use base64::prelude::*;

        // Too short (87 bytes)
        let short_bytes = vec![0u8; 87];
        let short_b64 = BASE64_STANDARD.encode(&short_bytes);
        assert!(matches!(
            VaultSlot::from_base64(&short_b64),
            Err(VaultError::InvalidSlotFormat(_))
        ));

        // Too long (89 bytes)
        let long_bytes = vec![0u8; 89];
        let long_b64 = BASE64_STANDARD.encode(&long_bytes);
        assert!(matches!(
            VaultSlot::from_base64(&long_b64),
            Err(VaultError::InvalidSlotFormat(_))
        ));

        // Malformed Base64
        assert!(matches!(
            VaultSlot::from_base64("not-valid-base64!@#$"),
            Err(VaultError::InvalidSlotFormat(_))
        ));
    }

    #[test]
    fn test_bip39_mnemonic_generation_and_validation() {
        let mnemonic = RecoveryMnemonic::generate().unwrap();
        let words: Vec<&str> = mnemonic.phrase().split_whitespace().collect();
        assert_eq!(words.len(), 12);

        // Validation of valid phrase
        assert!(RecoveryMnemonic::validate(mnemonic.phrase()).is_ok());

        // Invalid word count (too short: 11 words)
        let too_short = words[0..11].join(" ");
        assert!(matches!(
            RecoveryMnemonic::validate(&too_short),
            Err(VaultError::InvalidMnemonic(_))
        ));

        // Invalid word count (too long: 13 words)
        let mut too_long_words = words.clone();
        too_long_words.push(words[0]);
        let too_long = too_long_words.join(" ");
        assert!(matches!(
            RecoveryMnemonic::validate(&too_long),
            Err(VaultError::InvalidMnemonic(_))
        ));

        // Unknown word not in BIP-39 wordlist
        let mut corrupted_words = words.clone();
        corrupted_words[0] = "notaword";
        let corrupted_phrase = corrupted_words.join(" ");
        assert!(matches!(
            RecoveryMnemonic::validate(&corrupted_phrase),
            Err(VaultError::InvalidMnemonic(_))
        ));
    }

    #[test]
    fn test_recovery_mnemonic_debug_redacted() {
        let mnemonic = RecoveryMnemonic::generate().unwrap();
        let debug_str = format!("{:?}", mnemonic);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(mnemonic.phrase().split_whitespace().next().unwrap()));
    }

    #[test]
    fn test_vault_init_passwd_recover_lifecycle() {
        let initial_pass = SecretString::new("initial-passphrase".to_string());
        let (config, initial_key, mnemonic) = init_vault(&initial_pass).unwrap();

        assert_eq!(config.vault_id, initial_key.vault_id());

        // Password slot unwrap
        let pass_slot = VaultSlot::from_base64(&config.password_slot).unwrap();
        let unwrapped_from_pass = pass_slot
            .unwrap(&initial_pass, Some(&config.vault_id))
            .unwrap();
        assert_eq!(unwrapped_from_pass.expose(), initial_key.expose());

        // Recovery slot unwrap
        let rec_slot = VaultSlot::from_base64(&config.recovery_slot).unwrap();
        let unwrapped_from_mnemonic = rec_slot
            .unwrap(&mnemonic.0, Some(&config.vault_id))
            .unwrap();
        assert_eq!(unwrapped_from_mnemonic.expose(), initial_key.expose());

        // Change password
        let new_pass = SecretString::new("new-super-secure-passphrase".to_string());
        let updated_config = change_password(&config, &initial_pass, &new_pass).unwrap();

        assert_eq!(updated_config.vault_id, config.vault_id);
        assert_ne!(updated_config.password_slot, config.password_slot);
        assert_eq!(updated_config.recovery_slot, config.recovery_slot);

        // Verify old pass no longer unwraps new slot
        let new_pass_slot = VaultSlot::from_base64(&updated_config.password_slot).unwrap();
        assert!(matches!(
            new_pass_slot.unwrap(&initial_pass, Some(&updated_config.vault_id)),
            Err(VaultError::InvalidSecret)
        ));

        // Verify new pass unwraps to original vault key
        let key_after_change = new_pass_slot
            .unwrap(&new_pass, Some(&updated_config.vault_id))
            .unwrap();
        assert_eq!(key_after_change.expose(), initial_key.expose());
    }

    #[test]
    fn test_single_use_mnemonic_auto_revocation() {
        let initial_pass = SecretString::new("pass1".to_string());
        let (config, initial_key, mnemonic1) = init_vault(&initial_pass).unwrap();

        // Recover vault using mnemonic1
        let recovered_pass = SecretString::new("recovered-pass".to_string());
        let (recovered_config, mnemonic2) =
            recover_vault(&config, &mnemonic1.0, &recovered_pass).unwrap();

        assert_eq!(recovered_config.vault_id, config.vault_id);
        assert_ne!(mnemonic1.phrase(), mnemonic2.phrase());
        assert_ne!(recovered_config.recovery_slot, config.recovery_slot);

        // Verify recovered password slot yields original key
        let rec_pass_slot = VaultSlot::from_base64(&recovered_config.password_slot).unwrap();
        let key_from_rec_pass = rec_pass_slot
            .unwrap(&recovered_pass, Some(&recovered_config.vault_id))
            .unwrap();
        assert_eq!(key_from_rec_pass.expose(), initial_key.expose());

        // Single-use auto-revocation: Old mnemonic CANNOT recover the vault again!
        let third_pass = SecretString::new("third-pass".to_string());
        let second_recover_attempt = recover_vault(&recovered_config, &mnemonic1.0, &third_pass);
        assert!(matches!(
            second_recover_attempt,
            Err(VaultError::InvalidSecret)
        ));

        // New mnemonic CAN recover the vault
        let (config3, _mnemonic3) =
            recover_vault(&recovered_config, &mnemonic2.0, &third_pass).unwrap();
        assert_eq!(config3.vault_id, config.vault_id);
    }

    #[test]
    fn test_recover_vault_with_excess_whitespace_and_newlines() {
        let initial_pass = SecretString::new("initial-passphrase".to_string());
        let (config, initial_key, mnemonic) = init_vault(&initial_pass).unwrap();

        let raw_phrase = mnemonic.phrase();
        let words: Vec<&str> = raw_phrase.split_whitespace().collect();
        let messy_phrase = format!(
            "  \n  {} \t\t {}   \n  ",
            words[0..6].join("   \t  "),
            words[6..12].join("\n  ")
        );

        let new_pass = SecretString::new("new-passphrase".to_string());
        let (recovered_config, _new_mnemonic) =
            recover_vault(&config, &SecretString::new(messy_phrase), &new_pass)
                .expect("recover_vault should succeed with messy whitespace and newlines");

        assert_eq!(recovered_config.vault_id, config.vault_id);
        let recovered_pass_slot = VaultSlot::from_base64(&recovered_config.password_slot).unwrap();
        let unwrap_key = recovered_pass_slot
            .unwrap(&new_pass, Some(&config.vault_id))
            .unwrap();
        assert_eq!(unwrap_key.expose(), initial_key.expose());
    }

    #[test]
    fn test_weak_passphrase_rejection() {
        let empty_pass = SecretString::new("   ".to_string());
        assert!(matches!(
            init_vault(&empty_pass),
            Err(VaultError::WeakPassphrase(_))
        ));

        let valid_pass = SecretString::new("valid-passphrase".to_string());
        let (config, _, _) = init_vault(&valid_pass).unwrap();

        assert!(matches!(
            change_password(&config, &valid_pass, &empty_pass),
            Err(VaultError::WeakPassphrase(_))
        ));
    }

    #[test]
    fn test_encrypted_file_roundtrip() {
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

        let decrypted = vault_key.decrypt_file(&deserialized).unwrap();
        assert_eq!(decrypted.expose_secret().as_slice(), plaintext);
    }

    #[test]
    fn test_encrypted_file_zero_length_plaintext() {
        let vault_key = VaultKey::generate().unwrap();
        let plaintext = b"";

        let enc = vault_key.encrypt_file(plaintext).unwrap();
        assert_eq!(enc.ciphertext.len(), 16); // Only Poly1305 tag
        let bytes = enc.to_bytes();
        assert_eq!(bytes.len(), 48); // 8 + 24 + 16 = 48 bytes exactly

        let deserialized = EncryptedFile::from_bytes(&bytes).unwrap();
        let decrypted = vault_key.decrypt_file(&deserialized).unwrap();
        assert_eq!(decrypted.expose_secret().as_slice(), b"");
    }

    #[test]
    fn test_encrypted_file_tampered_ciphertext_fails_decryption() {
        let vault_key = VaultKey::generate().unwrap();
        let plaintext = b"Hello, secret world!";

        let mut enc = vault_key.encrypt_file(plaintext).unwrap();
        // Flip 1 bit in ciphertext
        enc.ciphertext[0] ^= 0x01;

        assert!(matches!(
            vault_key.decrypt_file(&enc),
            Err(VaultError::DecryptionFailed(_))
        ));
    }

    #[test]
    fn test_encrypted_file_tampered_vault_id_fails() {
        let vault_key = VaultKey::generate().unwrap();
        let plaintext = b"Hello, secret world!";

        let mut enc = vault_key.encrypt_file(plaintext).unwrap();
        enc.vault_id[0] ^= 0x01;

        assert!(matches!(
            vault_key.decrypt_file(&enc),
            Err(VaultError::VaultIdMismatch { .. })
        ));
    }

    #[test]
    fn test_encrypted_file_truncated_fails() {
        let truncated = vec![0u8; 47]; // Below ENC_FILE_MIN_LEN (48)
        assert!(matches!(
            EncryptedFile::from_bytes(&truncated),
            Err(VaultError::InvalidEncFormat(_))
        ));
    }

    #[test]
    fn test_encrypted_file_wrong_vault_key() {
        let vault_key1 = VaultKey::generate().unwrap();
        let vault_key2 = VaultKey::generate().unwrap();
        let plaintext = b"Confidential content";

        let enc = vault_key1.encrypt_file(plaintext).unwrap();
        assert!(matches!(
            vault_key2.decrypt_file(&enc),
            Err(VaultError::VaultIdMismatch { .. })
        ));
    }
}
