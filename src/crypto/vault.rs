use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::config::repo::VaultConfig;
use crate::crypto::{ExposeSecret, Secret, SecretString, fill_random_bytes};

pub use crate::crypto::cipher::{
    ENC_FILE_MIN_LEN, EncryptedFile, VAULT_SLOT_LEN, VaultSlot,
};
pub use crate::crypto::mnemonic::{BIP39_ENTROPY_BITS, RecoveryMnemonic};

pub const VAULT_KEY_LEN: usize = 32;
pub const VAULT_ID_INFO: &[u8] = b"dotler-vault-id-v1";
pub const ARGON2_M_COST_KIB: u32 = 65536;
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 4;
pub const ARGON2_SALT_LEN: usize = 16;
pub const XCHACHA_NONCE_LEN: usize = 24;
pub const POLY1305_TAG_LEN: usize = 16;

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

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").unwrap();
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
    .map_err(|e| VaultError::EncryptionFailed(format!("Invalid Argon2 parameters: {e}")))?;

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
        .map_err(|e| VaultError::EncryptionFailed(format!("Argon2 key derivation failed: {e}")))?;

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
        vault_hint: None,
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
        vault_hint: config.vault_hint.clone(),
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
        vault_hint: config.vault_hint.clone(),
    };

    Ok((new_config, new_mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_key_generation_fingerprint_and_debug_redacted() {
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

        let debug_str = format!("{key1:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(&id1));
    }

    #[test]
    fn test_argon2id_derivation_parameters() {
        let passphrase = SecretString::new("correct-horse-battery-staple".to_string());
        let kek1 = derive_kek(&passphrase, &[0x42u8; ARGON2_SALT_LEN]).unwrap();
        let kek2 = derive_kek(&passphrase, &[0x42u8; ARGON2_SALT_LEN]).unwrap();
        assert_eq!(kek1.expose_secret(), kek2.expose_secret());
        let kek3 = derive_kek(&passphrase, &[0x43u8; ARGON2_SALT_LEN]).unwrap();
        assert_ne!(kek1.expose_secret(), kek3.expose_secret());
    }

    #[test]
    fn test_vault_init_passwd_recover_lifecycle() {
        let initial_pass = SecretString::new("initial-passphrase".to_string());
        let (config, initial_key, mnemonic) = init_vault(&initial_pass).unwrap();
        assert_eq!(config.vault_id, initial_key.vault_id());

        let pass_slot = VaultSlot::from_base64(&config.password_slot).unwrap();
        assert_eq!(pass_slot.unwrap(&initial_pass, Some(&config.vault_id)).unwrap().expose(), initial_key.expose());

        let rec_slot = VaultSlot::from_base64(&config.recovery_slot).unwrap();
        assert_eq!(rec_slot.unwrap(&mnemonic.0, Some(&config.vault_id)).unwrap().expose(), initial_key.expose());

        let new_pass = SecretString::new("new-super-secure-passphrase".to_string());
        let updated = change_password(&config, &initial_pass, &new_pass).unwrap();
        assert_eq!(updated.vault_id, config.vault_id);
        assert_ne!(updated.password_slot, config.password_slot);
        assert_eq!(updated.recovery_slot, config.recovery_slot);

        let new_slot = VaultSlot::from_base64(&updated.password_slot).unwrap();
        assert!(matches!(new_slot.unwrap(&initial_pass, Some(&updated.vault_id)), Err(VaultError::InvalidSecret)));
        assert_eq!(new_slot.unwrap(&new_pass, Some(&updated.vault_id)).unwrap().expose(), initial_key.expose());
    }

    #[test]
    fn test_single_use_mnemonic_auto_revocation() {
        let (config, initial_key, mnemonic1) = init_vault(&SecretString::new("pass1".to_string())).unwrap();
        let recovered_pass = SecretString::new("recovered-pass".to_string());
        let (recovered_config, mnemonic2) = recover_vault(&config, &mnemonic1.0, &recovered_pass).unwrap();

        assert_eq!(recovered_config.vault_id, config.vault_id);
        assert_ne!(mnemonic1.phrase(), mnemonic2.phrase());
        assert_ne!(recovered_config.recovery_slot, config.recovery_slot);

        let rec_pass_slot = VaultSlot::from_base64(&recovered_config.password_slot).unwrap();
        assert_eq!(rec_pass_slot.unwrap(&recovered_pass, Some(&recovered_config.vault_id)).unwrap().expose(), initial_key.expose());

        let third_pass = SecretString::new("third-pass".to_string());
        assert!(matches!(recover_vault(&recovered_config, &mnemonic1.0, &third_pass), Err(VaultError::InvalidSecret)));
        let (config3, _) = recover_vault(&recovered_config, &mnemonic2.0, &third_pass).unwrap();
        assert_eq!(config3.vault_id, config.vault_id);
    }

    #[test]
    fn test_recover_vault_with_excess_whitespace_and_weak_passphrase() {
        let initial_pass = SecretString::new("initial-passphrase".to_string());
        let (config, initial_key, mnemonic) = init_vault(&initial_pass).unwrap();
        let words: Vec<&str> = mnemonic.phrase().split_whitespace().collect();
        let messy_phrase = format!("  \n  {} \t\t {}   \n  ", words[0..6].join("   \t  "), words[6..12].join("\n  "));

        let new_pass = SecretString::new("new-passphrase".to_string());
        let (recovered_config, _) = recover_vault(&config, &SecretString::new(messy_phrase), &new_pass)
            .expect("recover_vault should succeed with messy whitespace and newlines");
        let slot = VaultSlot::from_base64(&recovered_config.password_slot).unwrap();
        assert_eq!(slot.unwrap(&new_pass, Some(&config.vault_id)).unwrap().expose(), initial_key.expose());

        let empty_pass = SecretString::new("   ".to_string());
        assert!(matches!(init_vault(&empty_pass), Err(VaultError::WeakPassphrase(_))));
        assert!(matches!(change_password(&config, &initial_pass, &empty_pass), Err(VaultError::WeakPassphrase(_))));
    }
}
