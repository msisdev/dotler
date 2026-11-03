pub mod keyring;
pub mod vault;

pub use keyring::{
    KEYRING_DEFAULT_USER, KEYRING_SERVICE_NAME, KeyringError, OsKeyring, PASSPHRASE_ENV_VAR,
    PassphraseSource, ResolvedPassphrase,
};
pub use vault::{
    ARGON2_M_COST_KIB, ARGON2_P_COST, ARGON2_SALT_LEN, ARGON2_T_COST, BIP39_ENTROPY_BITS,
    ENC_FILE_MIN_LEN, EncryptedFile, POLY1305_TAG_LEN, RecoveryMnemonic, VAULT_ID_INFO,
    VAULT_KEY_LEN, VAULT_SLOT_LEN, VaultError, VaultKey, VaultSlot, XCHACHA_NONCE_LEN,
    change_password, init_vault, recover_vault,
};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),

    #[error("Keyring error: {0}")]
    Keyring(#[from] KeyringError),
}

impl CryptoError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CryptoError::Vault(e) => e.exit_code(),
            CryptoError::Keyring(e) => e.exit_code(),
        }
    }
}
