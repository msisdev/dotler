pub(crate) mod bip39_words;
pub mod keyring;
pub mod vault;

use zeroize::Zeroize;

pub trait ExposeSecret<S: ?Sized> {
    fn expose_secret(&self) -> &S;
}

#[derive(Clone)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(val: T) -> Self {
        Self(val)
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T: Zeroize> ExposeSecret<T> for Secret<T> {
    fn expose_secret(&self) -> &T {
        &self.0
    }
}

#[derive(Clone)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(val: String) -> Self {
        Self(val)
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl From<String> for SecretString {
    fn from(val: String) -> Self {
        Self(val)
    }
}

impl ExposeSecret<String> for SecretString {
    fn expose_secret(&self) -> &String {
        &self.0
    }
}

pub fn fill_random_bytes(dest: &mut [u8]) {
    getrandom::getrandom(dest).expect("OS CSPRNG (getrandom) failed");
}

pub fn random_u64() -> u64 {
    let mut buf = [0u8; 8];
    fill_random_bytes(&mut buf);
    u64::from_le_bytes(buf)
}

pub fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    fill_random_bytes(&mut buf);
    u32::from_le_bytes(buf)
}

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

#[derive(Debug)]
pub enum CryptoError {
    Vault(VaultError),
    Keyring(KeyringError),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vault(e) => write!(f, "Vault error: {e}"),
            Self::Keyring(e) => write!(f, "Keyring error: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<VaultError> for CryptoError {
    fn from(e: VaultError) -> Self {
        Self::Vault(e)
    }
}

impl From<KeyringError> for CryptoError {
    fn from(e: KeyringError) -> Self {
        Self::Keyring(e)
    }
}

impl CryptoError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CryptoError::Vault(e) => e.exit_code(),
            CryptoError::Keyring(e) => e.exit_code(),
        }
    }
}
