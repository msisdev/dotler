//! Core resource and workspace context loader subsystem.
//!
//! Provides lazy evaluation resource containers (`Resource<T, E>`), unified
//! workspace context resolution (`CoreContext`, `ResolvedRepoContext`), and
//! conditional vault master key unlocking and passphrase rotation.

pub mod context;
pub mod resource;
pub mod vault_loader;

pub use context::{CoreContext, ResolvedRepoContext};
pub use resource::{
    Resource, get_local_config, get_lock, get_password, get_repo_config, get_state_db,
};
pub use vault_loader::{
    VaultPasswdReport, VaultUnlockPolicy, has_encrypted_repo_files, has_encrypted_rules,
    read_new_passphrase, resolve_old_passphrase_for_vaults, rotate_vault_passphrases,
    unlock_vault_if_needed,
};
