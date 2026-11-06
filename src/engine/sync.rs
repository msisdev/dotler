//! Dotfile synchronisation and repository tidy engine.
//!
//! Implements 3-way hash reconciliation, atomic file operations,
//! hash-based re-encryption skipping, and format tidying.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::local::{WalkDir, expand_tilde};
use crate::config::repo::{
    OsInfo, RepoConfig, SelectionMode, evaluate_selection, is_symlink, parse_selection_rules,
    resolve_group_target_path, validate_dir_no_symlinks, validate_os_dir_path,
    validate_os_target_path,
};
pub use crate::config::state::{ATOMIC_REPLACE_RETRIES, TMP_FILE_PREFIX, write_file_safe};
use crate::config::state::{DotlerLockGuard, StateDb, SyncedFileRecord};
use crate::crypto::ExposeSecret;
use crate::crypto::vault::{EncryptedFile, VaultKey};
use crate::engine::EngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileSyncStatus {
    Synced,
    ModifiedLocally,
    ModifiedInRepo,
    Conflict,
    MissingLocally,
    MissingInRepo,
    EncryptionMismatch,
    Orphaned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TidyOrphanPolicy {
    #[default]
    KeepOnOs,
    PurgeFromOs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileActionPlan {
    pub repo_label: String,
    pub group_name: String,
    pub relative_path: String,
    pub target_os_path: PathBuf,
    pub repo_file_path: PathBuf,
    pub status: FileSyncStatus,
    pub is_encrypted: bool,
    pub os_hash: Option<String>,
    pub repo_hash: Option<String>,
    pub db_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncReport {
    pub processed: usize,
    pub skipped: usize,
    pub conflicts: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TidyReport {
    pub encrypted_in_repo: usize,
    pub decrypted_in_repo: usize,
    pub removed_from_repo: usize,
    pub removed_os_orphans: Vec<PathBuf>,
    pub untracked_kept_orphans: Vec<PathBuf>,
}

pub struct SyncEngine<'a> {
    pub repo_label: String,
    pub repo_dir: PathBuf,
    pub repo_config: &'a RepoConfig,
    pub state_db: &'a StateDb,
    pub devices: Vec<String>,
    pub os_info: OsInfo,
    pub vault_key: Option<&'a VaultKey>,
    pub home_dir: Option<PathBuf>,
}

impl<'a> SyncEngine<'a> {
    pub fn new(
        repo_label: impl Into<String>,
        repo_dir: impl Into<PathBuf>,
        repo_config: &'a RepoConfig,
        state_db: &'a StateDb,
        devices: Vec<String>,
        os_info: OsInfo,
        vault_key: Option<&'a VaultKey>,
    ) -> Self {
        Self {
            repo_label: repo_label.into(),
            repo_dir: repo_dir.into(),
            repo_config,
            state_db,
            devices,
            os_info,
            vault_key,
            home_dir: None,
        }
    }

    pub fn with_home_dir(mut self, home: impl Into<PathBuf>) -> Self {
        self.home_dir = Some(home.into());
        self
    }

    fn effective_home_dir(&self) -> PathBuf {
        if let Some(ref home) = self.home_dir {
            home.clone()
        } else {
            expand_tilde("~")
        }
    }

    fn expand_target_base(&self, base_str: &str) -> PathBuf {
        if let Some(ref home) = self.home_dir {
            if base_str == "~" {
                home.clone()
            } else if let Some(stripped) = base_str.strip_prefix("~/") {
                home.join(stripped)
            } else {
                PathBuf::from(base_str)
            }
        } else {
            expand_tilde(base_str)
        }
    }

    /// 3-Way Hash Reconciliation (`plan`)
    pub fn plan(
        &self,
        group_filter: Option<&str>,
        _lock: &DotlerLockGuard,
    ) -> Result<Vec<FileActionPlan>, EngineError> {
        let mut plans = Vec::new();
        let home_dir = self.effective_home_dir();

        for (group_name, group_cfg) in &self.repo_config.groups {
            if let Some(filter) = group_filter
                && filter != group_name
            {
                continue;
            }

            let target_base_str =
                match resolve_group_target_path(group_cfg, &self.devices, &self.os_info) {
                    Some(base) => base,
                    None => continue,
                };
            let target_base_path = self.expand_target_base(&target_base_str);
            let rules = parse_selection_rules(&group_cfg.files)?;

            // 1. Gather candidate relative paths
            let mut candidates = BTreeSet::new();

            // Repo scan (strictly reject any symbolic links inside repository)
            let group_repo_dir = self.repo_dir.join(group_name);
            validate_dir_no_symlinks(&group_repo_dir)?;
            if group_repo_dir.is_dir() {
                for entry in WalkDir::new(&group_repo_dir)
                    .into_iter()
                    .filter_map(|e| e.ok())
                {
                    if entry.file_type().is_file() {
                        let file_name = entry.file_name().to_string_lossy();
                        if file_name.starts_with(TMP_FILE_PREFIX) {
                            continue;
                        }
                        if let Ok(rel) = entry.path().strip_prefix(&group_repo_dir) {
                            let rel_str = rel.to_string_lossy().to_string();
                            let clean_rel = if let Some(stripped) = rel_str.strip_suffix(".enc") {
                                stripped.to_string()
                            } else {
                                rel_str
                            };
                            candidates.insert(clean_rel);
                        }
                    }
                }
            }

            // Concrete rule patterns
            for rule in &rules {
                if !rule.pattern.contains('*')
                    && !rule.pattern.contains('?')
                    && !rule.pattern.contains('[')
                {
                    candidates.insert(rule.pattern.clone());
                }
            }

            // Database records
            if let Ok(records) = self.state_db.list_synced_files(Some(&self.repo_label)) {
                for r in records {
                    if r.group_name == *group_name {
                        candidates.insert(r.relative_path);
                    }
                }
            }

            // OS directory scan
            validate_os_dir_path(&target_base_path, &home_dir)?;
            if target_base_path.is_dir() {
                let dotler_config_dir = if let Some(ref home) = self.home_dir {
                    home.join(".config").join("dotler")
                } else {
                    expand_tilde("~/.config/dotler")
                };

                for entry in WalkDir::new(&target_base_path)
                    .filter_entry(|e| {
                        if e.depth() == 0 {
                            return true;
                        }
                        let p = e.path();
                        if p.starts_with(&dotler_config_dir) || p == dotler_config_dir {
                            return false;
                        }
                        if p.starts_with(&self.repo_dir) || p == self.repo_dir {
                            return false;
                        }
                        if e.file_name() == ".git" {
                            return false;
                        }
                        if let Ok(rel) = p.strip_prefix(&target_base_path) {
                            let rel_str = rel.to_string_lossy();
                            if rel_str == ".config/dotler" || rel_str.starts_with(".config/dotler/")
                            {
                                return false;
                            }
                            if rel_str.split('/').any(|s| s == ".git") {
                                return false;
                            }
                        }
                        true
                    })
                    .filter_map(|e| e.ok())
                {
                    if entry.file_type().is_file()
                        || (entry.file_type().is_symlink() && !entry.path().is_dir())
                    {
                        let file_name = entry.file_name().to_string_lossy();
                        if file_name.starts_with(TMP_FILE_PREFIX) {
                            continue;
                        }
                        if let Ok(rel) = entry.path().strip_prefix(&target_base_path) {
                            let rel_str = rel.to_string_lossy().to_string();
                            if rel_str == ".config/dotler" || rel_str.starts_with(".config/dotler/")
                            {
                                continue;
                            }
                            if rel_str.split('/').any(|s| s == ".git") {
                                continue;
                            }
                            if entry.path().starts_with(&self.repo_dir) {
                                continue;
                            }
                            if evaluate_selection(&rules, &rel_str).is_some() {
                                candidates.insert(rel_str);
                            }
                        }
                    }
                }
            }

            // 2. Evaluate each candidate
            for rel_path in candidates {
                if rel_path == ".config/dotler" || rel_path.starts_with(".config/dotler/") {
                    continue;
                }
                if rel_path.split('/').any(|s| s == ".git") {
                    continue;
                }
                let target_os_path = target_base_path.join(&rel_path);
                if target_os_path.starts_with(&self.repo_dir) {
                    continue;
                }
                let mode = evaluate_selection(&rules, &rel_path);

                // Read DB record
                let db_record = self
                    .state_db
                    .get_synced_file(&target_os_path.to_string_lossy())?;
                let db_hash = db_record.as_ref().map(|r| r.file_hash.clone());

                if mode.is_none() || mode == Some(SelectionMode::Exclude) {
                    if db_record.is_some() {
                        plans.push(FileActionPlan {
                            repo_label: self.repo_label.clone(),
                            group_name: group_name.clone(),
                            relative_path: rel_path.clone(),
                            target_os_path: target_os_path.clone(),
                            repo_file_path: group_repo_dir.join(&rel_path),
                            status: FileSyncStatus::Orphaned,
                            is_encrypted: false,
                            os_hash: None,
                            repo_hash: None,
                            db_hash,
                        });
                    }
                    continue;
                }

                validate_os_target_path(&target_os_path, &home_dir)?;

                let is_encrypted = mode == Some(SelectionMode::EncryptedInclude);
                let plain_repo_path = group_repo_dir.join(&rel_path);
                let enc_repo_path = group_repo_dir.join(format!("{}.enc", rel_path));

                // Read OS file
                let os_bytes = fs::read(&target_os_path).ok();
                let os_hash = os_bytes
                    .as_ref()
                    .map(|b| blake3::hash(b).to_hex().to_string());

                // Read Repo file & decrypt if encrypted
                let mut repo_hash = None;
                let mut encryption_mismatch = false;

                if is_encrypted {
                    if plain_repo_path.is_file() && !enc_repo_path.is_file() {
                        encryption_mismatch = true;
                    } else if enc_repo_path.is_file()
                        && let Ok(bytes) = fs::read(&enc_repo_path)
                        && let Ok(enc_file) = EncryptedFile::from_bytes(&bytes)
                        && let Some(key) = self.vault_key
                        && let Ok(plain) = key.decrypt_file(&enc_file)
                    {
                        repo_hash = Some(blake3::hash(plain.expose_secret()).to_hex().to_string());
                    }
                } else if enc_repo_path.is_file() && !plain_repo_path.is_file() {
                    encryption_mismatch = true;
                } else if plain_repo_path.is_file()
                    && let Ok(bytes) = fs::read(&plain_repo_path)
                {
                    repo_hash = Some(blake3::hash(&bytes).to_hex().to_string());
                }

                let chosen_repo_path = if is_encrypted {
                    enc_repo_path
                } else {
                    plain_repo_path
                };

                let status = if encryption_mismatch {
                    FileSyncStatus::EncryptionMismatch
                } else {
                    match (&os_hash, &repo_hash, &db_hash) {
                        (Some(os_h), Some(repo_h), _) if os_h == repo_h => FileSyncStatus::Synced,
                        (Some(os_h), Some(repo_h), Some(db_h)) => {
                            if os_h == db_h {
                                FileSyncStatus::ModifiedInRepo
                            } else if repo_h == db_h {
                                FileSyncStatus::ModifiedLocally
                            } else {
                                FileSyncStatus::Conflict
                            }
                        }
                        (Some(_), Some(_), None) => FileSyncStatus::Conflict,
                        (Some(_), None, Some(_)) => FileSyncStatus::MissingInRepo,
                        (Some(_), None, None) => FileSyncStatus::ModifiedLocally,
                        (None, Some(_), Some(_)) => FileSyncStatus::MissingLocally,
                        (None, Some(_), None) => FileSyncStatus::ModifiedInRepo,
                        (None, None, Some(_)) => FileSyncStatus::MissingLocally,
                        (None, None, None) => FileSyncStatus::MissingInRepo,
                    }
                };

                plans.push(FileActionPlan {
                    repo_label: self.repo_label.clone(),
                    group_name: group_name.clone(),
                    relative_path: rel_path,
                    target_os_path,
                    repo_file_path: chosen_repo_path,
                    status,
                    is_encrypted,
                    os_hash,
                    repo_hash,
                    db_hash,
                });
            }
        }

        plans.sort_by(|a, b| a.target_os_path.cmp(&b.target_os_path));
        Ok(plans)
    }

    /// Dotfile Repository Collection (`import_files`)
    pub fn import_files(
        &self,
        plans: &[FileActionPlan],
        _lock: &DotlerLockGuard,
        dry_run: bool,
    ) -> Result<SyncReport, EngineError> {
        let mut report = SyncReport::default();
        let home_dir = self.effective_home_dir();

        for plan in plans {
            if is_symlink(&plan.repo_file_path) {
                return Err(EngineError::HardBlockedPath {
                    path: plan.repo_file_path.clone(),
                    reason: "symbolic links are prohibited inside a dotler repository".to_string(),
                });
            }
            validate_os_target_path(&plan.target_os_path, &home_dir)?;

            if is_symlink(&plan.target_os_path) && !plan.target_os_path.is_file() {
                return Err(EngineError::HardBlockedPath {
                    path: plan.target_os_path.clone(),
                    reason: "broken symbolic link at OS target path cannot be imported".to_string(),
                });
            }

            if !plan.target_os_path.is_file() {
                continue;
            }

            let os_bytes = fs::read(&plan.target_os_path)?;
            let os_hash = blake3::hash(&os_bytes).to_hex().to_string();

            // Hash-based re-encryption skipping
            if plan.is_encrypted {
                let vault_key = self.vault_key.ok_or_else(|| EngineError::VaultLocked {
                    reason: "encrypted files detected but no vault key was provided".into(),
                })?;

                if plan.repo_file_path.is_file() {
                    let can_skip = if plan.db_hash.as_deref() == Some(&os_hash) {
                        true
                    } else if let Ok(enc_bytes) = fs::read(&plan.repo_file_path) {
                        if let Ok(enc_file) = EncryptedFile::from_bytes(&enc_bytes) {
                            if let Ok(decrypted) = vault_key.decrypt_file(&enc_file) {
                                blake3::hash(decrypted.expose_secret()).to_hex().to_string()
                                    == os_hash
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    if can_skip {
                        if !dry_run {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as i64;
                            self.state_db.upsert_synced_file(&SyncedFileRecord {
                                target_path: plan.target_os_path.to_string_lossy().to_string(),
                                repo_label: self.repo_label.clone(),
                                group_name: plan.group_name.clone(),
                                relative_path: plan.relative_path.clone(),
                                file_hash: os_hash.clone(),
                                updated_at: now,
                            })?;
                        }
                        report.skipped += 1;
                        continue;
                    }
                }

                if dry_run {
                    report.processed += 1;
                    continue;
                }

                let enc = vault_key.encrypt_file(&os_bytes)?;
                write_file_safe(&plan.repo_file_path, &enc.to_bytes())?;

                // Clean up conflicting plain file if any
                let plain_counterpart = plan.repo_file_path.with_extension("");
                if plain_counterpart.is_file() {
                    let _ = fs::remove_file(plain_counterpart);
                }
            } else {
                if plan.repo_file_path.is_file()
                    && let Ok(existing_bytes) = fs::read(&plan.repo_file_path)
                    && blake3::hash(&existing_bytes).to_hex().to_string() == os_hash
                {
                    if !dry_run {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64;
                        self.state_db.upsert_synced_file(&SyncedFileRecord {
                            target_path: plan.target_os_path.to_string_lossy().to_string(),
                            repo_label: self.repo_label.clone(),
                            group_name: plan.group_name.clone(),
                            relative_path: plan.relative_path.clone(),
                            file_hash: os_hash,
                            updated_at: now,
                        })?;
                    }
                    report.skipped += 1;
                    continue;
                }

                if dry_run {
                    report.processed += 1;
                    continue;
                }

                write_file_safe(&plan.repo_file_path, &os_bytes)?;

                // Clean up conflicting .enc file if any
                let enc_counterpart =
                    PathBuf::from(format!("{}.enc", plan.repo_file_path.display()));
                if enc_counterpart.is_file() {
                    let _ = fs::remove_file(enc_counterpart);
                }
            }

            // Per-file immediate DB commit
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            self.state_db.upsert_synced_file(&SyncedFileRecord {
                target_path: plan.target_os_path.to_string_lossy().to_string(),
                repo_label: self.repo_label.clone(),
                group_name: plan.group_name.clone(),
                relative_path: plan.relative_path.clone(),
                file_hash: os_hash,
                updated_at: now,
            })?;

            report.processed += 1;
        }

        Ok(report)
    }

    /// Dotfile Filesystem Deployment (`export_files`)
    pub fn export_files(
        &self,
        plans: &[FileActionPlan],
        _lock: &DotlerLockGuard,
        force: bool,
        dry_run: bool,
    ) -> Result<SyncReport, EngineError> {
        let mut report = SyncReport::default();
        let home_dir = self.effective_home_dir();

        for plan in plans {
            if is_symlink(&plan.repo_file_path) {
                return Err(EngineError::HardBlockedPath {
                    path: plan.repo_file_path.clone(),
                    reason: "symbolic links are prohibited inside a dotler repository".to_string(),
                });
            }

            if plan.status == FileSyncStatus::EncryptionMismatch {
                return Err(EngineError::EncryptionMismatch {
                    path: plan.repo_file_path.clone(),
                    reason: format!(
                        "Repository file '{}' format conflicts with encryption rule in dotler.toml. Run 'dotler tidy' to reconcile format.",
                        plan.relative_path
                    ),
                });
            }

            if !plan.repo_file_path.is_file() {
                continue;
            }

            validate_os_target_path(&plan.target_os_path, &home_dir)?;

            // Read repo plaintext
            let plaintext_bytes = if plan.is_encrypted {
                let vault_key = self.vault_key.ok_or_else(|| EngineError::VaultLocked {
                    reason: "encrypted files detected but no vault key was provided".into(),
                })?;
                let raw_enc = fs::read(&plan.repo_file_path)?;
                let enc_file = EncryptedFile::from_bytes(&raw_enc)?;
                let decrypted = vault_key.decrypt_file(&enc_file)?;
                decrypted.expose_secret().clone()
            } else {
                fs::read(&plan.repo_file_path)?
            };

            let repo_hash = blake3::hash(&plaintext_bytes).to_hex().to_string();

            // Hash-Match Idempotency (always materialize if target is currently a symlink)
            let target_is_symlink = is_symlink(&plan.target_os_path);
            if plan.target_os_path.is_file() {
                let os_bytes = fs::read(&plan.target_os_path)?;
                let os_hash = blake3::hash(&os_bytes).to_hex().to_string();

                if os_hash == repo_hash && !target_is_symlink {
                    if !dry_run {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64;
                        self.state_db.upsert_synced_file(&SyncedFileRecord {
                            target_path: plan.target_os_path.to_string_lossy().to_string(),
                            repo_label: self.repo_label.clone(),
                            group_name: plan.group_name.clone(),
                            relative_path: plan.relative_path.clone(),
                            file_hash: repo_hash,
                            updated_at: now,
                        })?;
                    }
                    report.skipped += 1;
                    continue;
                }

                // Conflict detection
                if os_hash != repo_hash
                    && !force
                    && (plan.status == FileSyncStatus::ModifiedLocally
                        || plan.status == FileSyncStatus::Conflict
                        || (plan.db_hash.is_some() && plan.db_hash.as_deref() != Some(&os_hash)))
                {
                    report.conflicts.push(plan.target_os_path.clone());
                    return Err(EngineError::SyncConflict {
                        path: plan.target_os_path.clone(),
                        reason:
                            "target file was modified locally and does not match repository. Use --force to overwrite."
                                .to_string(),
                    });
                }
            }

            if dry_run {
                report.processed += 1;
                continue;
            }

            write_file_safe(&plan.target_os_path, &plaintext_bytes)?;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            self.state_db.upsert_synced_file(&SyncedFileRecord {
                target_path: plan.target_os_path.to_string_lossy().to_string(),
                repo_label: self.repo_label.clone(),
                group_name: plan.group_name.clone(),
                relative_path: plan.relative_path.clone(),
                file_hash: repo_hash,
                updated_at: now,
            })?;

            report.processed += 1;
        }

        Ok(report)
    }

    /// Integrated Tidy (`tidy`) for an optional single group filter.
    pub fn tidy(
        &self,
        group_filter: Option<&str>,
        lock: &DotlerLockGuard,
        policy: TidyOrphanPolicy,
        dry_run: bool,
    ) -> Result<TidyReport, EngineError> {
        let filters: Vec<String> = group_filter.into_iter().map(str::to_string).collect();
        self.tidy_groups(&filters, lock, policy, dry_run)
    }

    /// Integrated Tidy (`tidy`) supporting zero, one, or multiple group filters.
    pub fn tidy_groups(
        &self,
        group_filters: &[String],
        lock: &DotlerLockGuard,
        policy: TidyOrphanPolicy,
        dry_run: bool,
    ) -> Result<TidyReport, EngineError> {
        let mut report = TidyReport::default();
        let all_synced = self.state_db.list_synced_files(Some(&self.repo_label))?;

        for filter in group_filters {
            let exists_in_repo = self.repo_config.groups.contains_key(filter);
            let exists_in_db = all_synced.iter().any(|r| &r.group_name == filter);
            if !exists_in_repo && !exists_in_db {
                return Err(EngineError::GroupNotFound {
                    group: filter.clone(),
                    available: self.repo_config.groups.keys().cloned().collect(),
                });
            }
        }

        // 1. In-Repo Format Reconciliation
        for (group_name, group_cfg) in &self.repo_config.groups {
            if !group_filters.is_empty() && !group_filters.iter().any(|f| f == group_name) {
                continue;
            }

            let group_repo_dir = self.repo_dir.join(group_name);
            validate_dir_no_symlinks(&group_repo_dir)?;
            if !group_repo_dir.is_dir() {
                continue;
            }

            let rules = parse_selection_rules(&group_cfg.files)?;

            for entry in WalkDir::new(&group_repo_dir)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                let file_name = entry.file_name().to_string_lossy();
                if file_name.starts_with(TMP_FILE_PREFIX) {
                    continue;
                }

                let path = entry.path();
                let rel = match path.strip_prefix(&group_repo_dir) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let rel_str = rel.to_string_lossy().to_string();
                let is_enc_ext = rel_str.ends_with(".enc");
                let clean_rel = if is_enc_ext {
                    rel_str.strip_suffix(".enc").unwrap()
                } else {
                    &rel_str
                };

                let mode = evaluate_selection(&rules, clean_rel);
                match mode {
                    Some(SelectionMode::EncryptedInclude) => {
                        if !is_enc_ext {
                            let vault_key =
                                self.vault_key.ok_or_else(|| EngineError::VaultLocked {
                                    reason: "vault key required for tidy in-repo encryption".into(),
                                })?;
                            if !dry_run {
                                let plaintext = fs::read(path)?;
                                let enc = vault_key.encrypt_file(&plaintext)?;
                                let target_enc = group_repo_dir.join(format!("{clean_rel}.enc"));
                                write_file_safe(&target_enc, &enc.to_bytes())?;
                                let _ = fs::remove_file(path);
                            }
                            report.encrypted_in_repo += 1;
                        }
                    }
                    Some(SelectionMode::PlaintextInclude) => {
                        if is_enc_ext {
                            let vault_key =
                                self.vault_key.ok_or_else(|| EngineError::VaultLocked {
                                    reason: "vault key required for tidy in-repo decryption".into(),
                                })?;
                            if !dry_run {
                                let raw_enc = fs::read(path)?;
                                let enc = EncryptedFile::from_bytes(&raw_enc)?;
                                let decrypted = vault_key.decrypt_file(&enc)?;
                                let target_plain = group_repo_dir.join(clean_rel);
                                write_file_safe(&target_plain, decrypted.expose_secret())?;
                                let _ = fs::remove_file(path);
                            }
                            report.decrypted_in_repo += 1;
                        }
                    }
                    Some(SelectionMode::Exclude) | None => {
                        if !dry_run {
                            let _ = fs::remove_file(path);
                        }
                        report.removed_from_repo += 1;
                    }
                }
            }
        }

        // 2. Orphan Cleanup (`synced_files`)
        let mut plans = Vec::new();
        if group_filters.is_empty() {
            plans = self.plan(None, lock)?;
        } else {
            for g in group_filters {
                if self.repo_config.groups.contains_key(g) {
                    let mut p = self.plan(Some(g.as_str()), lock)?;
                    plans.append(&mut p);
                }
            }
        }

        let active_target_paths: std::collections::HashSet<String> = plans
            .iter()
            .filter(|p| p.status != FileSyncStatus::Orphaned)
            .map(|p| p.target_os_path.to_string_lossy().to_string())
            .collect();

        let orphaned: Vec<String> = all_synced
            .into_iter()
            .filter(|rec| {
                group_filters.is_empty() || group_filters.iter().any(|g| g == &rec.group_name)
            })
            .map(|rec| rec.target_path)
            .filter(|target| !active_target_paths.contains(target))
            .collect();

        for orphan_path_str in orphaned {
            let orphan_path = PathBuf::from(&orphan_path_str);
            match policy {
                TidyOrphanPolicy::PurgeFromOs => {
                    if (orphan_path.is_file() || is_symlink(&orphan_path)) && !dry_run {
                        let _ = fs::remove_file(&orphan_path);
                    }
                    if !dry_run {
                        let _ = self.state_db.remove_synced_file(&orphan_path_str);
                    }
                    report.removed_os_orphans.push(orphan_path);
                }
                TidyOrphanPolicy::KeepOnOs => {
                    if !dry_run {
                        let _ = self.state_db.remove_synced_file(&orphan_path_str);
                    }
                    report.untracked_kept_orphans.push(orphan_path);
                }
            }
        }

        Ok(report)
    }
}

pub fn plan(
    engine: &SyncEngine,
    group_filter: Option<&str>,
    lock: &DotlerLockGuard,
) -> Result<Vec<FileActionPlan>, EngineError> {
    engine.plan(group_filter, lock)
}

pub fn import_files(
    engine: &SyncEngine,
    plans: &[FileActionPlan],
    lock: &DotlerLockGuard,
    dry_run: bool,
) -> Result<SyncReport, EngineError> {
    engine.import_files(plans, lock, dry_run)
}

pub fn export_files(
    engine: &SyncEngine,
    plans: &[FileActionPlan],
    lock: &DotlerLockGuard,
    force: bool,
    dry_run: bool,
) -> Result<SyncReport, EngineError> {
    engine.export_files(plans, lock, force, dry_run)
}

pub fn tidy(
    engine: &SyncEngine,
    group_filter: Option<&str>,
    lock: &DotlerLockGuard,
    policy: TidyOrphanPolicy,
    dry_run: bool,
) -> Result<TidyReport, EngineError> {
    engine.tidy(group_filter, lock, policy, dry_run)
}

pub fn tidy_groups(
    engine: &SyncEngine,
    group_filters: &[String],
    lock: &DotlerLockGuard,
    policy: TidyOrphanPolicy,
    dry_run: bool,
) -> Result<TidyReport, EngineError> {
    engine.tidy_groups(group_filters, lock, policy, dry_run)
}
