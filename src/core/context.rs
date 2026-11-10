//! Workspace execution context loader unifying CLI and MCP resource resolution.

use std::path::PathBuf;

use crate::config::local::{
    LOCAL_CONFIG_FILE, LocalConfig, expand_tilde, resolve_repo_path_with_cwd,
};
use crate::config::repo::{OsInfo, RepoConfig};
use crate::config::state::{DOTLER_LOCK_PATH, DotlerLockGuard, STATE_DB_PATH, StateDb};
use crate::config::{ConfigError, LockError, StateError};
use crate::core::resource::{Resource, get_local_config, get_lock, get_repo_config, get_state_db};
use crate::engine::EngineError;

/// Core resource handle container passed to command execution functions.
pub struct CoreContext {
    pub lock: Resource<DotlerLockGuard, LockError>,
    pub local_config: Resource<LocalConfig, ConfigError>,
    pub state_db: Resource<StateDb, StateError>,
    pub repo_override: Option<String>,
    pub device_override: Option<String>,
    pub is_interactive: bool,
}

/// Snapshot of the resolved target repository, manifest, active devices, and OS environment.
#[derive(Debug, Clone)]
pub struct ResolvedRepoContext {
    pub label: String,
    pub repo_path: PathBuf,
    pub repo_config: RepoConfig,
    pub devices: Vec<String>,
    pub os_info: OsInfo,
}

impl CoreContext {
    /// Creates a new [`CoreContext`] bound to the default home configuration paths.
    pub fn new(
        repo_override: Option<String>,
        device_override: Option<String>,
        is_interactive: bool,
    ) -> Self {
        Self::with_paths(
            expand_tilde(DOTLER_LOCK_PATH),
            expand_tilde(LOCAL_CONFIG_FILE),
            expand_tilde(STATE_DB_PATH),
            repo_override,
            device_override,
            is_interactive,
        )
    }

    /// Creates a new [`CoreContext`] with explicit lock, config, and state database paths.
    pub fn with_paths(
        lock_path: PathBuf,
        local_config_path: PathBuf,
        state_db_path: PathBuf,
        repo_override: Option<String>,
        device_override: Option<String>,
        is_interactive: bool,
    ) -> Self {
        Self {
            lock: get_lock(lock_path),
            local_config: get_local_config(local_config_path),
            state_db: get_state_db(state_db_path),
            repo_override,
            device_override,
            is_interactive,
        }
    }

    /// Computes the effective device priority list, placing `device_override` at index 0 when set.
    pub fn effective_devices(&self, local_cfg: &LocalConfig) -> Vec<String> {
        let mut devices = local_cfg.default_devices.clone();
        if let Some(ref d) = self.device_override {
            devices.retain(|existing| existing != d);
            devices.insert(0, d.clone());
        }
        devices
    }

    /// Resolves the target repository path and loads `<repo>/dotler.toml`.
    pub fn resolve_repo(&self) -> Result<ResolvedRepoContext, EngineError> {
        let local_cfg = self.local_config.get()?;
        let (label, repo_path) =
            resolve_repo_path_with_cwd(local_cfg, self.repo_override.as_deref())?;
        let repo_cfg_res = get_repo_config(repo_path.join("dotler.toml"));
        let repo_config = repo_cfg_res.get()?.clone();
        let devices = self.effective_devices(local_cfg);
        let os_info = OsInfo::detect();

        Ok(ResolvedRepoContext {
            label,
            repo_path,
            repo_config,
            devices,
            os_info,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn resolve_repo_loads_label_and_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("my-dots");
        fs::create_dir_all(&repo_dir).unwrap();
        fs::write(
            repo_dir.join("dotler.toml"),
            "[nvim]\nos-nux = \"~/.config/nvim\"\nos-mac = \"~/.config/nvim\"\nfiles = \"*\"\n",
        )
        .unwrap();

        let cfg_path = tmp.path().join("config.toml");
        let mut local_cfg = LocalConfig {
            default_repo: Some("work".to_string()),
            default_devices: vec!["desktop".to_string()],
            ..Default::default()
        };
        local_cfg
            .repos
            .insert("work".to_string(), repo_dir.to_string_lossy().to_string());

        let mut ctx = CoreContext::with_paths(
            tmp.path().join("dotler.lock"),
            cfg_path,
            tmp.path().join("state.db"),
            None,
            None,
            false,
        );
        ctx.local_config = Resource::from_value(local_cfg);

        let resolved = ctx.resolve_repo().unwrap();
        assert_eq!(resolved.label, "work");
        assert_eq!(resolved.repo_path, repo_dir);
        assert!(resolved.repo_config.groups.contains_key("nvim"));
        assert_eq!(resolved.devices, vec!["desktop".to_string()]);
    }

    #[test]
    fn effective_devices_places_override_first() {
        let tmp = tempfile::tempdir().unwrap();
        let local_cfg = LocalConfig {
            default_devices: vec!["workstation".to_string(), "laptop".to_string()],
            ..Default::default()
        };

        let ctx = CoreContext::with_paths(
            tmp.path().join("dotler.lock"),
            tmp.path().join("config.toml"),
            tmp.path().join("state.db"),
            None,
            Some("gaming-rig".to_string()),
            false,
        );

        let devices = ctx.effective_devices(&local_cfg);
        assert_eq!(
            devices,
            vec![
                "gaming-rig".to_string(),
                "workstation".to_string(),
                "laptop".to_string()
            ]
        );
    }
}
