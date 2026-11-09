//! Generic lazy resource container backed by [`OnceCell`] and `loader`/`saver` closures.

use std::cell::OnceCell;
use std::path::PathBuf;

use crate::config::local::LocalConfig;
use crate::config::repo::RepoConfig;
use crate::config::state::{DotlerLockGuard, StateDb};
use crate::config::{ConfigError, LockError, StateError};
use crate::crypto::SecretString;
use crate::crypto::keyring::KeyringError;

type ResourceLoader<T, E> = Box<dyn Fn() -> Result<T, E>>;
type ResourceSaver<T, E> = Box<dyn Fn(&T) -> Result<(), E>>;

/// Functional lazy resource container backed by [`OnceCell`] and `loader`/`saver` closures.
///
/// Underlying resources (process locks, configuration files, SQLite connections, OS keyring secrets)
/// are accessed only on the first call to [`Resource::get`], and updated via [`Resource::set`].
pub struct Resource<T, E> {
    cache: OnceCell<T>,
    loader: ResourceLoader<T, E>,
    saver: ResourceSaver<T, E>,
}

impl<T, E> Resource<T, E> {
    pub fn new<L, S>(loader: L, saver: S) -> Self
    where
        L: Fn() -> Result<T, E> + 'static,
        S: Fn(&T) -> Result<(), E> + 'static,
    {
        Self {
            cache: OnceCell::new(),
            loader: Box::new(loader),
            saver: Box::new(saver),
        }
    }

    pub fn from_value(value: T) -> Self
    where
        T: 'static,
        E: 'static,
    {
        Self {
            cache: OnceCell::from(value),
            loader: Box::new(|| unreachable!("Resource already initialized")),
            saver: Box::new(|_| Ok(())),
        }
    }

    pub fn get(&self) -> Result<&T, E> {
        if let Some(val) = self.cache.get() {
            return Ok(val);
        }
        let loaded = (self.loader)()?;
        let _ = self.cache.set(loaded);
        Ok(self.cache.get().expect("OnceCell initialized"))
    }

    pub fn set(&mut self, value: T) -> Result<(), E> {
        (self.saver)(&value)?;
        self.cache = OnceCell::from(value);
        Ok(())
    }
}

/// Creates a lazy [`Resource`] for acquiring the exclusive process lock (`dotler.lock`).
pub fn get_lock(path: PathBuf) -> Resource<DotlerLockGuard, LockError> {
    crate::config::state::get_lock(path)
}

/// Creates a lazy [`Resource`] for loading and saving [`LocalConfig`] (`config.toml`).
pub fn get_local_config(path: PathBuf) -> Resource<LocalConfig, ConfigError> {
    crate::config::local::get_local_config(path)
}

/// Creates a lazy [`Resource`] for loading and saving [`RepoConfig`] (`dotler.toml`).
pub fn get_repo_config(path: PathBuf) -> Resource<RepoConfig, ConfigError> {
    crate::config::repo::get_repo_config(path)
}

/// Creates a lazy [`Resource`] for opening [`StateDb`] (`state.db`).
pub fn get_state_db(path: PathBuf) -> Resource<StateDb, StateError> {
    crate::config::state::get_state_db(path)
}

/// Creates a lazy [`Resource`] for resolving or storing the vault passphrase.
pub fn get_password(
    use_keyring: bool,
    hint: Option<String>,
    is_interactive: bool,
    stdin_passphrase: Option<String>,
) -> Resource<SecretString, KeyringError> {
    crate::crypto::keyring::get_password(use_keyring, hint, is_interactive, stdin_passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;

    #[test]
    fn resource_loads_lazily_and_persists_via_set() {
        let load_count = Rc::new(Cell::new(0usize));
        let save_count = Rc::new(Cell::new(0usize));

        let lc = Rc::clone(&load_count);
        let sc = Rc::clone(&save_count);

        let mut res = Resource::new(
            move || {
                lc.set(lc.get() + 1);
                Ok::<String, &'static str>("initial".to_string())
            },
            move |_val: &String| {
                sc.set(sc.get() + 1);
                Ok::<(), &'static str>(())
            },
        );

        assert_eq!(load_count.get(), 0, "loader must not run before get()");
        assert_eq!(res.get().unwrap(), "initial");
        assert_eq!(load_count.get(), 1, "loader runs once on first get()");
        assert_eq!(res.get().unwrap(), "initial");
        assert_eq!(load_count.get(), 1, "subsequent get() returns cached value");

        res.set("updated".to_string()).unwrap();
        assert_eq!(save_count.get(), 1, "saver runs on set()");
        assert_eq!(res.get().unwrap(), "updated");
        assert_eq!(load_count.get(), 1, "get() after set() uses updated cache");
    }

    #[test]
    fn resource_preserves_cache_when_saver_fails() {
        let mut res = Resource::new(
            || Ok::<String, &'static str>("initial".to_string()),
            |val: &String| {
                if val == "bad" {
                    Err("save failed")
                } else {
                    Ok(())
                }
            },
        );

        assert_eq!(res.get().unwrap(), "initial");
        assert!(res.set("bad".to_string()).is_err());
        assert_eq!(res.get().unwrap(), "initial");
    }
}
