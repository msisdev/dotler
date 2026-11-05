//! Generic lazy resource container backed by [`OnceCell`] and `loader`/`saver` closures.

use std::cell::OnceCell;

type ResourceLoader<T, E> = Box<dyn Fn() -> Result<T, E>>;
type ResourceSaver<T, E> = Box<dyn Fn(&T) -> Result<(), E>>;

/// Functional lazy resource container backed by [`OnceCell`] and `loader`/`saver` closures.
///
/// Underlying resources (configuration files, SQLite connections, OS keyring secrets)
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
