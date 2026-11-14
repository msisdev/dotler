use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::config::ConfigError;

pub struct WalkEntry {
    path: PathBuf,
    file_name: std::ffi::OsString,
    file_type: fs::FileType,
    depth: usize,
}

impl WalkEntry {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file_name(&self) -> &std::ffi::OsStr {
        &self.file_name
    }

    pub fn file_type(&self) -> fs::FileType {
        self.file_type
    }

    pub fn depth(&self) -> usize {
        self.depth
    }
}

pub struct WalkDir {
    root: PathBuf,
    min_depth: usize,
}

impl WalkDir {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            min_depth: 0,
        }
    }

    pub fn min_depth(mut self, depth: usize) -> Self {
        self.min_depth = depth;
        self
    }

    pub fn filter_entry<P>(self, mut predicate: P) -> std::vec::IntoIter<std::io::Result<WalkEntry>>
    where
        P: FnMut(&WalkEntry) -> bool,
    {
        let mut out = Vec::new();
        Self::collect_entries(&self.root, 0, self.min_depth, &mut predicate, &mut out);
        out.into_iter()
    }

    fn collect_entries<P>(
        path: &Path,
        depth: usize,
        min_depth: usize,
        predicate: &mut P,
        out: &mut Vec<std::io::Result<WalkEntry>>,
    ) where
        P: FnMut(&WalkEntry) -> bool,
    {
        let meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) => {
                out.push(Err(e));
                return;
            }
        };
        let file_type = meta.file_type();
        let file_name = path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| path.as_os_str().to_os_string());
        let entry = WalkEntry {
            path: path.to_path_buf(),
            file_name,
            file_type,
            depth,
        };
        if !predicate(&entry) {
            return;
        }
        let is_real_dir = file_type.is_dir() && !file_type.is_symlink();
        if depth >= min_depth {
            out.push(Ok(entry));
        }
        if is_real_dir {
            match fs::read_dir(path) {
                Ok(rd) => {
                    let mut children: Vec<PathBuf> =
                        rd.filter_map(|r| r.ok().map(|e| e.path())).collect();
                    children.sort();
                    for child in children {
                        Self::collect_entries(&child, depth + 1, min_depth, predicate, out);
                    }
                }
                Err(e) => out.push(Err(e)),
            }
        }
    }
}

impl IntoIterator for WalkDir {
    type Item = std::io::Result<WalkEntry>;
    type IntoIter = std::vec::IntoIter<std::io::Result<WalkEntry>>;

    fn into_iter(self) -> Self::IntoIter {
        self.filter_entry(|_| true)
    }
}

pub fn validate_path_security(path: &str) -> Result<(), ConfigError> {
    if path != "~" && !path.starts_with("~/") {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "path must start with '~' or '~/'".to_string(),
        });
    }

    if path.contains("..") {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "directory traversal ('..') is prohibited".to_string(),
        });
    }

    if path.contains('$') || path.contains('%') {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "environment variable expansion is prohibited".to_string(),
        });
    }

    if path.contains('\\') {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "backslash path separators are prohibited".to_string(),
        });
    }

    let trimmed = path.trim_end_matches('/');

    if trimmed == "~/.config/dotler" || trimmed.starts_with("~/.config/dotler/") {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "path cannot point inside ~/.config/dotler".to_string(),
        });
    }

    if trimmed.split('/').any(|segment| segment == ".git") {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "path cannot target .git directories".to_string(),
        });
    }

    Ok(())
}

/// Returns true if `path` itself is a symbolic link (including broken/dangling links).
pub fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
}

/// Rejects any symbolic link (file, directory, or broken link) inside a repository directory.
pub fn validate_dir_no_symlinks(dir: &Path) -> Result<(), ConfigError> {
    if is_symlink(dir) {
        return Err(ConfigError::HardBlockedPath {
            path: dir.display().to_string(),
            reason: "symbolic links are prohibited inside a dotler repository".to_string(),
        });
    }
    if !dir.exists() {
        return Ok(());
    }
    for entry in WalkDir::new(dir) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let p = entry.path();
        if p.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }
        if entry.file_type().is_symlink() || is_symlink(p) {
            return Err(ConfigError::HardBlockedPath {
                path: p.display().to_string(),
                reason: "symbolic links are prohibited inside a dotler repository".to_string(),
            });
        }
    }
    Ok(())
}

fn normalize_lexical_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn resolve_with_existing_ancestors(path: &Path) -> PathBuf {
    let lexical = normalize_lexical_path(path);
    let mut current = lexical.as_path();
    while let Some(parent) = current.parent() {
        if current.exists() {
            if let Ok(canon) = fs::canonicalize(current)
                && let Ok(tail) = lexical.strip_prefix(current)
            {
                if tail.as_os_str().is_empty() {
                    return canon;
                }
                return normalize_lexical_path(&canon.join(tail));
            }
            break;
        }
        if parent == current {
            break;
        }
        current = parent;
    }
    lexical
}

fn check_within_home_and_unprotected(
    original_path: &Path,
    resolved_path: &Path,
    canonical_home: &Path,
    canonical_dotler_dir: &Path,
) -> Result<(), ConfigError> {
    if !resolved_path.starts_with(canonical_home) {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: format!(
                "symbolic link target '{}' escapes home directory ('~')",
                resolved_path.display()
            ),
        });
    }
    if resolved_path == canonical_dotler_dir || resolved_path.starts_with(canonical_dotler_dir) {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: "symbolic link target cannot point inside ~/.config/dotler".to_string(),
        });
    }
    if let Ok(rel) = resolved_path.strip_prefix(canonical_home)
        && rel.components().any(|c| c.as_os_str() == ".git")
    {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: "symbolic link target cannot point inside a .git directory".to_string(),
        });
    }
    Ok(())
}

/// Validates that an OS target directory (and its existing ancestors) stays within `home_dir`.
pub fn validate_os_dir_path(target_dir: &Path, home_dir: &Path) -> Result<(), ConfigError> {
    let canonical_home =
        fs::canonicalize(home_dir).unwrap_or_else(|_| normalize_lexical_path(home_dir));
    let canonical_dotler_dir = canonical_home.join(".config").join("dotler");

    let mut curr_opt = Some(target_dir);
    while let Some(curr) = curr_opt {
        if is_symlink(curr) && !curr.exists() {
            return Err(ConfigError::HardBlockedPath {
                path: target_dir.display().to_string(),
                reason: format!(
                    "directory path '{}' is a broken symbolic link",
                    curr.display()
                ),
            });
        }
        if curr.exists() {
            let canonical_curr = fs::canonicalize(curr)?;
            check_within_home_and_unprotected(
                target_dir,
                &canonical_curr,
                &canonical_home,
                &canonical_dotler_dir,
            )?;
            if !canonical_curr.is_dir() {
                return Err(ConfigError::HardBlockedPath {
                    path: target_dir.display().to_string(),
                    reason: format!(
                        "target directory path '{}' is not a directory",
                        curr.display()
                    ),
                });
            }
            break;
        }
        curr_opt = curr.parent();
    }
    Ok(())
}

/// Validates that an OS target file path (and its ancestors) does not escape `home_dir`
/// or enter protected directories via symbolic links.
pub fn validate_os_target_path(target_os_path: &Path, home_dir: &Path) -> Result<(), ConfigError> {
    let canonical_home =
        fs::canonicalize(home_dir).unwrap_or_else(|_| normalize_lexical_path(home_dir));
    let canonical_dotler_dir = canonical_home.join(".config").join("dotler");

    if let Some(parent) = target_os_path.parent() {
        validate_os_dir_path(parent, home_dir)?;
    }

    if is_symlink(target_os_path) {
        if target_os_path.exists() {
            let canonical_target = fs::canonicalize(target_os_path)?;
            check_within_home_and_unprotected(
                target_os_path,
                &canonical_target,
                &canonical_home,
                &canonical_dotler_dir,
            )?;
            if !canonical_target.is_file() {
                return Err(ConfigError::HardBlockedPath {
                    path: target_os_path.display().to_string(),
                    reason: "symbolic link at target file path must point to a regular file"
                        .to_string(),
                });
            }
        } else {
            let link_target = fs::read_link(target_os_path)?;
            let parent = target_os_path.parent().unwrap_or(home_dir);
            let canonical_parent =
                fs::canonicalize(parent).unwrap_or_else(|_| normalize_lexical_path(parent));
            let joined = if link_target.is_absolute() {
                link_target
            } else {
                canonical_parent.join(link_target)
            };
            let resolved = resolve_with_existing_ancestors(&joined);
            check_within_home_and_unprotected(
                target_os_path,
                &resolved,
                &canonical_home,
                &canonical_dotler_dir,
            )?;
        }
    }

    Ok(())
}

pub fn validate_rule_pattern(pattern: &str) -> Result<(), ConfigError> {
    if pattern.is_empty() {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern cannot be empty".to_string(),
        });
    }

    if pattern.starts_with('/') || pattern.starts_with('~') {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern must be a relative path and cannot start with '/' or '~'"
                .to_string(),
        });
    }

    if pattern.contains("..") {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "directory traversal ('..') is prohibited".to_string(),
        });
    }

    if pattern.contains('$') || pattern.contains('%') {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "environment variable expansion is prohibited".to_string(),
        });
    }

    if pattern.contains('\\') {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "backslash path separators are prohibited".to_string(),
        });
    }

    let trimmed = pattern.trim_start_matches("./").trim_end_matches('/');

    if trimmed.is_empty() || trimmed == "." {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern cannot be empty".to_string(),
        });
    }

    if trimmed == ".config/dotler" || trimmed.starts_with(".config/dotler/") {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern cannot target internal dotler configuration directory ('~/.config/dotler')".to_string(),
        });
    }

    if trimmed.split('/').any(|segment| segment == ".git") {
        return Err(ConfigError::HardBlockedPath {
            path: pattern.to_string(),
            reason: "selection pattern cannot target .git directories".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_security_checks() {
        assert!(validate_path_security("~/.config/app").is_ok());
        assert!(validate_path_security("~/").is_ok());
        assert!(validate_path_security("~").is_ok());

        assert!(matches!(
            validate_path_security("/etc/app").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~/app/../secret").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~/app/$HOME").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~/app/%USERPROFILE%").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~\\app\\conf").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
    }


    #[test]
    fn test_path_security_checks_protects_internal_paths() {
        assert!(validate_path_security("~/.config/dotler").is_err());
        assert!(validate_path_security("~/.config/dotler/state.db").is_err());
        assert!(validate_path_security("~/.git").is_err());
        assert!(validate_path_security("~/.git/hooks").is_err());

        // Allowed dotfiles that contain git as substring
        assert!(validate_path_security("~/.gitconfig").is_ok());
        assert!(validate_path_security("~/.gitignore").is_ok());
        assert!(validate_path_security("~/.github").is_ok());
    }


    #[test]
    fn test_rule_pattern_security_checks() {
        assert!(validate_rule_pattern("").is_err());
        assert!(validate_rule_pattern("../secret").is_err());
        assert!(validate_rule_pattern("/etc/shadow").is_err());
        assert!(validate_rule_pattern("~/file").is_err());
        assert!(validate_rule_pattern("$HOME/file").is_err());
        assert!(validate_rule_pattern("%USER%/file").is_err());
        assert!(validate_rule_pattern("folder\\file").is_err());
        assert!(validate_rule_pattern(".config/dotler").is_err());
        assert!(validate_rule_pattern(".git").is_err());
        assert!(validate_rule_pattern(".git/hooks").is_err());

        assert!(validate_rule_pattern(".gitconfig").is_ok());
        assert!(validate_rule_pattern("custom.conf").is_ok());
        assert!(validate_rule_pattern("*.conf").is_ok());
    }

}
