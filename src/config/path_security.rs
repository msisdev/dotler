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

/// Returns true if `path` is anchored at the user's home directory (`"~"` or `"~/..."`).
pub fn is_home_group_path(path: &str) -> bool {
    path == "~" || path.starts_with("~/")
}

/// Returns true if `path` is anchored at the current working directory (`"."` or `"./..."`).
pub fn is_cwd_group_path(path: &str) -> bool {
    path == "." || path.starts_with("./")
}

pub fn validate_path_security(path: &str) -> Result<(), ConfigError> {
    if !is_home_group_path(path) && !is_cwd_group_path(path) {
        return Err(ConfigError::HardBlockedPath {
            path: path.to_string(),
            reason: "path must start with '~', '~/', '.', or './'".to_string(),
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

    if is_cwd_group_path(path) {
        let mut rel = trimmed
            .strip_prefix('.')
            .unwrap_or(trimmed)
            .trim_start_matches('/');
        while let Some(rest) = rel.strip_prefix("./") {
            rel = rest.trim_start_matches('/');
        }
        if rel == ".config/dotler" || rel.starts_with(".config/dotler/") {
            return Err(ConfigError::HardBlockedPath {
                path: path.to_string(),
                reason: "path cannot point inside .config/dotler".to_string(),
            });
        }
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

/// Recursively removes empty parent directories starting from `file_path.parent()` upward,
/// stopping immediately upon reaching `stop_at_root`, encountering a non-empty directory,
/// or encountering a symbolic link or filesystem error.
pub fn prune_empty_parent_dirs(file_path: &Path, stop_at_root: &Path) {
    let stop_root = normalize_lexical_path(stop_at_root);
    if stop_root.as_os_str().is_empty() {
        return;
    }
    let normalized_file = normalize_lexical_path(file_path);
    let Some(parent) = normalized_file.parent() else {
        return;
    };
    let Ok(rel_parent) = parent.strip_prefix(&stop_root) else {
        return;
    };
    if rel_parent.as_os_str().is_empty() {
        return;
    }

    // Verify no intermediate ancestor below `stop_root` is a symbolic link before pruning upward.
    let mut probe = stop_root.clone();
    for comp in rel_parent.components() {
        probe.push(comp);
        if is_symlink(&probe) {
            return;
        }
    }

    let mut current = Some(parent);
    while let Some(dir) = current {
        if dir == stop_root || !dir.starts_with(&stop_root) {
            break;
        }
        let Ok(meta) = fs::symlink_metadata(dir) else {
            break;
        };
        let file_type = meta.file_type();
        if file_type.is_symlink() || !file_type.is_dir() {
            break;
        }
        if fs::remove_dir(dir).is_err() {
            break;
        }
        current = dir.parent();
    }
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

pub(crate) fn normalize_lexical_path(path: &Path) -> PathBuf {
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

pub(crate) fn resolve_with_existing_ancestors(path: &Path) -> PathBuf {
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

fn check_within_boundary_and_unprotected(
    original_path: &Path,
    resolved_path: &Path,
    canonical_boundary: &Path,
    canonical_dotler_dir: &Path,
    boundary_label: &str,
) -> Result<(), ConfigError> {
    if !resolved_path.starts_with(canonical_boundary) {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: format!(
                "path target '{}' escapes {boundary_label}",
                resolved_path.display()
            ),
        });
    }
    if resolved_path == canonical_dotler_dir || resolved_path.starts_with(canonical_dotler_dir) {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: "path target cannot point inside ~/.config/dotler".to_string(),
        });
    }
    if let Ok(rel) = resolved_path.strip_prefix(canonical_boundary)
        && rel.components().any(|c| c.as_os_str() == ".git")
    {
        return Err(ConfigError::HardBlockedPath {
            path: original_path.display().to_string(),
            reason: "path target cannot point inside a .git directory".to_string(),
        });
    }
    Ok(())
}

fn resolve_boundary_and_dotler(
    boundary_dir: &Path,
    home_dir: &Path,
) -> Result<(PathBuf, PathBuf, &'static str), ConfigError> {
    let canonical_boundary = fs::canonicalize(boundary_dir)
        .unwrap_or_else(|_| resolve_with_existing_ancestors(boundary_dir));
    let canonical_home =
        fs::canonicalize(home_dir).unwrap_or_else(|_| resolve_with_existing_ancestors(home_dir));
    let canonical_dotler_dir = canonical_home.join(".config").join("dotler");

    if canonical_boundary == canonical_dotler_dir
        || canonical_boundary.starts_with(&canonical_dotler_dir)
    {
        return Err(ConfigError::HardBlockedPath {
            path: boundary_dir.display().to_string(),
            reason: "boundary directory cannot point inside ~/.config/dotler".to_string(),
        });
    }
    if canonical_boundary
        .components()
        .any(|c| c.as_os_str() == ".git")
    {
        return Err(ConfigError::HardBlockedPath {
            path: boundary_dir.display().to_string(),
            reason: "boundary directory cannot point inside a .git directory".to_string(),
        });
    }

    let label = if canonical_boundary == canonical_home {
        "home directory ('~')"
    } else {
        "current directory ('.')"
    };
    Ok((canonical_boundary, canonical_dotler_dir, label))
}

/// Validates that an OS target directory (and its existing ancestors) stays within `boundary_dir`
/// and outside protected directories (`~/.config/dotler`, `.git`).
pub fn validate_os_dir_path_with_home(
    target_dir: &Path,
    boundary_dir: &Path,
    home_dir: &Path,
) -> Result<(), ConfigError> {
    let (canonical_boundary, canonical_dotler_dir, boundary_label) =
        resolve_boundary_and_dotler(boundary_dir, home_dir)?;

    let resolved_target = resolve_with_existing_ancestors(target_dir);
    check_within_boundary_and_unprotected(
        target_dir,
        &resolved_target,
        &canonical_boundary,
        &canonical_dotler_dir,
        boundary_label,
    )?;

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
            check_within_boundary_and_unprotected(
                target_dir,
                &canonical_curr,
                &canonical_boundary,
                &canonical_dotler_dir,
                boundary_label,
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

/// Validates that an OS target directory (and its existing ancestors) stays within `home_dir`.
pub fn validate_os_dir_path(target_dir: &Path, home_dir: &Path) -> Result<(), ConfigError> {
    validate_os_dir_path_with_home(target_dir, home_dir, home_dir)
}

/// Validates that an OS target file path (and its ancestors) does not escape `boundary_dir`
/// or enter protected directories (`~/.config/dotler`, `.git`) via symbolic links.
pub fn validate_os_target_path_with_home(
    target_os_path: &Path,
    boundary_dir: &Path,
    home_dir: &Path,
) -> Result<(), ConfigError> {
    let (canonical_boundary, canonical_dotler_dir, boundary_label) =
        resolve_boundary_and_dotler(boundary_dir, home_dir)?;

    if let Some(parent) = target_os_path.parent() {
        validate_os_dir_path_with_home(parent, boundary_dir, home_dir)?;
    }

    if is_symlink(target_os_path) {
        if target_os_path.exists() {
            let canonical_target = fs::canonicalize(target_os_path)?;
            check_within_boundary_and_unprotected(
                target_os_path,
                &canonical_target,
                &canonical_boundary,
                &canonical_dotler_dir,
                boundary_label,
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
            let parent = target_os_path.parent().unwrap_or(boundary_dir);
            let canonical_parent = fs::canonicalize(parent)
                .unwrap_or_else(|_| resolve_with_existing_ancestors(parent));
            let joined = if link_target.is_absolute() {
                link_target
            } else {
                canonical_parent.join(link_target)
            };
            let resolved = resolve_with_existing_ancestors(&joined);
            check_within_boundary_and_unprotected(
                target_os_path,
                &resolved,
                &canonical_boundary,
                &canonical_dotler_dir,
                boundary_label,
            )?;
        }
    } else {
        let resolved = resolve_with_existing_ancestors(target_os_path);
        check_within_boundary_and_unprotected(
            target_os_path,
            &resolved,
            &canonical_boundary,
            &canonical_dotler_dir,
            boundary_label,
        )?;
    }

    Ok(())
}

/// Validates that an OS target file path (and its ancestors) does not escape `home_dir`
/// or enter protected directories via symbolic links.
pub fn validate_os_target_path(target_os_path: &Path, home_dir: &Path) -> Result<(), ConfigError> {
    validate_os_target_path_with_home(target_os_path, home_dir, home_dir)
}

/// Rejects target paths that overwrite `dotler.toml` or overlap any repository group storage
/// directory (`<repo>/<group>/`).
pub fn validate_repo_target_disjointness<'a>(
    repo_dir: &Path,
    group_names: impl IntoIterator<Item = &'a str>,
    target_path: &Path,
) -> Result<(), ConfigError> {
    let canon_repo =
        fs::canonicalize(repo_dir).unwrap_or_else(|_| resolve_with_existing_ancestors(repo_dir));
    let resolved_target = resolve_with_existing_ancestors(target_path);

    let manifest_path = canon_repo.join("dotler.toml");
    if resolved_target == manifest_path {
        return Err(ConfigError::HardBlockedPath {
            path: target_path.display().to_string(),
            reason: "target path cannot overwrite repository manifest 'dotler.toml'".to_string(),
        });
    }

    for group_name in group_names {
        let group_storage = canon_repo.join(group_name);
        if resolved_target == group_storage || resolved_target.starts_with(&group_storage) {
            return Err(ConfigError::HardBlockedPath {
                path: target_path.display().to_string(),
                reason: format!(
                    "target path overlaps repository group storage directory '{group_name}'; rename group '[{group_name}]' to avoid self-conflict"
                ),
            });
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
        assert!(validate_path_security(".").is_ok());
        assert!(validate_path_security("./").is_ok());
        assert!(validate_path_security("./config").is_ok());
        assert!(validate_path_security("././nested/app").is_ok());

        assert!(matches!(
            validate_path_security("/etc/app").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("relative/without/dot").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~/app/../secret").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("./../secret").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("~/app/$HOME").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
        assert!(matches!(
            validate_path_security("./$PWD").unwrap_err(),
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
        assert!(matches!(
            validate_path_security(".\\app\\conf").unwrap_err(),
            ConfigError::HardBlockedPath { .. }
        ));
    }

    #[test]
    fn test_path_security_checks_protects_internal_paths() {
        assert!(validate_path_security("~/.config/dotler").is_err());
        assert!(validate_path_security("~/.config/dotler/state.db").is_err());
        assert!(validate_path_security("./.config/dotler").is_err());
        assert!(validate_path_security("./.config/dotler/state.db").is_err());
        assert!(validate_path_security("././.config/dotler").is_err());
        assert!(validate_path_security("~/.git").is_err());
        assert!(validate_path_security("~/.git/hooks").is_err());
        assert!(validate_path_security("./.git").is_err());
        assert!(validate_path_security("./.git/hooks").is_err());
        assert!(validate_path_security("./sub/.git").is_err());

        // Allowed dotfiles that contain git as substring
        assert!(validate_path_security("~/.gitconfig").is_ok());
        assert!(validate_path_security("~/.gitignore").is_ok());
        assert!(validate_path_security("~/.github").is_ok());
        assert!(validate_path_security("./.gitconfig").is_ok());
        assert!(validate_path_security("./.gitignore").is_ok());
        assert!(validate_path_security("./.github").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn test_os_target_path_cwd_boundary_blocks_escape_to_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home_dir = tmp.path().join("home");
        let cwd = tmp.path().join("project");
        fs::create_dir_all(home_dir.join(".ssh")).unwrap();
        fs::create_dir_all(home_dir.join(".config/dotler")).unwrap();
        fs::create_dir_all(cwd.join("sub")).unwrap();

        let home_secret = home_dir.join(".ssh/id_rsa");
        fs::write(&home_secret, b"PRIVATE\n").unwrap();
        let in_cwd_real = cwd.join("sub/real.env");
        fs::write(&in_cwd_real, b"KEY=1\n").unwrap();

        // Symlink inside cwd pointing to another file inside cwd is allowed.
        let in_cwd_link = cwd.join("local_link.env");
        std::os::unix::fs::symlink(&in_cwd_real, &in_cwd_link).unwrap();
        assert!(validate_os_target_path_with_home(&in_cwd_link, &cwd, &home_dir).is_ok());

        // Symlink inside cwd pointing inside `home_dir` escapes `cwd` -> HardBlockedPath.
        let home_escape_link = cwd.join("home_escape.key");
        std::os::unix::fs::symlink(&home_secret, &home_escape_link).unwrap();
        assert!(matches!(
            validate_os_target_path_with_home(&home_escape_link, &cwd, &home_dir),
            Err(ConfigError::HardBlockedPath { .. })
        ));

        // Broken symlink inside cwd pointing outside cwd -> HardBlockedPath.
        let broken_escape = cwd.join("broken_escape");
        std::os::unix::fs::symlink("../outside.env", &broken_escape).unwrap();
        assert!(matches!(
            validate_os_target_path_with_home(&broken_escape, &cwd, &home_dir),
            Err(ConfigError::HardBlockedPath { .. })
        ));

        // Target inside .git or ~/.config/dotler when cwd == home_dir -> HardBlockedPath.
        assert!(matches!(
            validate_os_target_path_with_home(&cwd.join(".git/config"), &cwd, &home_dir),
            Err(ConfigError::HardBlockedPath { .. })
        ));
        assert!(matches!(
            validate_os_target_path_with_home(
                &home_dir.join(".config/dotler/state.db"),
                &home_dir,
                &home_dir
            ),
            Err(ConfigError::HardBlockedPath { .. })
        ));
    }

    #[test]
    fn test_validate_repo_target_disjointness() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("project");
        fs::create_dir_all(&repo_dir).unwrap();
        let groups = ["secrets", "app"];

        // Root project directory itself (`.`) and non-group subdirs are allowed.
        assert!(validate_repo_target_disjointness(&repo_dir, groups, &repo_dir).is_ok());
        assert!(
            validate_repo_target_disjointness(&repo_dir, groups, &repo_dir.join("config")).is_ok()
        );
        assert!(
            validate_repo_target_disjointness(&repo_dir, groups, &repo_dir.join(".env")).is_ok()
        );

        // `dotler.toml` and `<repo>/<group>/...` overlaps are blocked.
        assert!(matches!(
            validate_repo_target_disjointness(&repo_dir, groups, &repo_dir.join("dotler.toml")),
            Err(ConfigError::HardBlockedPath { .. })
        ));
        assert!(matches!(
            validate_repo_target_disjointness(&repo_dir, groups, &repo_dir.join("secrets")),
            Err(ConfigError::HardBlockedPath { .. })
        ));
        assert!(matches!(
            validate_repo_target_disjointness(&repo_dir, groups, &repo_dir.join("secrets/api.key")),
            Err(ConfigError::HardBlockedPath { .. })
        ));
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

    #[test]
    fn test_prune_empty_parent_dirs_removes_nested_empty_dirs_and_stops_at_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("group_root");
        let deep_file = root.join("a/b/c/file.txt");
        fs::create_dir_all(deep_file.parent().unwrap()).unwrap();
        fs::write(&deep_file, b"data").unwrap();
        fs::remove_file(&deep_file).unwrap();

        prune_empty_parent_dirs(&deep_file, &root);

        assert!(!root.join("a/b/c").exists());
        assert!(!root.join("a/b").exists());
        assert!(!root.join("a").exists());
        assert!(root.is_dir());
    }

    #[test]
    fn test_prune_empty_parent_dirs_stops_at_non_empty_ancestor_and_ignores_outside_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("group_root");
        let sibling = root.join("a/sibling.txt");
        let deep_file = root.join("a/b/c/file.txt");
        fs::create_dir_all(deep_file.parent().unwrap()).unwrap();
        fs::write(&sibling, b"keep").unwrap();
        fs::write(&deep_file, b"remove").unwrap();
        fs::remove_file(&deep_file).unwrap();

        prune_empty_parent_dirs(&deep_file, &root);

        assert!(!root.join("a/b/c").exists());
        assert!(!root.join("a/b").exists());
        assert!(root.join("a").is_dir());
        assert!(sibling.is_file());

        let outside_file = tmp.path().join("outside/nested/file.txt");
        fs::create_dir_all(outside_file.parent().unwrap()).unwrap();
        fs::write(&outside_file, b"outside").unwrap();
        fs::remove_file(&outside_file).unwrap();

        prune_empty_parent_dirs(&outside_file, &root);
        assert!(tmp.path().join("outside/nested").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn test_prune_empty_parent_dirs_never_removes_symlink_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("group_root");
        let target_dir = tmp.path().join("real_empty_target");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&target_dir).unwrap();

        let link_dir = root.join("linked");
        std::os::unix::fs::symlink(&target_dir, &link_dir).unwrap();
        let file_inside_link = link_dir.join("file.txt");

        prune_empty_parent_dirs(&file_inside_link, &root);

        assert!(is_symlink(&link_dir));
        assert!(target_dir.is_dir());
        assert!(root.is_dir());

        let nested_under_link = link_dir.join("sub");
        fs::create_dir_all(&nested_under_link).unwrap();
        let nested_file = nested_under_link.join("file.txt");
        prune_empty_parent_dirs(&nested_file, &root);

        assert!(nested_under_link.is_dir());
        assert!(is_symlink(&link_dir));
    }
}
