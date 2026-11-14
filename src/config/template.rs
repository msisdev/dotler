use std::path::Path;

use crate::config::ConfigError;


fn normalize_home_dir_str(home_dir: &Path) -> String {
    let s = home_dir.to_string_lossy().replace('\\', "/");
    if s == "/" {
        s
    } else {
        s.trim_end_matches('/').to_string()
    }
}

pub fn validate_template_text<'a>(content: &'a [u8], path_label: &str) -> Result<&'a str, ConfigError> {
    if content.contains(&0) {
        return Err(ConfigError::InvalidTemplateContent {
            path: path_label.to_string(),
            reason: "binary file (contains NUL byte) cannot use the 'tmpl' template attribute"
                .to_string(),
        });
    }
    std::str::from_utf8(content).map_err(|_| ConfigError::InvalidTemplateContent {
        path: path_label.to_string(),
        reason: "non-UTF-8 file cannot use the 'tmpl' template attribute".to_string(),
    })
}

fn replace_home_template_tokens(text: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open_idx) = rest.find("{{") {
        out.push_str(&rest[..open_idx]);
        let after_open = &rest[open_idx + 2..];
        if let Some(close_idx) = after_open.find("}}") {
            let inside = &after_open[..close_idx];
            if !inside.contains('\n') && !inside.contains('\r') && inside.trim() == "$HOME" {
                out.push_str(replacement);
                rest = &after_open[close_idx + 2..];
                continue;
            }
        }
        out.push_str("{{");
        rest = after_open;
    }
    out.push_str(rest);
    out
}

/// Renders `{{ $HOME }}` (and `{{$HOME}}`) tokens in a UTF-8 template payload into the
/// normalized OS home directory path. Rejects binary or non-UTF-8 content.
pub fn render_home_template(
    content: &[u8],
    home_dir: &Path,
    path_label: &str,
) -> Result<Vec<u8>, ConfigError> {
    let text = validate_template_text(content, path_label)?;
    let normalized_home = normalize_home_dir_str(home_dir);
    Ok(replace_home_template_tokens(text, &normalized_home).into_bytes())
}

/// Reverse-substitutes occurrences of the OS home directory path into canonical `{{ $HOME }}`
/// tokens for repository storage. Rejects binary or non-UTF-8 content.
pub fn unrender_home_template(
    content: &[u8],
    home_dir: &Path,
    path_label: &str,
) -> Result<Vec<u8>, ConfigError> {
    let text = validate_template_text(content, path_label)?;
    let mut normalized_text = replace_home_template_tokens(text, "{{ $HOME }}");
    let normalized_home = normalize_home_dir_str(home_dir);

    if !normalized_home.is_empty() && normalized_home != "/" {
        let raw_home = home_dir
            .to_string_lossy()
            .trim_end_matches(['/', '\\'])
            .to_string();
        if raw_home.contains('\\') {
            let escaped_backslash_home = raw_home.replace('\\', "\\\\");
            normalized_text = normalized_text.replace(&escaped_backslash_home, "{{ $HOME }}");
            normalized_text = normalized_text.replace(&raw_home, "{{ $HOME }}");
        }
        normalized_text = normalized_text.replace(&normalized_home, "{{ $HOME }}");
    }

    Ok(normalized_text.into_bytes())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_home_template_render_and_unrender_roundtrip() {
        let home = Path::new("/home/alice");
        let repo_template = b"excludesfile = {{ $HOME }}/.gitignore_global\ncompact = {{$HOME}}/bin\nliteral = {{ OTHER }}\n";
        let rendered = render_home_template(repo_template, home, ".gitconfig").unwrap();
        assert_eq!(
            std::str::from_utf8(&rendered).unwrap(),
            "excludesfile = /home/alice/.gitignore_global\ncompact = /home/alice/bin\nliteral = {{ OTHER }}\n"
        );

        let unrendered = unrender_home_template(&rendered, home, ".gitconfig").unwrap();
        assert_eq!(
            std::str::from_utf8(&unrendered).unwrap(),
            "excludesfile = {{ $HOME }}/.gitignore_global\ncompact = {{ $HOME }}/bin\nliteral = {{ OTHER }}\n"
        );

        // Windows backslash normalization
        let win_home = Path::new(r"C:\Users\alice");
        let win_rendered = render_home_template(repo_template, win_home, ".gitconfig").unwrap();
        assert_eq!(
            std::str::from_utf8(&win_rendered).unwrap(),
            "excludesfile = C:/Users/alice/.gitignore_global\ncompact = C:/Users/alice/bin\nliteral = {{ OTHER }}\n"
        );
        let win_os_mixed = b"a = C:/Users/alice/.cfg\nb = C:\\Users\\alice\\.cfg\nc = C:\\\\Users\\\\alice\\\\.cfg\n";
        let win_unrendered = unrender_home_template(win_os_mixed, win_home, ".gitconfig").unwrap();
        assert_eq!(
            std::str::from_utf8(&win_unrendered).unwrap(),
            "a = {{ $HOME }}/.cfg\nb = {{ $HOME }}\\.cfg\nc = {{ $HOME }}\\\\.cfg\n"
        );

        // Binary (NUL) or invalid UTF-8 rejected
        assert!(matches!(
            render_home_template(b"hello\0world", home, "bin.dat"),
            Err(ConfigError::InvalidTemplateContent { .. })
        ));
        assert!(matches!(
            unrender_home_template(&[0xff, 0xfe, 0xfd], home, "bad.utf8"),
            Err(ConfigError::InvalidTemplateContent { .. })
        ));
    }

}
