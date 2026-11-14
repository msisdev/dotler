use crate::config::ConfigError;
use crate::config::path_security::validate_rule_pattern;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMode {
    PlaintextInclude,
    EncryptedInclude,
    TemplateInclude,
    EncryptedTemplateInclude,
    Exclude,
}

impl SelectionMode {
    pub fn is_encrypted(self) -> bool {
        matches!(
            self,
            Self::EncryptedInclude | Self::EncryptedTemplateInclude
        )
    }

    pub fn is_template(self) -> bool {
        matches!(self, Self::TemplateInclude | Self::EncryptedTemplateInclude)
    }

    pub fn is_included(self) -> bool {
        !matches!(self, Self::Exclude)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRule {
    pub pattern: String,
    pub mode: SelectionMode,
    pub line_no: usize,
}

pub fn parse_selection_rules(files_content: &str) -> Result<Vec<SelectionRule>, ConfigError> {
    let mut rules = Vec::new();

    for (idx, line) in files_content.lines().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(stripped) = trimmed.strip_prefix('!') {
            let tokens: Vec<&str> = stripped.split_whitespace().collect();
            match tokens.len() {
                0 => {
                    return Err(ConfigError::InvalidSelectionAttribute {
                        attribute: trimmed.to_string(),
                        line_no,
                        hint: "Pattern cannot be empty after prefix '!'.".to_string(),
                    });
                }
                1 => {
                    let pattern = tokens[0].to_string();
                    validate_rule_pattern(&pattern)?;
                    rules.push(SelectionRule {
                        pattern,
                        mode: SelectionMode::Exclude,
                        line_no,
                    });
                }
                _ => {
                    let trailing = tokens[1..].join(" ");
                    let hint = if matches!(
                        tokens[1],
                        "enc" | "tmpl" | "encrypt" | "template" | "tmp" | "tpl"
                    ) {
                        "Exclusion prefix '!' already specifies selection mode; trailing attribute is redundant."
                            .to_string()
                    } else if tokens[1] == "encrpyt" || tokens[1].contains("encr") {
                        "Supported selection attributes are 'enc' and 'tmpl'. Check for typos."
                            .to_string()
                    } else {
                        "Expected single pattern after prefix '!' with no trailing attributes."
                            .to_string()
                    };
                    return Err(ConfigError::InvalidSelectionAttribute {
                        attribute: trailing,
                        line_no,
                        hint,
                    });
                }
            }
        } else {
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            match tokens.len() {
                1 => {
                    let pattern = tokens[0].to_string();
                    validate_rule_pattern(&pattern)?;
                    rules.push(SelectionRule {
                        pattern,
                        mode: SelectionMode::PlaintextInclude,
                        line_no,
                    });
                }
                2 | 3 => {
                    let pattern = tokens[0].to_string();
                    validate_rule_pattern(&pattern)?;
                    let mut has_enc = false;
                    let mut has_tmpl = false;
                    for &attr in &tokens[1..] {
                        match attr {
                            "enc" => {
                                if has_enc {
                                    return Err(ConfigError::InvalidSelectionAttribute {
                                        attribute: tokens[1..].join(" "),
                                        line_no,
                                        hint: "Duplicate 'enc' attribute on the same rule."
                                            .to_string(),
                                    });
                                }
                                has_enc = true;
                            }
                            "tmpl" => {
                                if has_tmpl {
                                    return Err(ConfigError::InvalidSelectionAttribute {
                                        attribute: tokens[1..].join(" "),
                                        line_no,
                                        hint: "Duplicate 'tmpl' attribute on the same rule."
                                            .to_string(),
                                    });
                                }
                                has_tmpl = true;
                            }
                            "encrypt" => {
                                return Err(ConfigError::InvalidSelectionAttribute {
                                    attribute: attr.to_string(),
                                    line_no,
                                    hint: "Use 'enc' instead of 'encrypt'. Supported selection attributes are 'enc' and 'tmpl'."
                                        .to_string(),
                                });
                            }
                            "template" | "tmp" | "tpl" => {
                                return Err(ConfigError::InvalidSelectionAttribute {
                                    attribute: attr.to_string(),
                                    line_no,
                                    hint: format!(
                                        "Use 'tmpl' instead of '{attr}'. Supported selection attributes are 'enc' and 'tmpl'."
                                    ),
                                });
                            }
                            _ => {
                                return Err(ConfigError::InvalidSelectionAttribute {
                                    attribute: attr.to_string(),
                                    line_no,
                                    hint: "Supported selection attributes are 'enc' and 'tmpl'. Check for typos."
                                        .to_string(),
                                });
                            }
                        }
                    }
                    let mode = match (has_enc, has_tmpl) {
                        (true, false) => SelectionMode::EncryptedInclude,
                        (false, true) => SelectionMode::TemplateInclude,
                        (true, true) => SelectionMode::EncryptedTemplateInclude,
                        (false, false) => SelectionMode::PlaintextInclude,
                    };
                    rules.push(SelectionRule {
                        pattern,
                        mode,
                        line_no,
                    });
                }
                _ => {
                    return Err(ConfigError::InvalidSelectionAttribute {
                        attribute: tokens[1..].join(" "),
                        line_no,
                        hint: "Expected format: '<pattern>', '<pattern> enc', '<pattern> tmpl', '<pattern> enc tmpl', or '!<pattern>'."
                            .to_string(),
                    });
                }
            }
        }
    }

    Ok(rules)
}

pub fn evaluate_selection(rules: &[SelectionRule], relative_path: &str) -> Option<SelectionMode> {
    let mut last_mode = None;

    for rule in rules {
        if matches_pattern(&rule.pattern, relative_path) {
            last_mode = Some(rule.mode);
        }
    }

    last_mode
}

pub fn rules_have_effective_encryption(rules: &[SelectionRule]) -> bool {
    rules.iter().any(|rule| {
        if !rule.mode.is_encrypted() {
            return false;
        }
        let trimmed = rule.pattern.trim_start_matches("./").trim_end_matches('/');
        let dir_prefix = format!("{trimmed}/");
        let is_dir_pattern = rule.pattern.ends_with('/')
            || (!trimmed.is_empty()
                && rules
                    .iter()
                    .any(|r| r.pattern.trim_start_matches("./").starts_with(&dir_prefix)));
        let probe = if is_dir_pattern {
            format!("{trimmed}/__probe__")
        } else {
            rule.pattern.clone()
        };
        evaluate_selection(rules, &probe).is_some_and(|m| m.is_encrypted())
    })
}

fn matches_pattern(pattern: &str, path: &str) -> bool {
    if pattern == path || pattern == "*" {
        return true;
    }

    let trimmed_pattern = pattern.trim_start_matches("./").trim_end_matches('/');
    let trimmed_path = path.trim_start_matches("./").trim_end_matches('/');

    if !trimmed_pattern.is_empty() {
        if trimmed_pattern == trimmed_path {
            return true;
        }
        if let Some(rest) = trimmed_path.strip_prefix(trimmed_pattern)
            && rest.starts_with('/')
        {
            return true;
        }
    }

    if let Ok(glob_pattern) = GlobPattern::new(pattern)
        && glob_pattern.matches(path)
    {
        return true;
    }

    if !trimmed_pattern.is_empty()
        && let Ok(glob_pattern) = GlobPattern::new(trimmed_pattern)
    {
        if glob_pattern.matches(trimmed_path) {
            return true;
        }
        for (idx, ch) in trimmed_path.char_indices() {
            if ch == '/' && glob_pattern.matches(&trimmed_path[..idx]) {
                return true;
            }
        }
    }

    false
}

#[derive(Clone, PartialEq, Eq)]
enum GlobToken {
    Char(char),
    AnyChar,
    AnySequence,
    AnyRecursiveSequence,
    AnyWithin(Vec<CharSpec>),
    AnyExcept(Vec<CharSpec>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CharSpec {
    Single(char),
    Range(char, char),
}

struct GlobPattern {
    tokens: Vec<GlobToken>,
}

impl GlobPattern {
    fn new(pattern: &str) -> Result<Self, ()> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut tokens = Vec::new();
        let mut i = 0;

        while i < chars.len() {
            match chars[i] {
                '?' => {
                    tokens.push(GlobToken::AnyChar);
                    i += 1;
                }
                '*' => {
                    let start = i;
                    while i < chars.len() && chars[i] == '*' {
                        i += 1;
                    }
                    let count = i - start;
                    if count > 2 {
                        return Err(());
                    } else if count == 2 {
                        if start == 0 || std::path::is_separator(chars[start - 1]) {
                            if i < chars.len() && std::path::is_separator(chars[i]) {
                                i += 1;
                            } else if i != chars.len() {
                                return Err(());
                            }
                        } else {
                            return Err(());
                        }
                        if !matches!(tokens.last(), Some(GlobToken::AnyRecursiveSequence)) {
                            tokens.push(GlobToken::AnyRecursiveSequence);
                        }
                    } else {
                        tokens.push(GlobToken::AnySequence);
                    }
                }
                '[' => {
                    if i + 4 <= chars.len() && chars[i + 1] == '!' {
                        if let Some(j) = chars[i + 3..].iter().position(|&c| c == ']') {
                            let specs = Self::parse_specs(&chars[i + 2..i + 3 + j]);
                            tokens.push(GlobToken::AnyExcept(specs));
                            i += j + 4;
                            continue;
                        }
                    } else if i + 3 <= chars.len()
                        && chars[i + 1] != '!'
                        && let Some(j) = chars[i + 2..].iter().position(|&c| c == ']')
                    {
                        let specs = Self::parse_specs(&chars[i + 1..i + 2 + j]);
                        tokens.push(GlobToken::AnyWithin(specs));
                        i += j + 3;
                        continue;
                    }
                    return Err(());
                }
                c => {
                    tokens.push(GlobToken::Char(c));
                    i += 1;
                }
            }
        }
        Ok(Self { tokens })
    }

    fn parse_specs(s: &[char]) -> Vec<CharSpec> {
        let mut specs = Vec::new();
        let mut i = 0;
        while i < s.len() {
            if i + 3 <= s.len() && s[i + 1] == '-' {
                specs.push(CharSpec::Range(s[i], s[i + 2]));
                i += 3;
            } else {
                specs.push(CharSpec::Single(s[i]));
                i += 1;
            }
        }
        specs
    }

    fn in_specs(specs: &[CharSpec], c: char) -> bool {
        specs.iter().any(|&spec| match spec {
            CharSpec::Single(sc) => c == sc,
            CharSpec::Range(start, end) => c >= start && c <= end,
        })
    }

    fn matches(&self, text: &str) -> bool {
        self.matches_from(true, text.chars(), 0) == 0
    }

    // Returns: 0 = Match, 1 = SubPatternDoesntMatch, 2 = EntirePatternDoesntMatch
    fn matches_from(
        &self,
        mut follows_separator: bool,
        mut file: std::str::Chars<'_>,
        token_idx: usize,
    ) -> u8 {
        for (ti, token) in self.tokens[token_idx..].iter().enumerate() {
            match token {
                GlobToken::AnySequence | GlobToken::AnyRecursiveSequence => {
                    let res =
                        self.matches_from(follows_separator, file.clone(), token_idx + ti + 1);
                    if res != 1 {
                        return res;
                    }
                    while let Some(c) = file.next() {
                        follows_separator = std::path::is_separator(c);
                        if matches!(token, GlobToken::AnyRecursiveSequence) && !follows_separator {
                            continue;
                        }
                        let sub =
                            self.matches_from(follows_separator, file.clone(), token_idx + ti + 1);
                        if sub != 1 {
                            return sub;
                        }
                    }
                }
                _ => {
                    let Some(c) = file.next() else {
                        return 2;
                    };
                    let matched = match token {
                        GlobToken::AnyChar => true,
                        GlobToken::AnyWithin(specs) => Self::in_specs(specs, c),
                        GlobToken::AnyExcept(specs) => !Self::in_specs(specs, c),
                        GlobToken::Char(c2) => c == *c2,
                        GlobToken::AnySequence | GlobToken::AnyRecursiveSequence => unreachable!(),
                    };
                    if !matched {
                        return 1;
                    }
                    follows_separator = std::path::is_separator(c);
                }
            }
        }
        if file.next().is_none() { 0 } else { 1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selection_rules_parsing_standard_syntax() {
        let content = "\n# Plaintext include\nconfig.json\n# Encrypted include\nid_ed25519 enc\n# Template include\n.gitconfig tmpl\n# Encrypted template include (both attribute orders)\ncredentials.toml enc tmpl\nsecrets.toml tmpl enc\n# Exclusion\n!temp*\n";
        let rules = parse_selection_rules(content).expect("rules should parse cleanly");
        let expected = [
            ("config.json", SelectionMode::PlaintextInclude, 3),
            ("id_ed25519", SelectionMode::EncryptedInclude, 5),
            (".gitconfig", SelectionMode::TemplateInclude, 7),
            (
                "credentials.toml",
                SelectionMode::EncryptedTemplateInclude,
                9,
            ),
            ("secrets.toml", SelectionMode::EncryptedTemplateInclude, 10),
            ("temp*", SelectionMode::Exclude, 12),
        ];
        assert_eq!(rules.len(), expected.len());
        for (rule, (pat, mode, line_no)) in rules.iter().zip(expected) {
            assert_eq!(
                rule,
                &SelectionRule {
                    pattern: pat.to_string(),
                    mode,
                    line_no
                }
            );
        }
    }

    #[test]
    fn test_selection_rules_invalid_attribute_error_with_line_number() {
        let content = "item1\nitem2\nitem3 encrpyt\nitem4";
        let err = parse_selection_rules(content).expect_err("misspelled attribute must fail");
        match err {
            ConfigError::InvalidSelectionAttribute {
                attribute,
                line_no,
                hint,
            } => {
                assert_eq!(attribute, "encrpyt");
                assert_eq!(line_no, 3);
                assert!(hint.contains("enc"));
                assert!(hint.contains("tmpl"));
            }
            other => panic!("expected InvalidSelectionAttribute, got {other:?}"),
        }

        for legacy in ["encrypt", "template", "tmp", "tpl"] {
            let line = format!("secret.txt {legacy}");
            let err = parse_selection_rules(&line).expect_err("legacy/alias attribute must fail");
            match err {
                ConfigError::InvalidSelectionAttribute {
                    attribute, hint, ..
                } => {
                    assert_eq!(attribute, legacy);
                    assert!(hint.contains("enc") && hint.contains("tmpl"));
                }
                other => panic!("expected InvalidSelectionAttribute, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_selection_rules_last_match_wins_precedence() {
        let content = r#"
* enc
*.pub
!known_hosts*
"#;
        let rules = parse_selection_rules(content).expect("rules should parse");

        let mode_key = evaluate_selection(&rules, "id_ed25519");
        assert_eq!(mode_key, Some(SelectionMode::EncryptedInclude));

        let mode_pub = evaluate_selection(&rules, "id_ed25519.pub");
        assert_eq!(mode_pub, Some(SelectionMode::PlaintextInclude));

        let mode_known = evaluate_selection(&rules, "known_hosts.old");
        assert_eq!(mode_known, Some(SelectionMode::Exclude));

        let mode_other = evaluate_selection(&rules, "other.file");
        assert_eq!(mode_other, Some(SelectionMode::EncryptedInclude));
    }

    #[test]
    fn test_directory_prefix_matching_without_wildcard_suffix() {
        let content = "\n*\n!cache\n!logs/\nsecrets enc\nplugins/ enc\n!plugins/disabled\n";
        let rules = parse_selection_rules(content).expect("rules should parse");
        for (path, expected) in [
            ("init.lua", Some(SelectionMode::PlaintextInclude)),
            ("cache/state.json", Some(SelectionMode::Exclude)),
            ("cache/sub/deep.bin", Some(SelectionMode::Exclude)),
            (
                "cache_other/state.json",
                Some(SelectionMode::PlaintextInclude),
            ),
            ("logs/app.log", Some(SelectionMode::Exclude)),
            ("logs/2026/11/debug.log", Some(SelectionMode::Exclude)),
            ("secrets/api_key.txt", Some(SelectionMode::EncryptedInclude)),
            (
                "secrets/nested/token",
                Some(SelectionMode::EncryptedInclude),
            ),
            (
                "plugins/telescope/init.lua",
                Some(SelectionMode::EncryptedInclude),
            ),
            ("plugins/disabled/init.lua", Some(SelectionMode::Exclude)),
        ] {
            assert_eq!(evaluate_selection(&rules, path), expected, "path: {path}");
        }
        assert!(rules_have_effective_encryption(&rules));
    }

    #[test]
    fn test_glob_pattern_wildcards_ranges_and_invalid_syntax() {
        assert!(GlobPattern::new("c?t").unwrap().matches("cat"));
        assert!(!GlobPattern::new("c?t").unwrap().matches("caat"));
        assert!(GlobPattern::new("k[!e]tteh").unwrap().matches("kitteh"));
        assert!(!GlobPattern::new("k[!e]tteh").unwrap().matches("ketteh"));
        assert!(
            GlobPattern::new("file[0-9].conf")
                .unwrap()
                .matches("file7.conf")
        );
        assert!(
            !GlobPattern::new("file[0-9].conf")
                .unwrap()
                .matches("filea.conf")
        );
        assert!(GlobPattern::new("**/init.lua").unwrap().matches("init.lua"));
        assert!(
            GlobPattern::new("**/init.lua")
                .unwrap()
                .matches("a/b/init.lua")
        );

        assert!(GlobPattern::new("***").is_err());
        assert!(GlobPattern::new("a**b").is_err());
        assert!(GlobPattern::new("[unclosed").is_err());
    }
}
