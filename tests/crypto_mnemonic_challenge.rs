use dotler::crypto::{
    EncryptedFile, RecoveryMnemonic, VaultError, VaultKey, VaultSlot, change_password, init_vault,
    recover_vault,
};
use dotler::crypto::{ExposeSecret, SecretString};

// ---------------------------------------------------------------------------
// Suite 3: BIP-39 Mnemonic Attacks
// ---------------------------------------------------------------------------

#[test]
fn test_mnemonic_invalid_word_count() {
    // Valid 12-word BIP-39 phrase with valid checksum
    let valid_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(RecoveryMnemonic::validate(valid_12).is_ok());

    let words: Vec<&str> = valid_12.split_whitespace().collect();

    // Test 0 words
    assert!(matches!(
        RecoveryMnemonic::validate(""),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Test 1 word
    assert!(matches!(
        RecoveryMnemonic::validate("abandon"),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Test 11 words (missing 1 word)
    let phrase_11 = words[..11].join(" ");
    assert!(matches!(
        RecoveryMnemonic::validate(&phrase_11),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Test 13 words (1 extra word)
    let mut words_13 = words.clone();
    words_13.push("about");
    let phrase_13 = words_13.join(" ");
    assert!(matches!(
        RecoveryMnemonic::validate(&phrase_13),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Test 15 words (valid BIP-39 160-bit mnemonic, but rejected by Dotler 12-word rule)
    let valid_15 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    assert!(matches!(
        RecoveryMnemonic::validate(valid_15),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Test 18 words (valid BIP-39 192-bit mnemonic)
    let valid_18 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent";
    assert!(matches!(
        RecoveryMnemonic::validate(valid_18),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Test 24 words (valid BIP-39 256-bit mnemonic)
    let valid_24 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    assert!(matches!(
        RecoveryMnemonic::validate(valid_24),
        Err(VaultError::InvalidMnemonic(_))
    ));
}

#[test]
fn test_mnemonic_words_outside_bip39_wordlist() {
    let base_valid = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let words: Vec<&str> = base_valid.split_whitespace().collect();

    // Word 0 outside wordlist
    let mut words_corrupt_0 = words.clone();
    words_corrupt_0[0] = "nonexistentwordxyz";
    assert!(matches!(
        RecoveryMnemonic::validate(&words_corrupt_0.join(" ")),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Word 11 outside wordlist
    let mut words_corrupt_11 = words.clone();
    words_corrupt_11[11] = "invalidwordfoo";
    assert!(matches!(
        RecoveryMnemonic::validate(&words_corrupt_11.join(" ")),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Non-English word (e.g. French word not in BIP-39 English wordlist)
    let mut words_foreign = words.clone();
    words_foreign[5] = "bonjour";
    assert!(matches!(
        RecoveryMnemonic::validate(&words_foreign.join(" ")),
        Err(VaultError::InvalidMnemonic(_))
    ));

    // Numbers and punctuation
    let mut words_symbols = words.clone();
    words_symbols[3] = "12345";
    assert!(matches!(
        RecoveryMnemonic::validate(&words_symbols.join(" ")),
        Err(VaultError::InvalidMnemonic(_))
    ));
}

#[test]
fn test_mnemonic_checksum_corruption() {
    // Valid 12-word mnemonic
    let valid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(RecoveryMnemonic::validate(valid_phrase).is_ok());

    let words: Vec<&str> = valid_phrase.split_whitespace().collect();

    // Swapping word 0 and word 11 produces invalid checksum
    let mut swapped = words.clone();
    swapped.swap(0, 11);
    let swapped_phrase = swapped.join(" ");
    assert!(
        matches!(
            RecoveryMnemonic::validate(&swapped_phrase),
            Err(VaultError::InvalidMnemonic(_))
        ),
        "swapped words must fail checksum validation"
    );

    // 12 times "abandon" has an invalid checksum
    let all_abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
    assert!(
        matches!(
            RecoveryMnemonic::validate(all_abandon),
            Err(VaultError::InvalidMnemonic(_))
        ),
        "12 identical 'abandon' words must fail checksum validation"
    );

    // Valid word replaced with another valid word that breaks checksum
    let mut bad_checksum = words.clone();
    bad_checksum[11] = "zoo"; // "zoo" is in wordlist, but does not match checksum
    let bad_checksum_phrase = bad_checksum.join(" ");
    assert!(
        matches!(
            RecoveryMnemonic::validate(&bad_checksum_phrase),
            Err(VaultError::InvalidMnemonic(_))
        ),
        "valid word with wrong checksum must fail validation"
    );
}

#[test]
fn test_mnemonic_single_use_auto_revocation_stress_chain() {
    let initial_pass = SecretString::new("initial-pass-1".to_string());
    let (config, initial_key, mnemonic_1) = init_vault(&initial_pass).unwrap();

    let secret_payload = b"SECRET_KEY_FOR_REVOCATION_CHAIN_TEST";
    let encrypted_file = initial_key.encrypt_file(secret_payload).unwrap();
    let enc_bytes = encrypted_file.to_bytes();

    // Chain 1: Recover with Mnemonic 1 -> produces Mnemonic 2
    let pass_2 = SecretString::new("second-pass-2".to_string());
    let (config_2, mnemonic_2) =
        recover_vault(&config, &mnemonic_1.0, &pass_2).expect("recovery 1 should succeed");

    assert_eq!(config_2.vault_id, config.vault_id);
    assert_ne!(mnemonic_1.phrase(), mnemonic_2.phrase());
    assert_ne!(config_2.recovery_slot, config.recovery_slot);

    // Mnemonic 1 MUST be permanently revoked immediately
    let failed_recover_1 = recover_vault(
        &config_2,
        &mnemonic_1.0,
        &SecretString::new("attacker-pass".to_string()),
    );
    assert!(
        matches!(failed_recover_1, Err(VaultError::InvalidSecret)),
        "revoked mnemonic 1 must be rejected with InvalidSecret"
    );

    // Chain 2: Recover with Mnemonic 2 -> produces Mnemonic 3
    let pass_3 = SecretString::new("third-pass-3".to_string());
    let (config_3, mnemonic_3) =
        recover_vault(&config_2, &mnemonic_2.0, &pass_3).expect("recovery 2 should succeed");

    // Both Mnemonic 1 and Mnemonic 2 MUST fail against config_3
    let failed_recover_m1_on_c3 = recover_vault(
        &config_3,
        &mnemonic_1.0,
        &SecretString::new("attacker-pass".to_string()),
    );
    assert!(matches!(
        failed_recover_m1_on_c3,
        Err(VaultError::InvalidSecret)
    ));

    let failed_recover_m2_on_c3 = recover_vault(
        &config_3,
        &mnemonic_2.0,
        &SecretString::new("attacker-pass".to_string()),
    );
    assert!(matches!(
        failed_recover_m2_on_c3,
        Err(VaultError::InvalidSecret)
    ));

    // Chain 3: Recover with Mnemonic 3 -> produces Mnemonic 4
    let pass_4 = SecretString::new("fourth-pass-4".to_string());
    let (config_4, _mnemonic_4) =
        recover_vault(&config_3, &mnemonic_3.0, &pass_4).expect("recovery 3 should succeed");

    // All old mnemonics (M1, M2, M3) fail against config_4
    for (idx, m) in [&mnemonic_1, &mnemonic_2, &mnemonic_3].iter().enumerate() {
        let res = recover_vault(
            &config_4,
            &m.0,
            &SecretString::new("attacker-pass".to_string()),
        );
        assert!(
            matches!(res, Err(VaultError::InvalidSecret)),
            "Mnemonic {} must fail against config_4",
            idx + 1
        );
    }

    // Only active Mnemonic 4 and pass_4 can unlock
    let pass_slot = VaultSlot::from_base64(&config_4.password_slot).unwrap();
    let recovered_key = pass_slot
        .unwrap(&pass_4, Some(&config_4.vault_id))
        .expect("pass_4 must unwrap key");
    assert_eq!(recovered_key.expose(), initial_key.expose());

    // Verify original encrypted dotfile is still decryptable by recovered key
    let parsed_enc = EncryptedFile::from_bytes(&enc_bytes).unwrap();
    let decrypted = recovered_key.decrypt_file(&parsed_enc).unwrap();
    assert_eq!(decrypted.expose_secret().as_slice(), secret_payload);
}

#[test]
fn test_tamper_sub_tag_ciphertext_direct_struct_no_panic() {
    let vault_key = VaultKey::generate().unwrap();

    // Construct EncryptedFile directly with ciphertext shorter than 16 bytes
    for sub_len in 0..16 {
        let direct_enc = EncryptedFile {
            vault_id: vault_key.vault_id_bytes(),
            nonce: [0u8; 24],
            ciphertext: vec![0x42u8; sub_len],
        };

        let result = vault_key.decrypt_file(&direct_enc);
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed(_))),
            "sub-tag length {} must return DecryptionFailed without panicking",
            sub_len
        );
    }
}

#[test]
fn test_mnemonic_whitespace_and_newline_boundary() {
    let initial_pass = SecretString::new("initial-pass".to_string());
    let (config, initial_key, mnemonic) = init_vault(&initial_pass).unwrap();

    // BIP-39 parser in validate accepts whitespace, and recover_vault normalizes
    // whitespace to single-spaced canonical form prior to Argon2id KEK derivation.
    let phrase_with_newline = format!("{}\n", mnemonic.phrase());
    assert!(
        RecoveryMnemonic::validate(&phrase_with_newline).is_ok(),
        "validate trims whitespace per BIP-39 spec"
    );

    // Normalized phrase with trailing newline successfully un-wraps slot and recovers vault
    let res_newline = recover_vault(
        &config,
        &SecretString::new(phrase_with_newline),
        &SecretString::new("new-pass".to_string()),
    );
    assert!(
        res_newline.is_ok(),
        "normalized trailing newline must successfully recover vault"
    );
    let (new_config, _new_m) = res_newline.unwrap();
    let pass_slot = VaultSlot::from_base64(&new_config.password_slot).unwrap();
    let key = pass_slot
        .unwrap(
            &SecretString::new("new-pass".to_string()),
            Some(&config.vault_id),
        )
        .unwrap();
    assert_eq!(key.expose(), initial_key.expose());
}

#[test]
fn test_lifecycle_slot_corruption_resistance() {
    let initial_pass = SecretString::new("lifecycle-pass".to_string());
    let (config, _, mnemonic) = init_vault(&initial_pass).unwrap();

    // 1. change_password with corrupted password_slot in config
    let mut bad_config = config.clone();
    bad_config.password_slot = "A".repeat(116); // Invalid base64 or length
    let res_change_corrupt = change_password(
        &bad_config,
        &initial_pass,
        &SecretString::new("new-pass".to_string()),
    );
    assert!(matches!(
        res_change_corrupt,
        Err(VaultError::InvalidSlotFormat(_))
    ));

    // 2. recover_vault with corrupted recovery_slot in config
    let mut bad_rec_config = config.clone();
    bad_rec_config.recovery_slot = "invalid_base64_payload!".to_string();
    let res_rec_corrupt = recover_vault(
        &bad_rec_config,
        &mnemonic.0,
        &SecretString::new("new-pass".to_string()),
    );
    assert!(matches!(
        res_rec_corrupt,
        Err(VaultError::InvalidSlotFormat(_))
    ));

    // 3. Vault ID mismatch in config during change_password
    let mut mismatch_config = config.clone();
    mismatch_config.vault_id = "0123456789abcdef".to_string();
    let res_mismatch = change_password(
        &mismatch_config,
        &initial_pass,
        &SecretString::new("new-pass".to_string()),
    );
    assert!(matches!(
        res_mismatch,
        Err(VaultError::VaultIdMismatch { .. })
    ));
}
