use std::fs;
use std::io::Write;
use tempfile::tempdir;

use base64::prelude::*;
use dotler::crypto::{
    EncryptedFile, RecoveryMnemonic, VaultError, VaultKey, VaultSlot, XCHACHA_NONCE_LEN,
    change_password, init_vault, recover_vault,
};
use secrecy::{ExposeSecret, SecretString};

// ---------------------------------------------------------------------------
// Suite 1: Tampering Attacks
// ---------------------------------------------------------------------------

#[test]
fn test_tamper_ciphertext_single_bit_flip_at_every_key_boundary() {
    let vault_key = VaultKey::generate().expect("vault key generation should succeed");
    let plaintext = b"CRITICAL_DATABASE_CREDENTIAL_ENCRYPTED_PAYLOAD_1234567890";
    let original_enc = vault_key
        .encrypt_file(plaintext)
        .expect("encryption should succeed");

    let ct_len = original_enc.ciphertext.len();
    assert!(ct_len >= 16);

    // Test flipping 1 bit at critical boundary positions:
    // 1. Index 0 (start of ciphertext payload)
    // 2. Index ct_len / 2 (middle of ciphertext)
    // 3. Index ct_len - 17 (last payload byte before 16-byte Poly1305 MAC tag)
    // 4. Index ct_len - 16 (first byte of 16-byte Poly1305 MAC tag)
    // 5. Index ct_len - 1 (last byte of 16-byte Poly1305 MAC tag)
    let probe_indices = vec![0, ct_len / 2, ct_len - 17, ct_len - 16, ct_len - 1];

    for idx in probe_indices {
        for bit_shift in [0, 1, 4, 7] {
            let mut tampered = original_enc.clone();
            tampered.ciphertext[idx] ^= 1 << bit_shift;

            let result = vault_key.decrypt_file(&tampered);
            match result {
                Err(VaultError::DecryptionFailed(_)) => {
                    assert_eq!(
                        VaultError::DecryptionFailed("".into()).exit_code(),
                        4,
                        "exit code for DecryptionFailed must be 4"
                    );
                }
                Err(e) => panic!(
                    "Expected DecryptionFailed for bit flip at index {} shift {}, got err: {:?}",
                    idx, bit_shift, e
                ),
                Ok(_) => panic!(
                    "Decryption unexpectedly succeeded for bit flip at index {} shift {}",
                    idx, bit_shift
                ),
            }
        }
    }
}

#[test]
fn test_tamper_ciphertext_multi_bit_flips() {
    let vault_key = VaultKey::generate().unwrap();
    let plaintext = b"MULTI_BIT_CORRUPTION_TEST_PAYLOAD";
    let original_enc = vault_key.encrypt_file(plaintext).unwrap();

    let mut tampered = original_enc.clone();
    // Invert all bits in first 4 bytes of ciphertext
    for i in 0..4 {
        tampered.ciphertext[i] ^= 0xFF;
    }

    let result = vault_key.decrypt_file(&tampered);
    assert!(
        matches!(result, Err(VaultError::DecryptionFailed(_))),
        "multi-bit corruption must fail decryption"
    );
}

#[test]
fn test_tamper_nonce_all_bit_positions() {
    let vault_key = VaultKey::generate().unwrap();
    let plaintext = b"NONCE_TAMPER_PROTECTION_PAYLOAD";
    let original_enc = vault_key.encrypt_file(plaintext).unwrap();

    // Verify each byte of the 24-byte XChaCha20 nonce is authenticated by Poly1305
    for byte_idx in 0..XCHACHA_NONCE_LEN {
        let mut tampered = original_enc.clone();
        tampered.nonce[byte_idx] ^= 0x01;

        let result = vault_key.decrypt_file(&tampered);
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed(_))),
            "nonce corruption at byte {} must fail decryption with DecryptionFailed",
            byte_idx
        );
    }

    // Test extreme nonce corruptions: all zeros and all ones
    let mut zero_nonce = original_enc.clone();
    zero_nonce.nonce = [0u8; XCHACHA_NONCE_LEN];
    assert!(matches!(
        vault_key.decrypt_file(&zero_nonce),
        Err(VaultError::DecryptionFailed(_))
    ));

    let mut ff_nonce = original_enc.clone();
    ff_nonce.nonce = [0xFFu8; XCHACHA_NONCE_LEN];
    assert!(matches!(
        vault_key.decrypt_file(&ff_nonce),
        Err(VaultError::DecryptionFailed(_))
    ));
}

#[test]
fn test_tamper_vault_id_boundary_and_mismatch() {
    let vault_key = VaultKey::generate().unwrap();
    let plaintext = b"VAULT_ID_MISMATCH_VERIFICATION_PAYLOAD";
    let original_enc = vault_key.encrypt_file(plaintext).unwrap();

    // 1-bit flip in vault_id byte 0
    let mut tampered_0 = original_enc.clone();
    tampered_0.vault_id[0] ^= 0x01;
    let res_0 = vault_key.decrypt_file(&tampered_0);
    match res_0 {
        Err(VaultError::VaultIdMismatch { expected, actual }) => {
            assert_eq!(expected, vault_key.vault_id());
            assert_ne!(actual, expected);
        }
        Err(e) => panic!("expected VaultIdMismatch, got err: {:?}", e),
        Ok(_) => panic!("decryption unexpectedly succeeded on corrupted vault_id"),
    }

    // 1-bit flip in vault_id byte 7 (last byte of 8-byte ID)
    let mut tampered_7 = original_enc.clone();
    tampered_7.vault_id[7] ^= 0x80;
    let res_7 = vault_key.decrypt_file(&tampered_7);
    match res_7 {
        Err(VaultError::VaultIdMismatch { expected, actual }) => {
            assert_eq!(expected, vault_key.vault_id());
            assert_ne!(actual, expected);
        }
        Err(e) => panic!("expected VaultIdMismatch, got err: {:?}", e),
        Ok(_) => panic!("decryption unexpectedly succeeded on corrupted vault_id"),
    }

    // Mismatch exit code verification
    let mismatch_err = VaultError::VaultIdMismatch {
        expected: "a".into(),
        actual: "b".into(),
    };
    assert_eq!(mismatch_err.exit_code(), 4);
}

#[test]
fn test_tamper_poly1305_tag_truncation_and_mangling() {
    let vault_key = VaultKey::generate().unwrap();
    let plaintext = b"POLY1305_TAG_ATTACK_TEST";
    let original_enc = vault_key.encrypt_file(plaintext).unwrap();
    let ct_len = original_enc.ciphertext.len();

    // Mangle each of the 16 bytes of the Poly1305 tag individually
    for tag_offset in 0..16 {
        let tag_idx = ct_len - 16 + tag_offset;
        let mut tampered = original_enc.clone();
        tampered.ciphertext[tag_idx] ^= 0x5A;

        let result = vault_key.decrypt_file(&tampered);
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed(_))),
            "Poly1305 tag mangling at offset {} must fail decryption",
            tag_offset
        );
    }

    // Truncate ciphertext: remove bytes from tag
    for truncate_bytes in [1, 8, 15, 16] {
        let mut truncated = original_enc.clone();
        truncated
            .ciphertext
            .truncate(ct_len.saturating_sub(truncate_bytes));

        let result = vault_key.decrypt_file(&truncated);
        assert!(
            matches!(result, Err(VaultError::DecryptionFailed(_))),
            "truncated ciphertext by {} bytes must fail decryption",
            truncate_bytes
        );
    }

    // Truncated raw binary file (< 48 bytes) must fail from_bytes parsing
    let serialized = original_enc.to_bytes();
    for len in [0, 1, 31, 32, 47] {
        let truncated_raw = &serialized[..len.min(serialized.len())];
        assert!(
            matches!(
                EncryptedFile::from_bytes(truncated_raw),
                Err(VaultError::InvalidEncFormat(_))
            ),
            "raw encrypted file of length {} must be rejected as InvalidEncFormat",
            len
        );
    }
}

#[test]
fn test_tamper_verify_before_write_prevents_file_modification() {
    let dir = tempdir().unwrap();
    let target_path = dir.path().join("preexisting_config.conf");
    let original_content = b"ORIGINAL_CRITICAL_CONFIG_DO_NOT_CORRUPT";
    fs::write(&target_path, original_content).unwrap();

    let initial_meta = fs::metadata(&target_path).unwrap();
    let initial_modified = initial_meta.modified().unwrap();

    let vault_key = VaultKey::generate().unwrap();
    let mut tampered_enc = vault_key.encrypt_file(b"MALICIOUS_REPLACEMENT").unwrap();
    tampered_enc.ciphertext[0] ^= 0x01; // Corrupt ciphertext bit

    // Simulate "Verify-Before-Write" pattern:
    // Decrypt first. If Err, NEVER open or truncate the destination file!
    let decrypt_result = vault_key.decrypt_file(&tampered_enc);
    assert!(decrypt_result.is_err());

    if let Ok(decrypted) = decrypt_result {
        // This branch MUST NEVER execute
        let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&target_path)
            .unwrap();
        file.write_all(decrypted.expose_secret()).unwrap();
    }

    // Verify destination file is 100% pristine and untouched
    let after_bytes = fs::read(&target_path).unwrap();
    assert_eq!(after_bytes.as_slice(), original_content);

    let after_meta = fs::metadata(&target_path).unwrap();
    assert_eq!(after_meta.len(), original_content.len() as u64);
    assert_eq!(after_meta.modified().unwrap(), initial_modified);

    // Also verify non-existent target: no partial or temporary files left
    let non_existent = dir.path().join("should_never_exist.conf");
    let decrypt_result_2 = vault_key.decrypt_file(&tampered_enc);
    if let Ok(decrypted) = decrypt_result_2 {
        fs::write(&non_existent, decrypted.expose_secret()).unwrap();
    }
    assert!(!non_existent.exists());
}

// ---------------------------------------------------------------------------
// Suite 2: Binary Boundary Attacks
// ---------------------------------------------------------------------------

#[test]
fn test_binary_boundary_truncated_vault_slot() {
    // Valid slot is exactly 88 bytes
    let truncated_lengths = [0, 1, 15, 16, 24, 39, 40, 80, 87];

    for len in truncated_lengths {
        let bytes = vec![0x42u8; len];
        let res_bytes = VaultSlot::from_bytes(&bytes);
        assert!(
            matches!(res_bytes, Err(VaultError::InvalidSlotFormat(_))),
            "raw slot of length {} must be rejected as InvalidSlotFormat",
            len
        );

        let b64 = BASE64_STANDARD.encode(&bytes);
        let res_b64 = VaultSlot::from_base64(&b64);
        assert!(
            matches!(res_b64, Err(VaultError::InvalidSlotFormat(_))),
            "base64 slot of decoded length {} must be rejected as InvalidSlotFormat",
            len
        );
    }
}

#[test]
fn test_binary_boundary_oversized_vault_slot() {
    let oversized_lengths = [89, 90, 100, 128, 256, 1024];

    for len in oversized_lengths {
        let bytes = vec![0x42u8; len];
        let res_bytes = VaultSlot::from_bytes(&bytes);
        assert!(
            matches!(res_bytes, Err(VaultError::InvalidSlotFormat(_))),
            "oversized slot of length {} must be rejected as InvalidSlotFormat",
            len
        );

        let b64 = BASE64_STANDARD.encode(&bytes);
        let res_b64 = VaultSlot::from_base64(&b64);
        assert!(
            matches!(res_b64, Err(VaultError::InvalidSlotFormat(_))),
            "oversized base64 slot of decoded length {} must be rejected as InvalidSlotFormat",
            len
        );
    }
}

#[test]
fn test_binary_boundary_invalid_base64_strings() {
    let invalid_strings = [
        "",
        "   ",
        "\t\n",
        "!!!@@@###$$$%%%^^^&&&***",
        "???///___---",
        "abc def",
        "YWJj\0ZGVm",
        "not_valid_base64_chars!!",
        "A",
        "AB",
        "ABC",
        "====",
        "======",
    ];

    for invalid in invalid_strings {
        let res = VaultSlot::from_base64(invalid);
        assert!(
            matches!(res, Err(VaultError::InvalidSlotFormat(_))),
            "input {:?} must be rejected as InvalidSlotFormat",
            invalid
        );
    }
}

#[test]
fn test_binary_boundary_wrong_passphrase_unwraps() {
    let correct_pass = SecretString::new("correct-horse-battery-staple".to_string());
    let vault_key = VaultKey::generate().unwrap();
    let slot = VaultSlot::wrap(&correct_pass, &vault_key).unwrap();

    let wrong_passphrases = [
        "correct-horse-battery-staplf",  // 1 character different
        "Correct-horse-battery-staple",  // case mismatch
        "correct-horse-battery-staple ", // trailing space
        " correct-horse-battery-staple", // leading space
        "",                              // empty
        "   ",                           // whitespace only
        "random_completely_different_passphrase_12345",
        "correct-horse-battery-staple\0extra", // embedded null
    ];

    for wrong in wrong_passphrases {
        let wrong_secret = SecretString::new(wrong.to_string());
        let res = slot.unwrap(&wrong_secret, Some(&vault_key.vault_id()));
        match res {
            Err(VaultError::InvalidSecret) => {
                assert_eq!(
                    VaultError::InvalidSecret.exit_code(),
                    4,
                    "InvalidSecret must have exit code 4"
                );
            }
            other => panic!(
                "expected InvalidSecret for wrong passphrase, got: {:?}",
                other.is_err()
            ),
        }
    }
}

#[test]
fn test_binary_boundary_slot_internal_corruption() {
    let pass = SecretString::new("boundary-test-password".to_string());
    let vault_key = VaultKey::generate().unwrap();
    let original_slot = VaultSlot::wrap(&pass, &vault_key).unwrap();

    // Corrupt salt
    let mut corrupt_salt = original_slot.clone();
    corrupt_salt.salt[0] ^= 0x01;
    assert!(matches!(
        corrupt_salt.unwrap(&pass, Some(&vault_key.vault_id())),
        Err(VaultError::InvalidSecret)
    ));

    // Corrupt nonce
    let mut corrupt_nonce = original_slot.clone();
    corrupt_nonce.nonce[0] ^= 0x01;
    assert!(matches!(
        corrupt_nonce.unwrap(&pass, Some(&vault_key.vault_id())),
        Err(VaultError::InvalidSecret)
    ));

    // Corrupt ciphertext body
    let mut corrupt_ct = original_slot.clone();
    corrupt_ct.ciphertext[0] ^= 0x01;
    assert!(matches!(
        corrupt_ct.unwrap(&pass, Some(&vault_key.vault_id())),
        Err(VaultError::InvalidSecret)
    ));

    // Corrupt Poly1305 MAC tag in slot ciphertext
    let mut corrupt_tag = original_slot.clone();
    corrupt_tag.ciphertext[47] ^= 0x01;
    assert!(matches!(
        corrupt_tag.unwrap(&pass, Some(&vault_key.vault_id())),
        Err(VaultError::InvalidSecret)
    ));

    // Expected vault_id mismatch when password is valid
    let mismatch_res = original_slot.unwrap(&pass, Some("0000000000000000"));
    assert!(matches!(
        mismatch_res,
        Err(VaultError::VaultIdMismatch { .. })
    ));
}

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
