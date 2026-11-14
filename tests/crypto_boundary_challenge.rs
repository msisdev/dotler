use std::fs;
use std::io::Write;
use tempfile::tempdir;

use dotler::crypto::{EncryptedFile, VaultError, VaultKey, VaultSlot, XCHACHA_NONCE_LEN};
use dotler::crypto::{ExposeSecret, SecretString};

fn test_b64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

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

        let b64 = test_b64_encode(&bytes);
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

        let b64 = test_b64_encode(&bytes);
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
