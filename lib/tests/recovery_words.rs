//! Recovery words as a person uses them: made on the device, written down, typed back in
//! (with typos, numbering, short forms), and turned into the keys that sign in.
use unlinkable_inference::seed::{self, Credential};

#[test]
fn standard_vectors_and_round_trip() {
    // BIP-39 test vectors (entropy -> words).
    assert_eq!(seed::words_from_entropy([0; 16]), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    assert_eq!(seed::words_from_entropy([0x7f; 16]), "legal winner thank year wave sausage worth useful legal winner thank yellow");
    assert_eq!(seed::words_from_entropy([0xff; 16]), "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong");
    for _ in 0..200 {
        let words = seed::new_recovery_words();
        assert_eq!(words.split(' ').count(), 12);
        assert_eq!(seed::normalize_words(&words).as_deref(), Some(words.as_str()));
    }
}

#[test]
fn typed_back_in() {
    let words = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    let typed = "1. Legal 2. winn 3. thank\n4. year, 5. wave 6. sausage 7. worth 8. usef 9. legal 10. winner 11. than 12. yellow";
    assert_eq!(seed::normalize_words(typed).as_deref(), Some(words));
    // A wrong word fails the checksum; so do 11 words, an unknown word, and a too-short form.
    assert!(seed::normalize_words(&words.replace("yellow", "zoo")).is_none());
    assert!(seed::normalize_words(&words.replace(" yellow", "")).is_none());
    assert!(seed::normalize_words(&words.replace("sausage", "sausages")).is_none());
    assert!(seed::normalize_words(&words.replace("sausage", "sau")).is_none());
    assert!(seed::normalize_words(&words.replace("winner", "win")).is_none());
}

#[test]
fn numbers_and_words_both_sign_in_to_different_keys() {
    assert_eq!(seed::normalize_credential("1234 5678-9012 3456"), Some(Credential::Number("1234567890123456".into())));
    let words = seed::new_recovery_words();
    assert_eq!(seed::normalize_credential(&words), Some(Credential::Words(words.clone())));
    assert!(seed::normalize_credential("123").is_none());
    let a = seed::account_keys(&words).unwrap();
    let b = seed::account_keys(&words.to_uppercase()).unwrap();
    assert_eq!(a.login_key, b.login_key);
    assert_eq!(a.seed, b.seed);
    let n = seed::account_keys("1234567890123456").unwrap();
    assert_ne!(a.login_key, n.login_key);
    // A number's keys are unchanged by this (accounts made before words still sign in).
    assert_eq!(n.login_key, seed::account_keys("1234-5678-9012-3456").unwrap().login_key);
}
