//! Account codes as a person uses them: made on the device, written down, typed back in (any
//! case, dashes or not, O for 0, I or L for 1), checked for typos, and turned into the keys that
//! sign in.
use unlinkable_inference::seed::{self, Credential};

const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[test]
fn made_and_read_back() {
    let zero = seed::code_from_bytes([0; 12]);
    assert_eq!(zero.len(), 20);
    assert!(zero.starts_with("0000000000000000000"), "{zero}");
    assert_eq!(seed::normalize_code(&zero).as_deref(), Some(zero.as_str()));
    for _ in 0..500 {
        let code = seed::new_account_code();
        assert_eq!(code.len(), 23, "four groups of five: {code}");
        assert!(code.split('-').all(|g| g.len() == 5), "{code}");
        let bare = code.replace('-', "");
        assert!(bare.chars().all(|c| ALPHABET.contains(c)), "{code}");
        assert_eq!(seed::normalize_code(&code).as_deref(), Some(bare.as_str()));
    }
}

#[test]
fn typed_back_in() {
    let code = seed::new_account_code();
    let bare = code.replace('-', "");
    // Lower case, spaces instead of dashes, no separators at all.
    for typed in [code.to_lowercase(), code.replace('-', " "), bare.clone(), format!(" {} ", bare.to_lowercase())] {
        assert_eq!(seed::normalize_code(&typed).as_deref(), Some(bare.as_str()), "{typed}");
    }
    // O is read as 0, and I or L as 1.
    let zero = seed::code_from_bytes([0; 12]);
    assert_eq!(seed::normalize_code(&zero.replace('0', "O")).as_deref(), Some(zero.as_str()));
    let with_one = (0..200).map(|_| seed::new_account_code().replace('-', "")).find(|c| c.contains('1')).unwrap();
    assert_eq!(seed::normalize_code(&with_one.replace('1', "l")).as_deref(), Some(with_one.as_str()));
    assert_eq!(seed::normalize_code(&with_one.replace('1', "I")).as_deref(), Some(with_one.as_str()));
    // A wrong character is caught by the check 15 times in 16: over every one-character change,
    // nearly all are.
    let (mut caught, mut tried) = (0, 0);
    for pos in 0..20 {
        for c in ALPHABET.chars() {
            if bare.chars().nth(pos) == Some(c) {
                continue;
            }
            let mut t: Vec<char> = bare.chars().collect();
            t[pos] = c;
            tried += 1;
            if seed::normalize_code(&t.into_iter().collect::<String>()).is_none() {
                caught += 1;
            }
        }
    }
    assert!(caught * 100 / tried >= 85, "{caught} of {tried} caught");
    // Wrong length, a U, punctuation.
    assert!(seed::normalize_code(&bare[..19]).is_none());
    assert!(seed::normalize_code(&format!("{bare}0")).is_none());
    assert!(seed::normalize_code(&format!("U{}", &bare[1..])).is_none());
    assert!(seed::normalize_code(&format!("*{}", &bare[1..])).is_none());
}

#[test]
fn codes_and_numbers_both_sign_in_to_different_keys() {
    assert_eq!(seed::normalize_credential("1234 5678-9012 3456"), Some(Credential::Number("1234567890123456".into())));
    let code = seed::new_account_code();
    assert_eq!(seed::normalize_credential(&code), Some(Credential::Code(code.replace('-', ""))));
    assert!(seed::normalize_credential("123").is_none());
    let a = seed::account_keys(&code).unwrap();
    let b = seed::account_keys(&code.to_lowercase().replace('-', " ")).unwrap();
    assert_eq!(a.login_key, b.login_key);
    assert_eq!(a.seed, b.seed);
    let n = seed::account_keys("1234567890123456").unwrap();
    assert_ne!(a.login_key, n.login_key);
    // A number's keys are unchanged by codes (accounts made before them still sign in).
    assert_eq!(n.login_key, seed::account_keys("1234-5678-9012-3456").unwrap().login_key);
}
