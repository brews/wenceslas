//! Password verifying and hashing logic.

use base64::{Engine, prelude::BASE64_STANDARD};
use hmac::{Hmac, Mac};
use log::error;
use phpass::PhPass;
use serde::Deserialize;
use sha2::Sha384;

/// An unverified password.
///
/// Don't print, debug, or access directly except to get a verification decision from 'WordpressHash::verify'.
#[derive(Deserialize)]
pub struct UnverifiedPassword(String);

impl UnverifiedPassword {
    /// Return a byte slice of the password.
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A Wordpress password hash, either a bcrypt variant or from PHPass.
///
/// Use `WordpressHash::verify` to verify `UnverifiedPassword`s.
#[derive(Debug, PartialEq)]
pub enum WordpressHash {
    /// A Wordpress-flavored bcrypt hash.
    Bcrypt(String),
    /// A PHPass hash.
    Phpass(String),
}
impl WordpressHash {
    /// Verify password with hash, consuming the password.
    pub fn verify(&self, pwd: UnverifiedPassword) -> bool {
        let password = pwd.as_bytes();
        match self {
            WordpressHash::Bcrypt(h) => wp_verify(h, password),
            WordpressHash::Phpass(h) => p_verify(h, password),
        }
    }
}

impl TryFrom<String> for WordpressHash {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Logic from wordpress v6.8.2 https://github.com/WordPress/WordPress/blob/7a06b8b559b6979e66c3d52307c29fc036d262b4/wp-includes/pluggable.php#L2736
        // Figure out what kind of hash this is.
        let prefix = &value[..3];
        log::debug!("verifying with prefix {prefix}");
        // TODO: Have this return a more descriptive/parsable error.
        match prefix {
            "$wp" => Ok(WordpressHash::Bcrypt(value)),
            "$P$" => Ok(WordpressHash::Phpass(value)),
            _ => Err("Could not identify password hash type"),
        }
    }
}

/// Verify password again Wordpress variation of bcrypt hashes. The hashes have a "$wp" prefix.
fn wp_verify(hash: &str, password: &[u8]) -> bool {
    log::info!("started verifying with $wp$ hash");

    // Hashes with "$wp" prefix need pre-hashing, so need to prehash password for comparison with stored hash.
    let key = b"wp-sha384";
    let mut hmac_sha384 =
        Hmac::<Sha384>::new_from_slice(key).expect("HMAC should take a key of any size");
    hmac_sha384.update(password);
    let digest = hmac_sha384.finalize().into_bytes();

    let prehashed_password = BASE64_STANDARD.encode(digest);

    // Remove the leading "$wp" from the stored hash.
    let hash_without_prefix = &hash[3..];

    let decision_result = bcrypt::verify(prehashed_password, hash_without_prefix);
    // Error during verification means that verification should fail (and the error logged).
    match decision_result {
        Ok(r) => r,
        Err(e) => {
            error!("Error verifying password with apparent bcrypt hash: {e}");
            false
        }
    }
}

/// Verify password against older Wordpress hash based on PHPass algorithm. These hashes have a "$P$" prefix.
fn p_verify(hash: &str, password: &[u8]) -> bool {
    log::info!("started verifying with $P$ hash");

    let hash_result = PhPass::try_from(hash);
    // Fail verification if we can't create a hash from what's in storage (and log the error).
    let hash = match hash_result {
        Ok(h) => h,
        Err(e) => {
            error!("Error when creating PHPass hash instance from hash in storage: {e}");
            return false;
        }
    };

    hash.verify(password).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test WpHash::try_from() makes string correct variant.
    #[test]
    fn test_wphash_tryfrom_string() {
        let victim_bcrypt = String::from("$wp$foobar");
        assert_eq!(
            WordpressHash::Bcrypt(victim_bcrypt.clone()),
            WordpressHash::try_from(victim_bcrypt).unwrap()
        );
        let victim_phpass = String::from("$P$foobar");
        assert_eq!(
            WordpressHash::Phpass(victim_phpass.clone()),
            WordpressHash::try_from(victim_phpass).unwrap()
        );
    }

    /// Test WpHash::try_from() errors on unknown hash prefixes.
    #[test]
    #[should_panic]
    fn test_wphash_tryfrom_string_badprefix_error() {
        let _ = WordpressHash::try_from(String::from("$foobar$ninini")).unwrap();
    }

    /// Test WpHash::try_from() errors when there is no hash prefix (or if hash is actually a raw password).
    #[test]
    #[should_panic]
    fn test_wphash_tryfrom_string_rawpassword_error() {
        let _ = WordpressHash::try_from(String::from("foobar")).unwrap();
    }

    #[test]
    fn test_verify_password_phpass() {
        // A good password should pass verification with PHPass hash.
        // Test case from phpass library (https://github.com/clausehound/phpass/blob/8c8f60467ad7510167d8bf9068f057fd9f22da0e/src/lib.rs).
        let hash =
            WordpressHash::try_from(String::from("$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/")).unwrap();
        let pw = UnverifiedPassword(String::from("finalFormSkeleton"));
        assert!(hash.verify(pw), "Failed to verify phpass hash")
    }

    #[test]
    fn test_verify_password_phpass_fails() {
        // Test that bad password fails verification against a phpass hash.
        let hash =
            WordpressHash::try_from(String::from("$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/")).unwrap();
        let pw = UnverifiedPassword(String::from("wrongPassword"));
        assert!(
            !hash.verify(pw),
            "Password verified successfully when it should have failed"
        )
    }

    #[test]
    fn test_verify_password_phpass2() {
        // Another good password should pass verification with PHPass hash.
        // Test case from phpass context test case in passlib (https://foss.heptapod.net/python-libs/passlib/-/blob/058b04309b762098c3a1f3bb026e6647caad085f/passlib/tests/test_apps.py).
        let hash =
            WordpressHash::try_from(String::from("$P$8Ja1vJsKa5qyy/b3mCJGXM7GyBnt6..")).unwrap();
        let pw = UnverifiedPassword(String::from("test"));
        assert!(hash.verify(pw), "Failed to verify phpass hash")
    }

    #[test]
    fn test_verify_password_phpass3() {
        // Tests a password verifies in check against PHPass hash created using non-default 7 rounds.
        // Phpass test case using hash generated with with 7 rounds at https://asecuritysite.com/hash/phpass.
        let hash =
            WordpressHash::try_from(String::from("$P$5ZDzPE45Ci.QxPaPz.03z6TYbakcSQ0")).unwrap();
        let pw = UnverifiedPassword(String::from("password"));
        assert!(hash.verify(pw), "Failed to verify phpass hash")
    }

    #[test]
    fn test_verify_password_wp() {
        // Test good password passes verification against a Wordpress-flavored bcrypt hash.
        // Wordpress-style bcrypt hash created by a Wordpress deployment
        let hash = WordpressHash::try_from(String::from(
            "$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q",
        ))
        .unwrap();
        let pw = UnverifiedPassword(String::from("Test123Now!"));
        assert!(
            hash.verify(pw),
            "Failed to verify Wordpress-style bcrypt hash"
        )
    }

    #[test]
    fn test_verify_password_wp_fails() {
        // Test bad password fails verification with Wordpress-style bcrypt hash
        let hash = WordpressHash::try_from(String::from(
            "$wp$2y$10$IlOpB3j5X32cWxWOG1b0YOGoRB2MeoHZrL7GDEVQJncNj47ib.vr2",
        ))
        .unwrap();
        let pw = UnverifiedPassword(String::from("thisPasswordBetterFail"));
        assert!(
            !hash.verify(pw),
            "Password passed verification when it should have failed"
        )
    }

    /// Test that verify_password gracefully handles a bad hash with a good $wp prefix
    #[test]
    fn test_verify_password_wp_graceful_bad_hash_good_prefix() {
        let hash =
            WordpressHash::try_from(String::from("$wpWxWOG1b0YOGoRB2MeoHZrL7GDEVQJncNj47ib.vr2"))
                .unwrap();
        let pw = UnverifiedPassword(String::from("thisPasswordBetterFail"));
        assert!(
            !hash.verify(pw),
            "Password passed verification when it should have failed"
        )
    }

    /// Test that verify_password gracefully handles a bad hash with a good $P$ prefix
    #[test]
    fn test_verify_password_p_graceful_bad_hash_good_prefix() {
        let hash =
            WordpressHash::try_from(String::from("$P$WxWOG1b0YOGoRB2MeoHZrL7GDEVQJncNj47ib.vr2"))
                .unwrap();
        let pw = UnverifiedPassword(String::from("thisPasswordALSOBetterFail"));
        assert!(
            !hash.verify(pw),
            "Password passed verification when it should have failed"
        )
    }

    #[test]
    fn test_p_verify() {
        // Test case from phpass library (https://github.com/clausehound/phpass/blob/8c8f60467ad7510167d8bf9068f057fd9f22da0e/src/lib.rs).
        assert!(
            p_verify(
                &String::from("$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/"),
                "finalFormSkeleton".as_bytes(),
            ),
            "Failed to verify random-salt hashed password"
        )
    }

    #[test]
    fn test_wp_verify() {
        // Wordpress-style bcrypt hash created by a Wordpress deployment
        assert!(
            wp_verify(
                &String::from("$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q"),
                "Test123Now!".as_bytes(),
            ),
            "Failed to verify Wordpress-variant bcrypt hashed password"
        )
    }
}
