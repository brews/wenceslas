//! Core logic for the application.

use base64::{Engine, prelude::BASE64_STANDARD};
use hmac::{Hmac, Mac};
use log::error;
use phpass::PhPass;
use sha2::Sha384;

/// Verify password against stored hash.
pub fn verify_password(hash: &str, password: &[u8]) -> bool {
    // Logic from wordpress v6.8.2 https://github.com/WordPress/WordPress/blob/7a06b8b559b6979e66c3d52307c29fc036d262b4/wp-includes/pluggable.php#L2736
    //
    // Figure out what kind of hash this is.
    let prefix = &hash[..3];
    log::debug!("verifying with prefix {prefix}");
    match prefix {
        "$wp" => wp_verify(hash, password),
        "$P$" => p_verify(hash, password),
        _ => false,
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

    #[test]
    fn test_verify_password_unhashed() {
        // Test the case when a "hash" is not actually a hash but a raw password. This case should fail verification.
        assert!(
            !verify_password("AnUnhashedPassword", "AnUnhashedPassword".as_bytes()),
            "A hash that is actually an un-unhashed password should not pass verification"
        )
    }

    #[test]
    fn test_verify_password_fails_unknown_hash() {
        // Test that some unknown "hash" fails verification.
        assert!(
            !verify_password(
                "$what$is$this$hash$2bajB//ff34WOg4vN9OI/",
                "aBadPassword".as_bytes()
            ),
            "Password verified against an unknown hash when it should have failed"
        )
    }

    #[test]
    fn test_verify_password_phpass() {
        // Test case from phpass library (https://github.com/clausehound/phpass/blob/8c8f60467ad7510167d8bf9068f057fd9f22da0e/src/lib.rs).
        assert!(
            verify_password(
                "$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/",
                "finalFormSkeleton".as_bytes()
            ),
            "Failed to verify phpass hash"
        )
    }

    #[test]
    fn test_verify_password_phpass_fails() {
        // Test that bad password fails verification against a phpass hash.
        assert!(
            !verify_password(
                "$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/",
                "wrongPassword".as_bytes()
            ),
            "Password verified that should have failed"
        )
    }

    #[test]
    fn test_verify_password_phpass2() {
        // Test case from phpass context test case in passlib (https://foss.heptapod.net/python-libs/passlib/-/blob/058b04309b762098c3a1f3bb026e6647caad085f/passlib/tests/test_apps.py).
        assert!(
            verify_password("$P$8Ja1vJsKa5qyy/b3mCJGXM7GyBnt6..", "test".as_bytes()),
            "Failed to verify phpass hash"
        )
    }

    #[test]
    fn test_verify_password_phpass3() {
        // Phpass test case using hash generated with with 7 rounds at https://asecuritysite.com/hash/phpass.
        assert!(
            verify_password("$P$5ZDzPE45Ci.QxPaPz.03z6TYbakcSQ0", "password".as_bytes()),
            "Failed to verify phpass hash"
        )
    }

    #[test]
    fn test_verify_password_wp() {
        // Wordpress-style bcrypt hash created by a Wordpress deployment
        assert!(
            verify_password(
                "$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q",
                "Test123Now!".as_bytes()
            ),
            "Failed to verify Wordpress-style bcrypt hash"
        )
    }

    #[test]
    fn test_verify_password_wp_fails() {
        // Test bad password fails verification with Wordpress-style bcrypt hash
        assert!(
            !verify_password(
                "$wp$2y$10$IlOpB3j5X32cWxWOG1b0YOGoRB2MeoHZrL7GDEVQJncNj47ib.vr2",
                "thisPasswordBetterFail".as_bytes()
            ),
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
