//! Password verifying and hashing logic.

use std::error::Error;

use base64::{Engine, prelude::BASE64_STANDARD};
use hmac::{Hmac, Mac};
use phpass::PhPass;
use serde::{Deserialize, Serialize};
use sha2::Sha384;

/// The profile part of a user record. Members should be owned by the object used for storage.
#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct UserProfile {
    pub user_email: UserEmail,
    pub display_name: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub nickname: Option<String>,
}

/// Verifies user email and password against stored password hashes.
///
/// Returns an empty Ok result when the password is successfully verified against a stored password hash under the same email address.
/// Any error or failure in this process returns an appropriate Err result.
///
/// Verification consumes the unverified password to guard against exposure.
pub fn verify(
    email: &UserEmail,
    password: UnverifiedPassword,
    storage: &impl HashReader,
) -> Result<(), VerifyError> {
    // Find hash in storage matching user email.
    let hash_result = storage.read_hash(email);
    let hash = match hash_result {
        Some(r) => r,
        None => return Err(VerifyError::UnknownEmail),
    };
    hash.verify(password)
}

/// Errors when getting user profile
#[derive(Debug, PartialEq)]
pub enum GetUserError {
    /// No recorded profile for user email.
    UnknownEmail,
}

/// Trait for reading a user profile from storage based on user email.
pub trait UserProfileReader: Send + Sync + Clone + 'static {
    fn read_user_profile(&self, email: &UserEmail) -> Result<UserProfile, GetUserError>;
}

/// Errors when verifying credentials.
#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// No recorded hash for user email.
    UnknownEmail,
    /// Verification completed but the password failed against hash.
    Password,
    /// Error from hashing algorithm, either when creating hashes or in the process of verification.
    Algorithm(AlgorithmVerifyError),
}

#[derive(Debug)]
pub struct AlgorithmVerifyError {
    pub context: String,
    pub source: Box<dyn Error>,
}
impl AlgorithmVerifyError {
    fn new<E: Error + 'static>(context: &str, source: E) -> Self {
        AlgorithmVerifyError {
            context: String::from(context),
            source: Box::new(source), // Need to own the error.
        }
    }
}

impl std::fmt::Display for AlgorithmVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.context)
    }
}

impl std::error::Error for AlgorithmVerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl PartialEq for AlgorithmVerifyError {
    fn eq(&self, _other: &Self) -> bool {
        // Equal as long as same type
        true
    }
}

/// Trait for reading a hashed password from storage based on user email.
pub trait HashReader: Send + Sync + Clone + 'static {
    fn read_hash(&self, email: &UserEmail) -> Option<&WordpressHash>;
}

/// A user's email address.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, Serialize)]
pub struct UserEmail(String);

impl UserEmail {
    pub fn new(value: &str) -> Self {
        Self(String::from(value))
    }
}

/// A password that has not yet been verified with a password hash.
///
/// Don't print, debug, or access directly except to get a verification decision from 'WordpressHash::verify'.
#[derive(Deserialize)]
pub struct UnverifiedPassword(String);

impl UnverifiedPassword {
    pub fn new(pwd: &str) -> Self {
        Self(String::from(pwd))
    }

    /// Return a byte slice of the password.
    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// A Wordpress password hash, either a bcrypt variant or from PHPass.
///
/// Use `WordpressHash::verify` to verify `UnverifiedPassword`s.
#[derive(Clone, Debug, PartialEq)]
pub enum WordpressHash {
    /// A Wordpress-flavored bcrypt hash.
    Bcrypt(BcryptWordpressHash),
    /// A PHPass hash.
    Phpass(PhpassWordpressHash),
}
impl WordpressHash {
    /// Verify password with hash, consuming the password.
    pub fn verify(&self, password: UnverifiedPassword) -> Result<(), VerifyError> {
        match self {
            WordpressHash::Bcrypt(h) => h.verify(password),
            WordpressHash::Phpass(h) => h.verify(password),
        }
    }
}

impl TryFrom<String> for WordpressHash {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // Logic from wordpress v6.8.2 https://github.com/WordPress/WordPress/blob/7a06b8b559b6979e66c3d52307c29fc036d262b4/wp-includes/pluggable.php#L2736
        // Figure out what kind of hash this is.
        let prefix = &value[..3];
        match prefix {
            "$wp" => Ok(WordpressHash::Bcrypt(BcryptWordpressHash::new(&value))),
            "$P$" => Ok(WordpressHash::Phpass(PhpassWordpressHash::new(&value))),
            _ => Err("Could not identify password hash type from prefix"),
        }
    }
}

/// A bcrypt-flavored Wordpress password hash.
#[derive(Clone, Debug, PartialEq)]
pub struct BcryptWordpressHash(String);

impl BcryptWordpressHash {
    fn new(value: &str) -> Self {
        // TODO: This assert is a sharp edge, should return a Result with a PrefixError as Err.
        assert!(
            value.starts_with("$wp"),
            "hash string from Wordpress-style brcypt should start with '$wp$' prefix"
        );
        Self(String::from(value))
    }

    fn verify(&self, pwd: UnverifiedPassword) -> Result<(), VerifyError> {
        let hash = &self.0;
        let password = pwd.as_bytes();

        log::debug!("started verifying with $wp$ hash");

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
        match decision_result {
            Ok(true) => Ok(()),
            Ok(false) => Err(VerifyError::Password),
            Err(e) => Err(VerifyError::Algorithm(AlgorithmVerifyError::new(
                "Error verifying user password with Wordpress-style bcrypt hash",
                e,
            ))),
        }
    }
}

/// A Wordpress password hash created with PHPass.
#[derive(Clone, Debug, PartialEq)]
pub struct PhpassWordpressHash(String);

impl PhpassWordpressHash {
    fn new(value: &str) -> Self {
        // TODO: This assert is a sharp edge, should return a Result with a PrefixError as Err.
        assert!(
            value.starts_with("$P$"),
            "hash string from Phpass should start with '$P$' prefix"
        );
        Self(String::from(value))
    }

    fn verify(&self, pwd: UnverifiedPassword) -> Result<(), VerifyError> {
        let hash = self.0.as_str();
        let password = pwd.as_bytes();

        // TODO: Will this work with 32 bit hashes or something from older Wordpress PHPass? Test and define the limits there.
        // TODO: Should just construct this PHPass instance when loading storage on startup. Later: Tried this and had lifetime issues because of requirements in phpass crate. Need to work those out.
        let hash_result = PhPass::try_from(hash);
        let hash = match hash_result {
            Ok(h) => h,
            Err(e) => {
                return Err(VerifyError::Algorithm(AlgorithmVerifyError::new(
                    "Error creating PHPass hash from stored hash",
                    e,
                )));
            }
        };

        let verify_result = hash.verify(password);
        match verify_result {
            Ok(r) => Ok(r),
            Err(phpass::error::Error::VerificationError) => Err(VerifyError::Password),
            Err(e) => Err(VerifyError::Algorithm(AlgorithmVerifyError::new(
                "Error verifying user password with PHPass hash",
                e,
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test WpHash::try_from() makes string correct variant.
    #[test]
    fn test_wphash_tryfrom_string() {
        let victim_bcrypt = String::from("$wp$foobar");
        assert_eq!(
            WordpressHash::Bcrypt(BcryptWordpressHash::new(&victim_bcrypt)),
            WordpressHash::try_from(victim_bcrypt).unwrap()
        );
        let victim_phpass = String::from("$P$foobar");
        assert_eq!(
            WordpressHash::Phpass(PhpassWordpressHash::new(&victim_phpass)),
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
        let pw = UnverifiedPassword::new("finalFormSkeleton");
        assert!(hash.verify(pw).is_ok(), "Failed to verify phpass hash")
    }

    #[test]
    fn test_verify_password_phpass_fails() {
        // Test that bad password fails verification against a phpass hash.
        let hash =
            WordpressHash::try_from(String::from("$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/")).unwrap();
        let pw = UnverifiedPassword::new("wrongPassword");
        assert_eq!(hash.verify(pw).unwrap_err(), VerifyError::Password)
    }

    #[test]
    fn test_verify_password_phpass2() {
        // Another good password should pass verification with PHPass hash.
        // Test case from phpass context test case in passlib (https://foss.heptapod.net/python-libs/passlib/-/blob/058b04309b762098c3a1f3bb026e6647caad085f/passlib/tests/test_apps.py).
        let hash =
            WordpressHash::try_from(String::from("$P$8Ja1vJsKa5qyy/b3mCJGXM7GyBnt6..")).unwrap();
        let pw = UnverifiedPassword::new("test");
        assert!(hash.verify(pw).is_ok(), "Failed to verify phpass hash")
    }

    #[test]
    fn test_verify_password_phpass3() {
        // Tests a password verifies in check against PHPass hash created using non-default 7 rounds.
        // Phpass test case using hash generated with with 7 rounds at https://asecuritysite.com/hash/phpass.
        let hash =
            WordpressHash::try_from(String::from("$P$5ZDzPE45Ci.QxPaPz.03z6TYbakcSQ0")).unwrap();
        let pw = UnverifiedPassword::new("password");
        assert!(hash.verify(pw).is_ok(), "Failed to verify phpass hash")
    }

    #[test]
    fn test_verify_password_wp() {
        // Test good password passes verification against a Wordpress-flavored bcrypt hash.
        // Wordpress-style bcrypt hash created by a Wordpress deployment
        let hash = WordpressHash::try_from(String::from(
            "$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q",
        ))
        .unwrap();
        let pw = UnverifiedPassword::new("Test123Now!");
        assert!(
            hash.verify(pw).is_ok(),
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
        let pw = UnverifiedPassword::new("thisPasswordBetterFail");
        assert_eq!(hash.verify(pw).unwrap_err(), VerifyError::Password)
    }

    /// Test that verify_password gracefully handles a bad hash with a good $wp prefix
    #[test]
    fn test_verify_password_wp_graceful_bad_hash_good_prefix() {
        let hash =
            WordpressHash::try_from(String::from("$wpWxWOG1b0YOGoRB2MeoHZrL7GDEVQJncNj47ib.vr2"))
                .unwrap();
        let pw = UnverifiedPassword::new("thisPasswordBetterFail");
        // TODO: Check for more specific algorithm error?
        assert!(hash.verify(pw).is_err())
    }

    /// Test that verify_password gracefully handles a bad hash with a good $P$ prefix
    #[test]
    fn test_verify_password_p_graceful_bad_hash_good_prefix() {
        let hash =
            WordpressHash::try_from(String::from("$P$WxWOG1b0YOGoRB2MeoHZrL7GDEVQJncNj47ib.vr2"))
                .unwrap();
        let pw = UnverifiedPassword::new("thisPasswordALSOBetterFail");
        // TODO: Check for more specific algorithm error?
        assert!(hash.verify(pw).is_err())
    }

    #[test]
    fn test_phpass_verify() {
        // Test case from phpass library (https://github.com/clausehound/phpass/blob/8c8f60467ad7510167d8bf9068f057fd9f22da0e/src/lib.rs).
        let hash = PhpassWordpressHash::new("$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/");
        let password = UnverifiedPassword::new("finalFormSkeleton");
        assert!(
            hash.verify(password).is_ok(),
            "Failed to verify random-salt hashed password"
        )
    }

    #[test]
    fn test_wpbcrypt_verify() {
        // Wordpress-style bcrypt hash created by a Wordpress deployment
        let hash = BcryptWordpressHash::new(
            "$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q",
        );
        let password = UnverifiedPassword::new("Test123Now!");
        assert!(
            hash.verify(password).is_ok(),
            "Failed to verify Wordpress-variant bcrypt hashed password"
        )
    }
}
