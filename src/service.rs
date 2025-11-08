//! Logic about all the services this application provides to users.

use crate::core;
use crate::core::{
    GetUserError, HashReader, UnverifiedPassword, UserEmail, UserProfile, UserProfileReader,
    VerifyError,
};

pub trait Verifier: Clone + Send + Sync + 'static {
    fn verify(&self, email: &UserEmail, password: UnverifiedPassword) -> Result<(), VerifyError>;
}

pub trait UserProfileGetter: Clone + Send + Sync + 'static {
    fn get_user_profile(&self, email: &UserEmail) -> Result<UserProfile, GetUserError>;
}

#[derive(Debug, Clone)]
pub struct Service<S: HashReader + UserProfileReader> {
    storage: S,
}

impl<S: HashReader + UserProfileReader> Service<S> {
    pub fn new(storage: S) -> Self {
        Service { storage }
    }
}

impl<S: HashReader + UserProfileReader> Verifier for Service<S> {
    fn verify(&self, email: &UserEmail, password: UnverifiedPassword) -> Result<(), VerifyError> {
        core::verify(email, password, &self.storage)
    }
}

impl<S: HashReader + UserProfileReader> UserProfileGetter for Service<S> {
    fn get_user_profile(&self, email: &UserEmail) -> Result<UserProfile, GetUserError> {
        self.storage.read_user_profile(email)
    }
}

/// Simple service storing a single `UserProfile`, for internal application testing only.
#[derive(Debug, Clone)]
pub struct SimpleTestService(UserProfile);

impl Default for SimpleTestService {
    fn default() -> Self {
        let target_email = UserEmail::new("fake@user.com");
        let test_user_profile = UserProfile {
            user_email: target_email.clone(),
            display_name: None,
            first_name: None,
            last_name: None,
            nickname: None,
        };
        Self(test_user_profile)
    }
}

impl Verifier for SimpleTestService {
    /// Always verifies as ok when email matches internal `UserProfile.user_email`. Otherwise, results in `VerifyError::UnknownEmail`.
    fn verify(&self, email: &UserEmail, _password: UnverifiedPassword) -> Result<(), VerifyError> {
        if &self.0.user_email == email {
            Ok(())
        } else {
            Err(VerifyError::UnknownEmail)
        }
    }
}

impl UserProfileGetter for SimpleTestService {
    /// Returns a clone of the services internal `UserProfile` if emails match. Otherwise, results in `GetUserError::UnknownEmail`.
    fn get_user_profile(&self, email: &UserEmail) -> Result<UserProfile, GetUserError> {
        if &self.0.user_email == email {
            Ok(self.0.clone())
        } else {
            Err(GetUserError::UnknownEmail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage;
    use std::io::Cursor;

    #[test]
    fn test_simpletestservice_verify() {
        let service = SimpleTestService::default();
        let target_email = service.0.user_email.clone();

        let result = service.verify(&target_email, UnverifiedPassword::new("fakepw"));

        assert!(result.is_ok(),)
    }

    #[test]
    fn test_simpletestservice_verify_unverified() {
        let service = SimpleTestService::default();
        let target_email = UserEmail::new("nonmatching@email.com");
        let expected = Err(VerifyError::UnknownEmail);

        let result = service.verify(&target_email, UnverifiedPassword::new("fakepw"));

        assert_eq!(result, expected)
    }

    #[test]
    fn test_simpletestservice_get_user_profile() {
        let service = SimpleTestService::default();
        let target_email = service.0.user_email.clone();
        let expected = service.0.clone();

        let result = service.get_user_profile(&target_email).unwrap();

        assert_eq!(result, expected)
    }

    #[test]
    fn test_simpletestservice_get_user_profile_nomatch() {
        let service = SimpleTestService::default();
        let target_email = UserEmail::new("nonmatching@email.com");
        let expected = Err(GetUserError::UnknownEmail);

        let result = service.get_user_profile(&target_email);

        assert_eq!(result, expected)
    }

    #[test]
    fn test_integration_service_verify_with_load_storage() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();

        let service = Service::new(store);

        // A phpass library-style hash.
        let result1 = service.verify(
            &UserEmail::new("email@example.com"),
            UnverifiedPassword::new("finalFormSkeleton"),
        );
        // A wordpress-style bcrypt hash.
        let result2 = service.verify(
            &UserEmail::new("email2@foobar.com"),
            UnverifiedPassword::new("Test123Now!"),
        );

        // Both should pass
        assert!(result1.is_ok());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_integration_service_get_user_profile_with_load_storage() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$BsSozX7pxy0bajB//ff34WOg4vN9OI/\nemail2@foobar.com,$wp$2y$10$gN3SQdbNc/cVlK7DylUiVumiuujud7lR0h5J4M2ZsNRMYOFbED16q";
        let cursor = Cursor::new(file_str);
        let store = storage::load_storage(cursor).unwrap();

        let service = Service::new(store);

        let target_email = UserEmail::new("email@example.com");
        let result1 = service.get_user_profile(&target_email).unwrap();

        // Not checking entire profile, just that it has email matching the email we requested.
        assert_eq!(result1.user_email, target_email);
    }
}
