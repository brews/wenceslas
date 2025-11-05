//! Logic for IO and data storage.

use anyhow::{Context, Result, bail};
use log::info;
use serde::{Deserialize, Deserializer, de::Error};
use std::{collections::HashMap, io::Read};

use crate::core::{
    GetUserError, HashReader, UserEmail, UserProfile, UserProfileReader, WordpressHash,
};

/// In-memory storage for password hashes indexed on user email
pub struct HashStorage {
    backend: HashMap<UserEmail, UserRecord>,
}

impl HashReader for HashStorage {
    fn read_hash(&self, email: &UserEmail) -> Option<&WordpressHash> {
        let user_record_result = self.backend.get(email);
        let wordpress_hash = match user_record_result {
            Some(r) => &r.user_pass,
            None => return None,
        };
        Some(wordpress_hash)
    }
}

impl UserProfileReader for HashStorage {
    fn read_user_profile(&self, email: &UserEmail) -> Result<UserProfile, GetUserError> {
        let user_record_result = self.backend.get(email);
        let user_record = match user_record_result {
            Some(r) => r,
            None => return Err(GetUserError::UnknownEmail),
        };
        Ok(UserProfile {
            user_email: user_record.user_email.clone(),
            display_name: user_record.display_name.clone(),
            first_name: user_record.first_name.clone(),
            last_name: user_record.last_name.clone(),
            nickname: user_record.nickname.clone(),
        })
    }
}

/// Load credentials into mapped memory from hard storage.
pub fn load_storage<R: Read>(reader: R) -> Result<HashStorage> {
    let mut reader = csv::Reader::from_reader(reader);

    let mut data_map: HashMap<UserEmail, UserRecord> = HashMap::new();
    let mut n = 0;

    for result in reader.deserialize() {
        let record: UserRecord = result.context("Could not deserialize line from file")?;

        // Error if we find duplicate user_email in records.
        if data_map.contains_key(&record.user_email) {
            bail!(
                "Encountered duplicate user_email in storage {0:?}",
                record.user_email
            )
        }

        data_map.insert(record.user_email.clone(), record);
        n += 1;
    }
    info!("loaded {n} records from storage");

    Ok(HashStorage { backend: data_map })
}

/// Stored record for profile and login credentials of a single user.
#[derive(Deserialize)]
struct UserRecord {
    user_email: UserEmail,
    user_pass: WordpressHash,
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    nickname: Option<String>,
}

impl<'de> Deserialize<'de> for WordpressHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?; // Deserialize the input as a String

        // Let core hashing logic determine how string is parsed, but wrap any errors so this returns proper deserialization errors.
        WordpressHash::try_from(s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_load_storage_basic() {
        let file_str = "user_email,user_pass\nemail@example.com,$P$AFakeHash\nemail2@foobar.com,$wp$AnotherFakeHash";
        let cursor = Cursor::new(file_str);

        let store = load_storage(cursor).expect("File didn't load");

        assert_eq!(
            store.read_hash(&UserEmail::new("email@example.com")),
            Some(&WordpressHash::try_from(String::from("$P$AFakeHash")).unwrap())
        );
    }

    #[test]
    #[should_panic]
    fn test_no_duplicates() {
        // Duplicate emails should cause load_storage to return Err.
        let file_str =
            "user_email,user_pass\nemail@example.com,AFakeHash\nemail@example.com,AnotherFakeHash";
        let cursor = Cursor::new(file_str);

        let _ = load_storage(cursor).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_storage_needs_user_pass_column() {
        // Storage file needs user_pass column or load_storage should panic.
        let file_str = "user_email,not_user_pass\nemail@example.com,AFakeHash\nemail@example.com,AnotherFakeHash";
        let cursor = Cursor::new(file_str);

        let _ = load_storage(cursor).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_storage_needs_user_email_column() {
        // Storage file needs user_email column or load_storage should panic.
        let file_str = "user_email,not_user_pass\nemail@example.com,AFakeHash\nemail@example.com,AnotherFakeHash";
        let cursor = Cursor::new(file_str);

        let _ = load_storage(cursor).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_storage_needs_recognized_hashes() {
        // Storage file needs to have recognized hash types or reading it should cause panic.
        // Note the $BADHASHPREFIX$ entry is a bad hash that shouldn't be recognized.
        let file_str = "user_email,user_pass\nemail@example.com,$BADHASHPREFIX$AFakeHash\nemail2@foobar.com,$wp$AnotherFakeHash";
        let cursor = Cursor::new(file_str);

        let _ = load_storage(cursor).unwrap();
    }

    #[test]
    fn test_load_storage_full_profile() {
        // Can load storage file to create a UserProfile is required fields are available in stored data.
        let file_str = "user_email,user_pass,display_name,first_name,last_name,nickname\nemail@example.com,$P$AFakeHash,DisplayName1,FirstName1,LastName1,Nickname1\nemail2@foobar.com,$wp$AnotherFakeHash,DisplayName2,FirstName2,LastName2,Nickname2";
        let cursor = Cursor::new(file_str);

        let store = load_storage(cursor).expect("File didn't load");

        assert_eq!(
            store.read_hash(&UserEmail::new("email@example.com")),
            Some(&WordpressHash::try_from(String::from("$P$AFakeHash")).unwrap())
        );
        assert_eq!(
            store
                .read_user_profile(&UserEmail::new("email@example.com"))
                .unwrap(),
            UserProfile {
                user_email: UserEmail::new("email@example.com"),
                display_name: Some(String::from("DisplayName1")),
                first_name: Some(String::from("FirstName1")),
                last_name: Some(String::from("LastName1")),
                nickname: Some(String::from("Nickname1")),
            }
        )
    }
}
