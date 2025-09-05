//! Logic for IO and data storage.

use anyhow::{Context, Result, bail};
use log::info;
use serde::{Deserialize, Deserializer, de::Error};
use std::{collections::HashMap, io::Read};

use crate::core::{HashReader, UserEmail, WordpressHash};

/// In-memory storage for password hashes indexed on user email
pub struct HashStorage {
    backend: HashMap<UserEmail, WordpressHash>,
}

impl HashReader for HashStorage {
    fn read_hash(&self, email: &UserEmail) -> Option<&WordpressHash> {
        self.backend.get(email)
    }
}

/// Load credentials into mapped memory from hard storage.
pub fn load_storage<R: Read>(reader: R) -> Result<HashStorage> {
    let mut reader = csv::Reader::from_reader(reader);

    let mut data_map: HashMap<UserEmail, WordpressHash> = HashMap::new();
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

        data_map.insert(record.user_email, record.user_pass);
        n += 1;
    }
    info!("loaded {n} records from storage");

    Ok(HashStorage { backend: data_map })
}

/// Stored record for login credentials of a single user.
#[derive(Deserialize)]
struct UserRecord {
    user_email: UserEmail,
    user_pass: WordpressHash,
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
}
