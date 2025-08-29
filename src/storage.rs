//! Logic for IO and data storage.

use anyhow::{Context, Result, bail};
use log::info;
use serde::Deserialize;
use std::{collections::HashMap, io::Read};

/// In-memory storage for user hashes indexed on user email
#[derive(Deserialize)]
pub struct HashStorage {
    backend: HashMap<String, String>,
}

/// In-memory storage for securely hashed user credentials.
impl HashStorage {
    pub fn read_user_hash(&self, user_email: &String) -> Option<&String> {
        self.backend.get(user_email)
    }
}

/// Load credentials into mapped memory from hard storage.
pub fn load_storage<R: Read>(reader: R) -> Result<HashStorage> {
    let mut reader = csv::Reader::from_reader(reader);

    let mut data_map: HashMap<String, String> = HashMap::new();
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
    user_email: String,
    user_pass: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_load_storage_basic() {
        let file_str =
            "user_email,user_pass\nemail@example.com,AFakeHash\nemail2@foobar.com,AnotherFakeHash";
        let cursor = Cursor::new(file_str);

        let store = load_storage(cursor).expect("File didn't load");

        assert_eq!(
            store.read_user_hash(&String::from("email@example.com")),
            Some(&String::from("AFakeHash"))
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
}
