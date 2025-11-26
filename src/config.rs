//! Logic for pulling together application configurations.

/// Application configuration
///
/// Use the [load] constructor to instantiate.
#[derive(Debug)]
pub struct Config {
    pub csv_path: String,
    pub host: String,
    pub port: String,
    pub apikey: Option<String>,
}

impl Config {
    /// Loads application configuration into memory.
    ///
    /// Panics if required environment variables are not set.
    pub fn load() -> Config {
        let csv_path =
            std::env::var("CSV_PATH").expect("required CSV_PATH environment variable is not set");
        let host = std::env::var("HOST").expect("required HOST environment variable is not set");
        let port = std::env::var("PORT").expect("required PORT environment variable is not set");
        let apikey: Option<String> = std::env::var("APIKEY").ok();

        Config {
            csv_path,
            host,
            port,
            apikey,
        }
    }
}
