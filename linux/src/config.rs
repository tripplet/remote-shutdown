/// Configuration for the service.
pub struct Config {
    /// Listen address for the server.
    pub address: String,

    /// Secret used to validate requests.
    pub secret: String,
}

impl Config {
    /// Creates a [`Config`] from environment variables.
    pub fn from_env() -> Self {
        let secret = match read_secret() {
            Ok(secret) => secret,
            Err(e) => panic!("Failed to read secret: {e}"),
        };

        assert!(
            secret.len() >= 24,
            "SECRET variable is not long enough (minimum 24 characters)"
        );

        Self {
            address: std::env::var("ADDRESS").unwrap_or("[::]:10102".into()),
            secret,
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn read_secret() -> Result<String, std::io::Error> {
    Err(std::io::Error::other("Unsupported OS"))
}

/// Read the secret via systemd-secrets
#[cfg(target_os = "linux")]
fn read_secret() -> Result<String, std::io::Error> {
    let credential_directory =
        std::env::var("CREDENTIALS_DIRECTORY").unwrap_or("/run/secrets".into());

    // Read the secret from the file directly
    Ok(
        std::fs::read_to_string(format!("{credential_directory}/remote-shutdown-secret"))?
            .trim()
            .to_string(),
    )
}
