use std::{
    collections::HashMap,
    ops::Add,
    str::FromStr,
    sync::{LazyLock, Mutex, atomic::AtomicU64},
    time::{Duration, SystemTime},
};

use hmac::{Hmac, KeyInit, Mac, digest::FixedOutput};
use sha2::Sha256;

use crate::{command::Command, globals};

type HmacSha256 = Hmac<Sha256>;

/// Secret key used for challenge generation and verification.
static CHALLENGE_SECRET_KEY: LazyLock<[u8; 64]> = LazyLock::new(|| {
    let mut buf = [0u8; 64];
    getrandom::fill(&mut buf).unwrap();
    buf
});

static CHALLENGE_COUNTER: LazyLock<AtomicU64> =
    LazyLock::new(|| AtomicU64::new(getrandom::u64().unwrap() / 2));

static CHALLENGE_COUNTER_USED: LazyLock<Mutex<HashMap<u64, SystemTime>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A challenge (based on a timestamp and HMAC signature) for a challenge-response protocol.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct Challenge {
    valid_till: u64,
    counter: u64,
}

impl Challenge {
    // Generates a new challenge
    pub fn new() -> Self {
        let valid_till = SystemTime::now()
            .add(globals::CHALLENGE_VALID_DURATION)
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time should always be after unix epoch")
            .as_secs();

        let counter = CHALLENGE_COUNTER.fetch_add(
            (getrandom::u64().unwrap() % 100) + 1,
            std::sync::atomic::Ordering::Relaxed,
        );

        Self {
            valid_till,
            counter,
        }
    }

    pub fn signature(&self) -> Hmac<Sha256> {
        let mut hmac = HmacSha256::new_from_slice(&*CHALLENGE_SECRET_KEY)
            .expect("HMAC can take key of any size");
        hmac.update(&self.valid_till.to_be_bytes());
        hmac.update(&self.counter.to_be_bytes());
        hmac
    }

    /// Verifies that the given challenge is valid
    ///
    /// This should only be called once as the challenge is considered valid after this point.
    ///
    /// Returns `Ok` if the challenge is valid, `Err` otherwise.
    pub fn validate(&self, now: SystemTime) -> Result<(), &'static str> {
        let valid_till = SystemTime::UNIX_EPOCH.add(Duration::from_secs(self.valid_till));
        if valid_till < now {
            return Err("Expired");
        }

        // Valid timestamps should not be too far in the future but allow for some clock skew
        // This prevents someone from generating a valid challenge far in the future
        if valid_till > (now + 2 * globals::CHALLENGE_VALID_DURATION) {
            return Err("Expired");
        }

        let mut counters_used = CHALLENGE_COUNTER_USED.lock().unwrap();
        if counters_used.contains_key(&self.counter) {
            return Err("Challenge already used");
        }

        counters_used.insert(self.counter, valid_till);

        // Cleanup all expired counter entries
        counters_used.retain(|_, till| *till > now);

        Ok(())
    }
}

impl FromStr for Challenge {
    type Err = &'static str;

    /// Parses a challenge string into a [`Challenge`] instance.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let Ok(received_bytes) = hex::decode(input) else {
            return Err("Invalid challenge format");
        };

        if received_bytes.len() != 48 {
            return Err("Invalid challenge length");
        }

        let challenge = Self {
            valid_till: u64::from_be_bytes(received_bytes[0..8].try_into().unwrap()),
            counter: u64::from_be_bytes(received_bytes[8..16].try_into().unwrap()),
        };
        let received_signature = &received_bytes[16..];

        challenge
            .signature()
            .verify_slice(received_signature)
            .map_err(|_| "Invalid challenge signature")?;

        Ok(challenge)
    }
}

impl std::fmt::Display for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.valid_till.to_be_bytes()))?;
        write!(f, "{}", hex::encode(self.counter.to_be_bytes()))?;
        write!(f, "{}", hex::encode(self.signature().finalize_fixed()))
    }
}

/// Validates the response against the given secret and returns the parsed command.
pub fn validate_response(signed_response: &str, secret: &str) -> Result<Command, &'static str> {
    // Split the signed response into the response and the signature
    let Some((response, signature)) = signed_response.rsplit_once('.') else {
        return Err("Invalid format");
    };

    // Extract the command string and challenge from the response
    let Some((command_str, challenge)) = response.split_once('.') else {
        return Err("Invalid format");
    };

    // Verify that this is a valid challenge we send out
    challenge
        .parse::<Challenge>()?
        .validate(SystemTime::now())?;

    // Verify the signature matches to ensure client is in possession of the secret
    let mut hmac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    hmac.update(response.as_bytes());
    hmac.verify_slice(&hex::decode(signature).map_err(|_| "Invalid HMAC")?)
        .map_err(|_| "Invalid signature")?;

    command_str
        .parse::<Command>()
        .map_err(|_| "Invalid command")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_response(response: &str, secret: &str) -> String {
        let mut hmac =
            HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
        hmac.update(response.as_bytes());
        hex::encode(hmac.finalize_fixed())
    }

    #[test]
    fn challenge_roundtrip() {
        let challenge = Challenge::new();
        let parsed = format!("{challenge}").parse::<Challenge>().unwrap();
        assert!(parsed.validate(SystemTime::now()).is_ok());
    }

    #[test]
    fn challenge_invalid() {
        let challenge = Challenge::new();
        let challenge_str = format!("{challenge}");
        let mut challenge_bytes = challenge_str.as_bytes().to_vec();
        challenge_bytes[30] = b'y';
        let invalid_challenge = String::from_utf8(challenge_bytes).unwrap();
        assert_eq!(
            invalid_challenge.parse::<Challenge>(),
            Err("Invalid challenge format")
        );
    }

    #[test]
    fn challenge_expired() {
        let challenge = Challenge::new();
        let expired_timestamp =
            SystemTime::now() + globals::CHALLENGE_VALID_DURATION + Duration::from_secs(1);

        assert_eq!(Err("Expired"), challenge.validate(expired_timestamp));
    }

    #[test]
    fn challenge_reuse() {
        // create a copy
        let challenge = Challenge::new();
        let challenge_copy = format!("{}", challenge).parse::<Challenge>().unwrap();

        assert_eq!(Ok(()), challenge.validate(SystemTime::now()));
        assert_eq!(
            Err("Challenge already used"),
            challenge_copy.validate(SystemTime::now())
        );
    }

    #[test]
    fn test_challenge_performance() {
        let start = SystemTime::now();
        for _ in 0..100 {
            let challenge_str = format!("{}", Challenge::new());
            let challenge = challenge_str.parse::<Challenge>().unwrap();

            assert!(challenge.validate(SystemTime::now()).is_ok());
        }
        let duration = SystemTime::now().duration_since(start).unwrap();
        assert!(duration < Duration::from_secs(1));
    }

    #[test]
    fn test_validate_response() {
        let secret = "secret";
        let challenge = Challenge::new();
        let response = format!("shutdown.{challenge}");
        let signature = sign_response(&response, secret);
        let signed_response = format!("{response}.{signature}");
        assert_eq!(
            Ok(Command::Shutdown),
            validate_response(&signed_response, secret)
        );
    }
}
