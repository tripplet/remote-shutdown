//! Global constants

use std::time::Duration;

/// Duration for which a challenge is valid.
pub const CHALLENGE_VALID_DURATION: Duration = Duration::from_secs(5);

/// Timeout for socket operations.
pub const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum number of concurrent connections for rate limiting.
pub const RATE_LIMIT_MAX_CONNECTIONS: isize = 16;

/// Maximum request length.
pub const MAX_REQUEST_LEN: u64 = 4096;

/// Maximum number of HTTP headers.
pub const MAX_HTTP_HEADERS: usize = 32;
