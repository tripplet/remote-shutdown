use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::Arc,
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{
    config::Config,
    crypto::{Challenge, validate_response},
    globals,
};

/// Start the TCP server
pub fn start_server(config: &Config) -> Result<JoinHandle<()>, std::io::Error> {
    let listener = TcpListener::bind(&config.address)?;
    let secret = config.secret.clone();
    Ok(thread::spawn(move || run_server(&listener, &secret)))
}

struct Semaphore {
    counter: std::sync::Mutex<isize>,
    condvar: std::sync::Condvar,
}

struct SemaphoreGuard<'a> {
    semaphore: &'a Semaphore,
}

impl Drop for SemaphoreGuard<'_> {
    fn drop(&mut self) {
        *self.semaphore.counter.lock().unwrap() += 1;
        self.semaphore.condvar.notify_one();
    }
}

/// Run the TCP server thread
pub fn run_server(listener: &TcpListener, secret: &str) {
    let max_connections = Arc::new(Semaphore {
        counter: std::sync::Mutex::new(globals::RATE_LIMIT_MAX_CONNECTIONS),
        condvar: std::sync::Condvar::new(),
    });

    thread::scope(|s| {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    if let Err(e) = stream.set_read_timeout(Some(globals::SOCKET_TIMEOUT)) {
                        eprintln!("Failed to set read timeout: {e}");
                        continue;
                    }

                    if let Err(e) = stream.set_write_timeout(Some(globals::SOCKET_TIMEOUT)) {
                        eprintln!("Failed to set write timeout: {e}");
                        continue;
                    }

                    let Ok(stream_read) = stream.try_clone() else {
                        eprintln!("Failed to clone stream for reading");
                        continue;
                    };

                    let mut count = max_connections.counter.lock().unwrap();
                    while *count <= 0 {
                        count = max_connections.condvar.wait(count).unwrap();
                    }
                    *count -= 1;
                    drop(count);

                    s.spawn({
                        let guard = SemaphoreGuard {
                            semaphore: &max_connections,
                        };
                        move || {
                            // Simple rate limiting
                            thread::sleep(Duration::from_millis(100));

                            handle_connection(stream_read, stream, secret);
                            drop(guard);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error accepting connection: {e}");
                }
            }

            // Rate limit with a 100ms sleep
            thread::sleep(Duration::from_millis(100));
        }
    });
}

/// Handle a single incoming connection
fn handle_connection(
    stream_read: impl std::io::Read,
    mut stream_write: impl std::io::Write,
    secret: &str,
) {
    // Limit the size of the request to prevent memory exhaustion
    let reader = BufReader::new(stream_read);
    let mut reader = reader.take(globals::MAX_REQUEST_LEN);

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Err(e) => {
                eprintln!("Failed to read request: {e}");
                return;
            }
            Ok(0) => return,
            Ok(_) => {
                let request = line.trim();
                if request.starts_with("GET ") || request.starts_with("POST ") {
                    return handle_http_request(request, secret, &mut reader, &mut stream_write);
                }

                if request == "ping" {
                    let _ = stream_write.write_all(b"pong\n");
                } else if request == "request_challenge" {
                    let challenge = Challenge::new();
                    if let Err(e) = stream_write.write_all(format!("{challenge}\n").as_bytes()) {
                        eprintln!("Failed to send challenge: {e}");
                    }
                } else {
                    let response = handle_command(request, secret);
                    let _ = stream_write.write_all(response.as_bytes());
                }
            }
        }
    }
}

fn handle_command(request: &str, secret: &str) -> &'static str {
    match validate_response(request, secret) {
        Ok(command) => match command.execute() {
            Ok(()) => {
                eprintln!("Command executed successfully: {command}");
                "1\n"
            }
            Err(e) => {
                eprintln!("Failed to execute command: {e}");
                "0\n"
            }
        },
        Err(e) => {
            eprintln!("Invalid response: {e}");
            "0\n"
        }
    }
}

fn handle_http_request(
    request: &str,
    secret: &str,
    reader: &mut std::io::Take<BufReader<impl Read>>,
    stream_write: &mut impl Write,
) {
    let (method, path, _headers) = match parse_http_request(request, reader) {
        Ok(parsed) => parsed,
        Err(response) => {
            let _ = stream_write.write_all(response.as_bytes());
            return;
        }
    };

    let (status, body_response) = match (method.as_str(), path.as_str()) {
        ("GET", "/ping") => ("200 OK", String::from("pong")),
        ("GET", "/request_challenge") => ("200 OK", Challenge::new().to_string()),
        ("POST", path) if path.starts_with("/command?") => match path.split_once('?') {
            Some((_, signed_response)) => {
                let resp = handle_command(signed_response, secret);
                ("200 OK", String::from(resp))
            }
            None => ("400 Bad Request", String::new()),
        },
        _ => ("404 Not Found", String::new()),
    };

    send_http_response(stream_write, status, &body_response).ok();
}

fn send_http_response(
    stream_write: &mut impl Write,
    status: &str,
    body_text: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body_text}",
        len = body_text.len()
    );
    stream_write.write_all(response.as_bytes())
}

fn parse_http_request(
    request_line: &str,
    reader: &mut std::io::Take<BufReader<impl Read>>,
) -> Result<(String, String, std::collections::HashMap<String, String>), &'static str> {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    if method != "GET" && method != "POST" {
        return Err(
            "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, POST\r\nContent-Length: 0\r\n\r\n",
        );
    }

    let mut headers = std::collections::HashMap::new();
    let mut buf = String::new();

    loop {
        buf.clear();
        match reader.read_line(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = buf.trim_end_matches(['\r', '\n']);
                if line.is_empty() {
                    break;
                }
                if let Some((key, value)) = line.split_once(':') {
                    if headers.len() >= globals::MAX_HTTP_HEADERS {
                        return Err(
                            "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n",
                        );
                    }
                    headers.insert(key.trim().to_lowercase(), value.trim().to_string());
                }
            }
        }
    }

    Ok((method, path, headers))
}
