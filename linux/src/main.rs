mod command;
mod config;
mod crypto;
mod globals;
mod network;

fn main() {
    if std::env::args().any(|arg| arg == "--version") {
        println!(
            "remote-shutdown v{}-{}",
            env!("CARGO_PKG_VERSION"),
            env!("GIT_HASH")
        );
        return;
    }

    let config = config::Config::from_env();
    let handle = network::start_server(&config).unwrap();
    handle.join().unwrap();
}
