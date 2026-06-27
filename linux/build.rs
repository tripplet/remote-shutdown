fn main() {
    // Get get git commit hash
    let git_hash = std::process::Command::new("git")
        .arg("describe")
        .arg("--always")
        .arg("--tags")
        .arg("--dirty")
        .output()
        .unwrap()
        .stdout;

    let git_hash = String::from_utf8_lossy(&git_hash).trim().to_string();

    // 2. Set the environment variable for compile-time
    println!("cargo:rustc-env=GIT_HASH={git_hash}");
}
