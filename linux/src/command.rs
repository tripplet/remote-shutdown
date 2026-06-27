use std::fmt::Display;

/// Command to execute
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub enum Command {
    /// Shutdown the system
    Shutdown,

    /// Forcibly shutdown the system
    AdminShutdown,

    /// Reboot the system
    Reboot,
}

impl std::str::FromStr for Command {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("shutdown") {
            Ok(Self::Shutdown)
        } else if s.eq_ignore_ascii_case("admin_shutdown") {
            Ok(Self::AdminShutdown)
        } else if s.eq_ignore_ascii_case("reboot") {
            Ok(Self::Reboot)
        } else {
            Err("Invalid command")
        }
    }
}

impl Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Shutdown => write!(f, "shutdown"),
            Command::AdminShutdown => write!(f, "admin_shutdown"),
            Command::Reboot => write!(f, "reboot"),
        }
    }
}

impl Command {
    #[cfg(target_os = "linux")]
    pub fn execute(self) -> Result<(), String> {
        let exit_status = match self {
            Command::Shutdown => std::process::Command::new("systemctl")
                .arg("poweroff")
                .spawn(),
            Command::AdminShutdown => std::process::Command::new("systemctl")
                .arg("poweroff")
                .arg("--force")
                .spawn(),
            Command::Reboot => std::process::Command::new("systemctl")
                .arg("reboot")
                .spawn(),
        };

        let exit_status = exit_status
            .map_err(|e| e.to_string())?
            .wait()
            .map_err(|e| e.to_string())?;

        if !exit_status.success() {
            return Err("Command failed".to_string());
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[expect(clippy::unused_self)]
    pub fn execute(self) -> Result<(), String> {
        Err("Command execution is only supported on Linux".to_string())
    }
}
