//! Terminal questions. Prompts go to stderr so `-o json` stays pipeable, and
//! a secret is read without echo.

use std::io::Write;

use anyhow::{Context, Result};

/// Ask for a value, offering `default` when the answer is empty.
pub fn ask(label: &str, default: &str) -> Result<String> {
    if default.is_empty() {
        eprint!("  {label}: ");
    } else {
        eprint!("  {label} [{default}]: ");
    }
    std::io::stderr().flush().ok();

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading from stdin")?;
    let line = line.trim().to_string();
    Ok(if line.is_empty() {
        default.to_string()
    } else {
        line
    })
}

/// Ask for a secret without echoing it.
pub fn ask_secret(label: &str) -> Result<String> {
    let v = rpassword::prompt_password(format!("  {label}: "))
        .context("reading the API key from the terminal")?;
    Ok(v.trim().to_string())
}
