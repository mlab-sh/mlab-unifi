//! Progress rendering: spinner, status lines, elapsed time.
//!
//! Same three rules as the other mlab CLIs, because they are what keep the
//! output usable:
//!
//! 1. **Progress goes to stderr.** stdout carries the result, so
//!    `-o json | jq` stays parsable while a spinner is running.
//! 2. **Nothing is drawn unless stderr is a terminal.** Pipes, CI logs and
//!    tests get clean output with no escape sequences.
//! 3. **Nothing is drawn for fast work.** The spinner only appears once a call
//!    has run past `SHOW_AFTER`; a console on the LAN usually answers first.

pub mod render;

use std::future::Future;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use colored::Colorize;

const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const TICK: Duration = Duration::from_millis(80);
/// Work finishing faster than this never gets a spinner: the flash of one
/// appearing and vanishing reads as a glitch, not as feedback.
const SHOW_AFTER: Duration = Duration::from_millis(250);
const CLEAR_LINE: &str = "\r\x1b[2K";
const HIDE_CURSOR: &str = "\x1b[?25l";
const SHOW_CURSOR: &str = "\x1b[?25h";

static QUIET: AtomicBool = AtomicBool::new(false);
static ENABLED: AtomicBool = AtomicBool::new(false);
/// Set while the spinner may have written a partial line, so the error path
/// knows it has to wipe before printing.
static DIRTY: AtomicBool = AtomicBool::new(false);
/// The emergency brake: only the error path sets it, which is what makes
/// `restore()` safe to call from inside a running spinner.
static STOP_ALL: AtomicBool = AtomicBool::new(false);

/// Decide once, at startup, what this run may print.
///
/// Two separate questions: `--quiet` silences *everything* this module writes,
/// while a non-terminal stderr only rules out *animation* — a log still wants
/// the warnings.
pub fn init(quiet: bool) {
    let silenced = quiet || env_flag("MLAB_UNIFI_NO_PROGRESS");
    let animated = !silenced && !env_flag("CI") && std::io::stderr().is_terminal();
    QUIET.store(silenced, Ordering::SeqCst);
    ENABLED.store(animated, Ordering::SeqCst);
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !v.is_empty() && v != "0" && v != "false")
        .unwrap_or(false)
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::SeqCst)
}

pub fn quiet() -> bool {
    QUIET.load(Ordering::SeqCst)
}

/// Leave the terminal usable however the process ends — the error path exits
/// without unwinding, so no destructor would run.
pub fn restore() {
    STOP_ALL.store(true, Ordering::SeqCst);
    if DIRTY.load(Ordering::SeqCst) {
        // One tick, so the drawing thread cannot repaint the line after the wipe.
        thread::sleep(TICK + Duration::from_millis(20));
        clear_line();
    }
}

fn clear_line() {
    if DIRTY.swap(false, Ordering::SeqCst) {
        let mut err = std::io::stderr();
        let _ = write!(err, "{CLEAR_LINE}{SHOW_CURSOR}");
        let _ = err.flush();
    }
}

struct State {
    message: Mutex<String>,
    running: AtomicBool,
}

pub struct Spinner {
    state: Arc<State>,
    handle: Option<JoinHandle<()>>,
}

impl Spinner {
    pub fn start(message: impl Into<String>) -> Self {
        let state = Arc::new(State {
            message: Mutex::new(message.into()),
            running: AtomicBool::new(true),
        });
        let start = Instant::now();

        let handle = if enabled() {
            let state = Arc::clone(&state);
            Some(thread::spawn(move || animate(state, start)))
        } else {
            None
        };

        Self { state, handle }
    }

    /// Change what the line says, for work that moves through named steps.
    pub fn set(&self, message: impl Into<String>) {
        if let Ok(mut m) = self.state.message.lock() {
            *m = message.into();
        }
    }

    /// Stop drawing and wipe the line, leaving nothing behind.
    pub fn clear(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.state.running.store(false, Ordering::SeqCst);
        // Joining first guarantees the thread cannot repaint after the wipe.
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        clear_line();
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn animate(state: Arc<State>, start: Instant) {
    let mut frame = 0usize;
    let mut drawn = false;
    let mut err = std::io::stderr();

    while state.running.load(Ordering::SeqCst) && !STOP_ALL.load(Ordering::SeqCst) {
        if start.elapsed() >= SHOW_AFTER {
            if !drawn {
                DIRTY.store(true, Ordering::SeqCst);
                let _ = write!(err, "{HIDE_CURSOR}");
                drawn = true;
            }
            let message = state.message.lock().map(|m| m.clone()).unwrap_or_default();
            if STOP_ALL.load(Ordering::SeqCst) {
                break;
            }
            let _ = write!(
                err,
                "{CLEAR_LINE}  {} {}  {}",
                FRAMES[frame % FRAMES.len()].cyan(),
                message,
                elapsed(start.elapsed()).dimmed(),
            );
            let _ = err.flush();
            frame += 1;
        }
        thread::sleep(TICK);
    }
}

/// A status line, on stderr like everything else here.
pub fn note(marker: colored::ColoredString, message: &str) {
    if quiet() {
        return;
    }
    eprintln!("  {marker} {message}");
}

pub fn success(message: &str) {
    note("✔".green().bold(), message);
}

pub fn warning(message: &str) {
    note("!".yellow().bold(), message);
}

pub fn info(message: &str) {
    note("›".cyan().bold(), message);
}

pub fn elapsed(d: Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else if d.as_secs() < 60 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        format!("{}m{:02}s", d.as_secs() / 60, d.as_secs() % 60)
    }
}

/// Await `fut` behind a spinner. The line is wiped before the caller prints, so
/// progress and results never interleave.
pub async fn spin<T>(message: &str, fut: impl Future<Output = T>) -> T {
    let spinner = Spinner::start(message);
    let out = fut.await;
    spinner.clear();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests steer process-wide switches and the harness runs them in
    /// parallel: without this they race each other.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        STOP_ALL.store(false, Ordering::SeqCst);
        DIRTY.store(false, Ordering::SeqCst);
        g
    }

    #[test]
    fn elapsed_reads_as_ms_then_seconds_then_minutes() {
        assert_eq!(elapsed(Duration::from_millis(12)), "12ms");
        assert_eq!(elapsed(Duration::from_millis(1500)), "1.5s");
        assert_eq!(elapsed(Duration::from_secs(61)), "1m01s");
    }

    #[test]
    fn quiet_disables_drawing_whatever_the_terminal_says() {
        let _g = guard();
        init(true);
        assert!(quiet());
        assert!(!enabled());
    }

    #[test]
    fn a_spinner_still_runs_its_work_when_animation_is_off() {
        let _g = guard();
        init(true);
        let s = Spinner::start("working");
        s.clear();
        assert!(
            !STOP_ALL.load(Ordering::SeqCst),
            "a normal stop must not arm the brake"
        );
    }

    #[test]
    fn restore_is_safe_when_nothing_was_drawn() {
        let _g = guard();
        restore();
        restore();
    }
}
