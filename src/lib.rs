//! Application text logs, for forensics: who connected to the FTP server
//! and what they took, who failed to log in to the database, which
//! programs a Debian host last ran, what the IDS raised, what Santa let run
//! on a Mac and what its firewall let listen.
//!
//! - vsftpd's `vsftpd.log`: connections, logins, uploads and downloads.
//! - PostgreSQL's server log (`postgresql-*.log`, the default
//!   `log_line_prefix`): severity, process, user and database, message.
//! - Debian's popularity-contest log (`/var/log/popularity-contest`): each
//!   package's most recently used file, with its access and change times.
//! - Snort's and Suricata's fast alerts (`alert_fast.txt`, `fast.log`): the
//!   rule, message, classification, priority, protocol and addresses.
//! - Google logging (glog: `<program>.<host>.<user>.log.INFO.…`): level,
//!   thread, source file and line, message.
//! - Santa's `santa.log` (macOS): executions allowed or blocked, file
//!   writes, renames and deletions, disks appearing and processes exiting.
//! - macOS securityd's `security.log` and the application firewall's
//!   `appfirewall.log`.
//!
//! Times are read as each log writes them: in UTC where it says so (Santa,
//! popularity-contest, a PostgreSQL zone of `UTC`), otherwise as local
//! wall-clock times, the zone unknown. Logs that write no year (Snort
//! without `-y`, glog, securityd, the application firewall) have it
//! inferred, as `sootmark-syslog` does: lines are in order, so it goes up
//! when the month goes back; glog's header gives the first year, otherwise
//! the last line is dated in the year the file was last modified
//! ([`Context::modified`]), and without that the time is left unset, its
//! text kept.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let data = std::fs::read("/var/log/vsftpd.log")?;
//! if let Some(kind) = applogs::detect("vsftpd.log", &data) {
//!     for entry in applogs::read(kind, &data, applogs::Context::default()).entries {
//!         println!("{:?} {:?} {:?}", entry.time, entry.user, entry.message);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Text is read as UTF-8, invalid bytes replaced. Lines that can't be read
//! go to `problems`, never a panic.

mod appfirewall;
mod classic;
mod glog;
mod popcontest;
mod postgresql;
mod santa;
mod securityd;
mod snort;
mod time;
mod vsftpd;

use common::time::Ts;

/// This crate's version, for records of what parsed them.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A kind of application log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// vsftpd's `vsftpd.log`.
    Vsftpd,
    /// A PostgreSQL server log.
    PostgreSql,
    /// Debian's popularity-contest log.
    PopularityContest,
    /// Snort's or Suricata's fast alert log.
    SnortFast,
    /// A Google logging (glog) file.
    Glog,
    /// Santa's `santa.log`.
    Santa,
    /// macOS securityd's `security.log`.
    Securityd,
    /// The macOS application firewall's `appfirewall.log`.
    AppFirewall,
}

impl Kind {
    /// A short name (`vsftpd`, `postgresql`, `popularity_contest`,
    /// `snort_fast`, `glog`, `santa`, `securityd`, `appfirewall`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Vsftpd => "vsftpd",
            Self::PostgreSql => "postgresql",
            Self::PopularityContest => "popularity_contest",
            Self::SnortFast => "snort_fast",
            Self::Glog => "glog",
            Self::Santa => "santa",
            Self::Securityd => "securityd",
            Self::AppFirewall => "appfirewall",
        }
    }
}

/// What the file's metadata says, for what its lines don't.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    /// When the file was last modified (UTC): the year of its last line,
    /// for logs that write no year.
    pub modified: Option<Ts>,
}

/// An entry of a log: a line, and the lines continuing it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// Its first line, from 1.
    pub line: usize,
    /// When: UTC where the log says so, local (zone unknown) otherwise;
    /// `None` when the year couldn't be inferred.
    pub time: Option<Ts>,
    /// The time as written.
    pub time_text: String,
    /// Whether the year was inferred (logs that write none).
    pub year_inferred: bool,
    /// The host (glog's machine, the firewall's host name).
    pub host: Option<String>,
    /// The program that wrote it (`santad`, `secd`, `socketfilterfw`).
    pub program: Option<String>,
    /// Its process id.
    pub pid: Option<u32>,
    /// Its level or severity, as the log names it (`LOG`, `FATAL`, `INFO`,
    /// `Error`).
    pub level: Option<String>,
    /// The account concerned (vsftpd's, PostgreSQL's, Santa's).
    pub user: Option<String>,
    /// The entry's text.
    pub message: Option<String>,
    /// Other times it records, by name (popularity-contest's `ctime`, a
    /// session's `end`, a Santa disk's `appearance`).
    pub times: Vec<(&'static str, Ts)>,
    /// Every other value, by name.
    pub fields: Vec<(String, String)>,
}

impl Entry {
    /// A value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// Another time by name.
    #[must_use]
    pub fn time_of(&self, name: &str) -> Option<Ts> {
        self.times.iter().find(|(n, _)| *n == name).map(|(_, t)| *t)
    }

    /// Keep `value` under `name`, if not empty.
    fn push(&mut self, name: &str, value: &str) {
        if let Some(value) = value_of(value) {
            self.fields.push((name.to_owned(), value));
        }
    }
}

/// A log's entries and what couldn't be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Log {
    /// The entries, in order.
    pub entries: Vec<Entry>,
    /// The lines that couldn't be read, with why.
    pub problems: Vec<String>,
}

impl Log {
    /// Note that line `number` couldn't be read.
    fn problem(&mut self, number: usize, why: &str) {
        self.problems.push(format!("line {number}: {why}"));
    }
}

/// Whether a line is one of a log's.
type LineTest = fn(&str) -> bool;

/// Which log `head` (a file's first bytes) starts like, if any, by its
/// first line (glog: its header). The name isn't needed.
#[must_use]
pub fn detect(_name: &str, head: &[u8]) -> Option<Kind> {
    let text = String::from_utf8_lossy(head);
    let first = lines(&text).next().map(|(_, line)| line)?;
    let tests: [(Kind, LineTest); 8] = [
        (Kind::Vsftpd, vsftpd::is_line),
        (Kind::PostgreSql, postgresql::is_line),
        (Kind::PopularityContest, popcontest::is_line),
        (Kind::SnortFast, snort::is_line),
        (Kind::Glog, glog::is_line),
        (Kind::Santa, santa::is_line),
        (Kind::Securityd, securityd::is_line),
        (Kind::AppFirewall, appfirewall::is_line),
    ];
    tests
        .into_iter()
        .find(|(_, test)| test(first))
        .map(|(kind, _)| kind)
}

/// Read a log of `kind`.
#[must_use]
pub fn read(kind: Kind, data: &[u8], context: Context) -> Log {
    let text = String::from_utf8_lossy(data);
    let text = text.trim_start_matches('\u{feff}');
    match kind {
        Kind::Vsftpd => vsftpd::read(text),
        Kind::PostgreSql => postgresql::read(text),
        Kind::PopularityContest => popcontest::read(text),
        Kind::SnortFast => snort::read(text, context),
        Kind::Glog => glog::read(text, context),
        Kind::Santa => santa::read(text),
        Kind::Securityd => securityd::read(text, context),
        Kind::AppFirewall => appfirewall::read(text, context),
    }
}

/// The lines of `text` that aren't blank, each with its number (from 1), a
/// carriage return dropped.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split('\n')
        .enumerate()
        .map(|(index, line)| (index + 1, line.strip_suffix('\r').unwrap_or(line)))
        .filter(|(_, line)| !line.trim().is_empty())
}

/// Trimmed, empty meaning none.
fn value_of(text: &str) -> Option<String> {
    Some(text.trim())
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
}

/// A decimal number of up to 18 digits, nothing else.
fn digits(text: &str) -> Option<i64> {
    (!text.is_empty() && text.len() <= 18 && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}
