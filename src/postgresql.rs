//! PostgreSQL's server log (`log_destination = stderr`, as the logging
//! collector writes `postgresql-*.log`), with the default prefix, `%m [%p]
//! ` (Debian's adds `%q%u@%d `):
//!
//! ```text
//! 2022-04-12 00:16:05.526 UTC [7755] LOG:  starting PostgreSQL 12.9 …
//! 2022-04-12 00:24:24.741 UTC [9158] postgres@postgres FATAL:  password authentication failed for user "postgres"
//! 2022-04-12 00:24:24.741 UTC [9158] postgres@postgres DETAIL:  User "postgres" has no password assigned.
//!         Connection matched pg_hba.conf line 96: "host all all 127.0.0.1/32 md5"
//! 2022-07-15 23:04:27 AEST [203851-1] user@databasename LOG:  could not receive data from client
//! ```
//!
//! The time is followed by `log_timezone`'s abbreviation: `UTC` (and
//! `GMT`) and numeric offsets (`+03`, `-0430`) give UTC; another name
//! (`AEST`, `CET`) is kept as written, the time local, for abbreviations
//! are ambiguous (`IST`, `CST`). The process id may carry the session's
//! line number (`%p-%l`). A line that doesn't start with a time continues
//! the message before it.

use crate::time::iso;
use crate::{value_of, Entry, Log};

/// Zone names that mean UTC.
const UTC_NAMES: [&str; 4] = ["UTC", "GMT", "UCT", "Z"];

/// Whether a line starts like a PostgreSQL log line.
pub(crate) fn is_line(line: &str) -> bool {
    parse(line, 0).is_ok()
}

/// Read a PostgreSQL log.
pub(crate) fn read(text: &str) -> Log {
    let mut log = Log::default();
    for (number, line) in crate::lines(text) {
        match parse(line, number) {
            Ok(entry) => log.entries.push(entry),
            Err(why) => match log.entries.last_mut() {
                Some(previous) if !starts_with_date(line) => {
                    let message = previous.message.get_or_insert_with(String::new);
                    message.push('\n');
                    message.push_str(line.trim_end());
                }
                _ => log.problem(number, &why),
            },
        }
    }
    log
}

/// Whether a line starts with a date, so isn't a continuation.
fn starts_with_date(line: &str) -> bool {
    line.get(..10)
        .is_some_and(|date| iso(&format!("{date} 00:00:00"), ' ').is_some())
}

fn parse(line: &str, number: usize) -> Result<Entry, String> {
    let mut words = line.splitn(4, ' ');
    let (Some(date), Some(clock), Some(zone), Some(rest)) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        return Err("no time, zone and process".to_owned());
    };
    let time_text = &line[..date.len() + clock.len() + zone.len() + 2];
    let (year, clock) = iso(&format!("{date} {clock}"), ' ')
        .ok_or_else(|| format!("a time {time_text:?} not read"))?;
    let local = clock
        .local_in(year)
        .ok_or_else(|| format!("a time {time_text:?} not read"))?;
    let mut entry = Entry {
        line: number,
        time_text: time_text.to_owned(),
        ..Entry::default()
    };
    entry.time = match zone_offset(zone) {
        Some(offset) => Some(local.assume_offset(offset)),
        None if zone.bytes().all(|b| b.is_ascii_alphabetic()) => {
            entry.push("zone", zone);
            Some(local)
        }
        None => return Err(format!("a zone {zone:?} not read")),
    };
    let (process, rest) = rest
        .strip_prefix('[')
        .and_then(|r| r.split_once("] "))
        .ok_or("no [process id]")?;
    let (pid, session_line) = process.split_once('-').unwrap_or((process, ""));
    entry.pid = Some(
        pid.parse()
            .map_err(|_| format!("a process id {process:?} not read"))?,
    );
    entry.push("session_line", session_line);
    let (head, message) = rest.split_once(':').ok_or("no severity")?;
    let (session, severity) = head.rsplit_once(' ').unwrap_or(("", head));
    let is_severity = !severity.is_empty()
        && severity
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    if !is_severity {
        return Err(format!("a severity {severity:?} not read"));
    }
    if let Some((user, database)) = session.split_once('@') {
        entry.user = value_of(user);
        entry.push("database", database);
    }
    entry.level = Some(severity.to_owned());
    entry.message = value_of(message);
    Ok(entry)
}

/// A zone's offset from UTC in minutes: 0 for UTC's names, or a numeric
/// offset (`+03`, `-0430`, `+05:30`).
fn zone_offset(zone: &str) -> Option<i32> {
    if UTC_NAMES.contains(&zone) {
        return Some(0);
    }
    let (sign, digits) = match zone.as_bytes().first()? {
        b'+' => (1, &zone[1..]),
        b'-' => (-1, &zone[1..]),
        _ => return None,
    };
    let digits = digits.replace(':', "");
    if !(digits.len() == 2 || digits.len() == 4) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i32 = digits[..2].parse().ok()?;
    let minutes: i32 = digits
        .get(2..)
        .filter(|m| !m.is_empty())
        .map_or(Some(0), |m| m.parse().ok())?;
    (hours < 24 && minutes < 60).then_some(sign * (hours * 60 + minutes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zones() {
        assert_eq!(zone_offset("UTC"), Some(0));
        assert_eq!(zone_offset("+03"), Some(180));
        assert_eq!(zone_offset("-04:30"), Some(-270));
        assert_eq!(zone_offset("AEST"), None);
        assert_eq!(zone_offset("+3"), None);
    }

    #[test]
    fn lines() {
        let utc = parse("2022-04-12 00:24:24.741 +02 [9158] postgres@postgres FATAL:  password authentication failed", 1).unwrap();
        assert_eq!(
            utc.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2022-04-11T22:24:24.7410000Z")
        );
        assert_eq!(
            (
                utc.user.as_deref(),
                utc.get("database"),
                utc.level.as_deref()
            ),
            (Some("postgres"), Some("postgres"), Some("FATAL"))
        );
        let named = parse("2022-07-15 23:04:27 AEST [203851-1] user@db LOG:  x", 2).unwrap();
        assert_eq!(
            named.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2022-07-15T23:04:27.0000000")
        );
        assert_eq!(
            (named.pid, named.get("session_line"), named.get("zone")),
            (Some(203_851), Some("1"), Some("AEST"))
        );
        assert!(parse("2022-04-12 00:24:24.741 UTC [x] LOG:  x", 3).is_err());
        assert!(parse("2022-04-12 00:24:24.741 UTC [1] log:  x", 4).is_err());
    }

    #[test]
    fn continuations() {
        let log = read("2022-04-12 00:24:24.741 UTC [9158] DETAIL:  a\n\tb\nstray\n");
        assert_eq!(log.entries[0].message.as_deref(), Some("a\n\tb\nstray"));
        let log = read("stray\n2022-04-12 00:24:24.741 UTC [x]\n");
        assert_eq!(log.problems.len(), 2);
    }
}
