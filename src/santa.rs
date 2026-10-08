//! Santa's log (`/var/db/santa/santa.log`, macOS), UTC to the
//! millisecond, values between `|`:
//!
//! ```text
//! [2018-08-19T03:10:45.966Z] I santad: action=EXEC|decision=ALLOW|reason=CERT|sha256=…|cert_sha256=…|cert_cn=Software Signing|pid=479|ppid=1|uid=0|user=root|gid=0|group=wheel|mode=M|path=/usr/libexec/xpcproxy|args=xpcproxy com.apple.Safari
//! [2022-02-17T16:30:05.253Z] I santad: action=RENAME|path=/private/var/db/santa/santa.log.5.gz|newpath=…|pid=26150|…|process=newsyslog|processpath=/usr/sbin/newsyslog|uid=0|user=root|gid=0|group=wheel
//! [2018-08-19T03:09:13.120Z] I santad: action=DISKAPPEAR|mount=/|volume=HDD|bsdname=disk1s1|fs=apfs|model=…|serial=…|bus=PCI|dmgpath=|appearance=2018-08-19T03:09:08.425Z
//! [2018-08-19T03:13:12.253Z] *** LOG MESSAGE QUOTA EXCEEDED - SOME MESSAGES FROM THIS PROCESS HAVE BEEN DISCARDED ***
//! ```
//!
//! The action (`EXEC` with its decision, `WRITE`, `RENAME`, `LINK`,
//! `DELETE`, `EXIT`, `DISKAPPEAR`, `DISKDISAPPEAR`, …) and every value are
//! fields, by Santa's names; the account, process id and level (`I`, `W`,
//! `E`, `D`) have their places. A disk's appearance is another time,
//! unless it is Santa's zero (2001-01-01T00:00:00Z, the Cocoa epoch: not
//! known). A value can hold `|` (a command line's): a piece that isn't
//! `name=value` belongs to the value before. A line Santa writes when it
//! drops messages is kept, its text as the message.

use common::time::Ts;

use crate::time::iso;
use crate::{value_of, Entry, Log};

/// The time Santa writes for a disk that didn't say when it appeared.
const COCOA_EPOCH: &str = "2001-01-01T00:00:00.000Z";

/// Whether a line is a Santa log line.
pub(crate) fn is_line(line: &str) -> bool {
    parse(line, 0).is_ok_and(|entry| entry.program.is_some())
}

/// Read a Santa log.
pub(crate) fn read(text: &str) -> Log {
    let mut log = Log::default();
    for (number, line) in crate::lines(text) {
        match parse(line, number) {
            Ok(entry) => log.entries.push(entry),
            Err(why) => log.problem(number, &why),
        }
    }
    log
}

fn parse(line: &str, number: usize) -> Result<Entry, String> {
    let (stamp, rest) = line
        .strip_prefix('[')
        .and_then(|l| l.split_once("] "))
        .ok_or("no [time]")?;
    let mut entry = Entry {
        line: number,
        time: Some(utc(stamp).ok_or_else(|| format!("a time {stamp:?} not read"))?),
        time_text: stamp.to_owned(),
        ..Entry::default()
    };
    let Some((head, values)) = rest.split_once(": ") else {
        entry.message = value_of(rest);
        return Ok(entry);
    };
    let (level, program) = head.split_once(' ').ok_or("no level and program")?;
    entry.level = Some(
        spelled(level)
            .ok_or_else(|| format!("a level {level:?} not read"))?
            .to_owned(),
    );
    entry.program = value_of(program);
    for (name, value) in pairs(values) {
        match name {
            "user" => entry.user = value_of(value),
            "pid" => entry.pid = value.parse().ok(),
            "appearance" if value != COCOA_EPOCH => {
                if let Some(appearance) = utc(value) {
                    entry.times.push(("appearance", appearance));
                }
            }
            _ => {}
        }
        entry.push(name, value);
    }
    Ok(entry)
}

/// The `name=value` pairs between `|`, a piece without `=` (or whose name
/// isn't a name) joined to the value before.
fn pairs(text: &str) -> Vec<(&str, &str)> {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    let mut start = 0;
    for (at, piece) in pieces(text) {
        let is_pair = piece.split_once('=').is_some_and(|(name, _)| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        });
        match pairs.last_mut() {
            Some((_, value)) if !is_pair => {
                *value = &text[start..at + piece.len()];
            }
            _ => {
                let (name, value) = piece.split_once('=').unwrap_or((piece, ""));
                start = at + name.len() + 1;
                pairs.push((name, value));
            }
        }
    }
    pairs
}

/// The pieces of `text` between `|`, each with where it starts.
fn pieces(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split('|').scan(0, |at, piece| {
        let start = *at;
        *at += piece.len() + 1;
        Some((start, piece))
    })
}

/// `2018-08-19T03:09:13.120Z`.
fn utc(text: &str) -> Option<Ts> {
    let (year, clock) = iso(text.strip_suffix('Z')?, 'T')?;
    clock.utc_in(year)
}

/// Santa's level letters, spelled out.
fn spelled(level: &str) -> Option<&'static str> {
    Some(match level {
        "I" => "INFO",
        "W" => "WARNING",
        "E" => "ERROR",
        "D" => "DEBUG",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_holding_bars() {
        let entry = parse(
            "[2022-02-09T16:47:01.893Z] I santad: action=EXEC|decision=ALLOW|pid=7|user=root|path=/bin/sh|args=sh -c ps|grep x | wc -l",
            1,
        )
        .unwrap();
        assert_eq!(entry.get("args"), Some("sh -c ps|grep x | wc -l"));
        assert_eq!(
            (entry.pid, entry.user.as_deref(), entry.level.as_deref()),
            (Some(7), Some("root"), Some("INFO"))
        );
        assert_eq!(
            entry.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2022-02-09T16:47:01.8930000Z")
        );
    }

    #[test]
    fn disks_and_dropped_messages() {
        let disk = parse("[2018-08-19T03:09:13.592Z] I santad: action=DISKAPPEAR|mount=/net|volume=|serial=(null)|appearance=2001-01-01T00:00:00.000Z", 1).unwrap();
        assert_eq!(
            (disk.times.len(), disk.get("volume"), disk.get("serial")),
            (0, None, Some("(null)"))
        );
        let quota = parse(
            "[2018-08-19T03:13:12.253Z] *** LOG MESSAGE QUOTA EXCEEDED ***",
            2,
        )
        .unwrap();
        assert_eq!(
            quota.message.as_deref(),
            Some("*** LOG MESSAGE QUOTA EXCEEDED ***")
        );
        assert!(parse("[2018-08-19] I santad: x=1", 3).is_err());
    }
}
