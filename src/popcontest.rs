//! Debian's popularity-contest log (`/var/log/popularity-contest`, what
//! `popularity-contest` reports each week), Unix times in UTC:
//!
//! ```text
//! POPULARITY-CONTEST-0 TIME:1277185301 ID:12345678901234567890123456789012 ARCH:i386 POPCONVER:1.38
//! 1277192082 1270556742 at /usr/sbin/atd
//! 1275197180 1275197263 empathy /usr/bin/empathy <RECENT-CTIME>
//! 1272987776 1272987590 nessus /usr/bin/nessus <OLD>
//! 0 0 freepats <NOFILES>
//! END-POPULARITY-CONTEST-0 TIME:1277185301
//! ```
//!
//! Between a session's header and footer, one line per installed package:
//! the access time (atime) and change time (ctime) of its most recently
//! used file, the package, that file (the message), and a tag: `<OLD>` (not used for a
//! month), `<RECENT-CTIME>` (changed about when last used: just
//! installed), `<NOFILES>` (no file to time). The access time is when a
//! program was last run or a library last loaded: the entry's time, the
//! change time kept as `ctime`; `0` means none. The header gives the
//! session's time, the host's identifier (`host_id`) and other values by
//! their names (`ARCH`, `POPCONVER`); the footer its end.

use common::time::Ts;

use crate::{digits, value_of, Entry, Log};

const HEADER: &str = "POPULARITY-CONTEST-";
const FOOTER: &str = "END-POPULARITY-CONTEST-";

/// Whether a line is a session's header.
pub(crate) fn is_line(line: &str) -> bool {
    header(line, 0).is_ok()
}

/// Read a popularity-contest log.
pub(crate) fn read(text: &str) -> Log {
    let mut log = Log::default();
    // The open session's number and its entry's index.
    let mut session: Option<(String, usize)> = None;
    for (number, line) in crate::lines(text) {
        let parsed = if line.starts_with(HEADER) {
            header(line, number).map(|entry| {
                session = entry
                    .get("session")
                    .map(|s| (s.to_owned(), log.entries.len()));
                Some(entry)
            })
        } else if line.starts_with(FOOTER) {
            footer(line, session.take(), &mut log).map(|()| None)
        } else {
            package(line, number).map(Some)
        };
        match parsed {
            Ok(Some(entry)) => log.entries.push(entry),
            Ok(None) => {}
            Err(why) => log.problem(number, &why),
        }
    }
    log
}

/// `POPULARITY-CONTEST-<n> TIME:<unix> ID:<host> KEY:value…`: a session's
/// entry, at its start.
fn header(line: &str, number: usize) -> Result<Entry, String> {
    let mut words = line.split_whitespace();
    let session = words
        .next()
        .and_then(|w| w.strip_prefix(HEADER))
        .and_then(|n| digits(n).map(|_| n))
        .ok_or("no session number")?;
    let time_text = words
        .next()
        .and_then(|w| w.strip_prefix("TIME:"))
        .ok_or("no TIME:")?;
    let host = words
        .next()
        .and_then(|w| w.strip_prefix("ID:"))
        .ok_or("no ID:")?;
    let mut entry = Entry {
        line: number,
        time: Some(unix(time_text).ok_or_else(|| format!("a time {time_text:?} not read"))?),
        time_text: time_text.to_owned(),
        ..Entry::default()
    };
    entry.push("session", session);
    entry.push("host_id", host);
    for word in words {
        let (name, value) = word.split_once(':').unwrap_or((word, ""));
        entry.push(name, value);
    }
    Ok(entry)
}

/// `END-POPULARITY-CONTEST-<n> TIME:<unix>`: the open session's end.
fn footer(line: &str, open: Option<(String, usize)>, log: &mut Log) -> Result<(), String> {
    let mut words = line.split_whitespace();
    let session = words
        .next()
        .and_then(|w| w.strip_prefix(FOOTER))
        .unwrap_or_default();
    let time_text = words
        .next()
        .and_then(|w| w.strip_prefix("TIME:"))
        .ok_or("no TIME:")?;
    let end = unix(time_text).ok_or_else(|| format!("a time {time_text:?} not read"))?;
    let index = open
        .filter(|(number, _)| number == session)
        .map(|(_, index)| index)
        .ok_or_else(|| format!("the end of session {session:?}, not the one open"))?;
    if let Some(entry) = log.entries.get_mut(index) {
        entry.times.push(("end", end));
    }
    Ok(())
}

/// `<atime> <ctime> <package> [<file>] [<tag>]`.
fn package(line: &str, number: usize) -> Result<Entry, String> {
    let mut words = line.splitn(3, ' ');
    let (Some(atime), Some(ctime), Some(rest)) = (words.next(), words.next(), words.next()) else {
        return Err("not a package's line".to_owned());
    };
    if digits(atime).is_none() || digits(ctime).is_none() {
        return Err("no access and change times".to_owned());
    }
    let (package, rest) = rest.trim().split_once(' ').unwrap_or((rest.trim(), ""));
    let (file, tag) = match rest.trim().rsplit_once('<') {
        Some((file, tag)) if tag.ends_with('>') => (file, tag.trim_end_matches('>')),
        _ => (rest, ""),
    };
    let mut entry = Entry {
        line: number,
        time: unix(atime),
        time_text: atime.to_owned(),
        ..Entry::default()
    };
    if let Some(ctime) = unix(ctime) {
        entry.times.push(("ctime", ctime));
    }
    entry.push("package", package);
    entry.push("path", file);
    entry.push("tag", tag);
    entry.message = value_of(file);
    Ok(entry)
}

/// Unix seconds, UTC; `0` (none) and times out of range are no time.
fn unix(text: &str) -> Option<Ts> {
    digits(text)
        .map(Ts::from_unix_seconds)
        .filter(|t| t.ticks().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions() {
        let log = read(
            "POPULARITY-CONTEST-0 TIME:1277185301 ID:abc ARCH:i386 POPCONVER:1.38\n\
             1277192082 1270556742 at /usr/sbin/atd\n\
             0 0 freepats <NOFILES>\n\
             1273651113 0 plaso /super/c\u{f3}\u{f3}l <WRONG_TAG>\n\
             END-POPULARITY-CONTEST-0 TIME:1277185302\n\
             END-POPULARITY-CONTEST-1 TIME:1277185302\n",
        );
        assert_eq!(
            log.problems,
            ["line 6: the end of session \"1\", not the one open"]
        );
        let session = &log.entries[0];
        assert_eq!(
            ["session", "host_id", "ARCH", "POPCONVER"].map(|f| session.get(f)),
            ["0", "abc", "i386", "1.38"].map(Some)
        );
        assert_eq!(
            session.time_of("end"),
            Some(Ts::from_unix_seconds(1_277_185_302))
        );
        let nofiles = &log.entries[2];
        assert_eq!(
            (nofiles.time, nofiles.get("package"), nofiles.get("tag")),
            (None, Some("freepats"), Some("NOFILES"))
        );
        let accented = &log.entries[3];
        assert_eq!(
            (accented.get("path"), accented.time_of("ctime")),
            (Some("/super/c\u{f3}\u{f3}l"), None)
        );
    }
}
