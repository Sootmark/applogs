//! vsftpd's own log (`vsftpd.log`, `vsftpd_log_file`), local time with a
//! year:
//!
//! ```text
//! Mon Jun  6 18:43:28 2016 [pid 2] CONNECT: Client "192.168.1.9"
//! Mon Jun  6 18:43:32 2016 [pid 1] [jean] OK LOGIN: Client "192.168.1.9"
//! Mon Jun  6 18:43:59 2016 [pid 3] [jean] OK UPLOAD: Client "192.168.1.9", "/home/jean/a.png", 1884648 bytes, 41264.44Kbyte/sec
//! Fri Jun 10 14:31:12 2016 [pid 3] [jean] FAIL DOWNLOAD: Client "192.168.1.7", "/home/jean/b.jpg", 0.00Kbyte/sec
//! ```
//!
//! After the process comes the account, once logged in, the result (`OK`,
//! `FAIL`) and the action (`LOGIN`, `UPLOAD`, `DOWNLOAD`, `MKDIR`,
//! `DELETE`, `RENAME`, and with `log_ftp_protocol` the `FTP command`s and
//! `FTP response`s), then the client's address, the path (or the command
//! or response), the bytes moved and the rate. The whole text after the
//! time is the message; its parts are fields.

use crate::time::{month, Clock};
use crate::{digits, value_of, Entry, Log};

/// Whether a line starts like a vsftpd log line.
pub(crate) fn is_line(line: &str) -> bool {
    parse(line, 0).is_ok_and(|entry| entry.pid.is_some())
}

/// Read a vsftpd log.
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
    let (words, rest) = words(line, 5).ok_or("no time")?;
    let time_text = line[..line.len() - rest.len()].trim_end();
    let [_, month_name, day, clock, year] = words[..] else {
        return Err("no time".to_owned());
    };
    let time = month(month_name)
        .zip(digits(day))
        .and_then(|(month, day)| Clock::parse(month, day as u32, clock))
        .zip(digits(year).filter(|_| year.len() == 4))
        .and_then(|(clock, year)| clock.local_in(year))
        .ok_or_else(|| format!("a time {time_text:?} not read"))?;
    let mut entry = Entry {
        line: number,
        time: Some(time),
        time_text: time_text.to_owned(),
        message: value_of(rest),
        ..Entry::default()
    };
    let mut rest = rest.trim();
    if let Some((pid, after)) =
        bracketed(rest).and_then(|(b, after)| Some((b.strip_prefix("pid ")?, after)))
    {
        entry.pid = pid.parse().ok();
        rest = after;
    }
    if let Some((user, after)) = bracketed(rest) {
        entry.user = value_of(user);
        rest = after;
    }
    let (head, details) = rest
        .split_once(": ")
        .unwrap_or((rest.trim_end_matches(':'), ""));
    let action = match head.split_once(' ') {
        Some((result @ ("OK" | "FAIL"), action)) => {
            entry.push("result", result);
            action
        }
        _ => head,
    };
    entry.push("action", action);
    let quoted_name = match action {
        "FTP command" => "command",
        "FTP response" => "response",
        _ => "path",
    };
    for part in parts(details) {
        if let Some(client) = part.strip_prefix("Client ") {
            entry.push("client", client.trim_matches('"'));
        } else if let Some(password) = part.strip_prefix("anon password ") {
            entry.push("anon_password", password.trim_matches('"'));
        } else if let Some(bytes) = part.strip_suffix(" bytes") {
            entry.push("bytes", bytes);
        } else if part.ends_with("/sec") {
            entry.push("rate", part);
        } else if part.starts_with('"') {
            entry.push(quoted_name, unquote(part));
        } else {
            entry.push("detail", part);
        }
    }
    Ok(entry)
}

/// The first `count` words of `line` and what follows them.
fn words(line: &str, count: usize) -> Option<(Vec<&str>, &str)> {
    let mut rest = line;
    let mut words = Vec::with_capacity(count);
    for _ in 0..count {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (word, after) = rest.split_at(end);
        if word.is_empty() {
            return None;
        }
        words.push(word);
        rest = after;
    }
    Some((words, rest))
}

/// `[inside] rest`: what's inside the brackets, and what follows them.
fn bracketed(text: &str) -> Option<(&str, &str)> {
    let (inside, after) = text.strip_prefix('[')?.split_once(']')?;
    Some((inside, after.trim_start()))
}

/// The comma-separated parts of the details, commas inside quotes kept.
fn parts(details: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (at, c) in details.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ',' if !quoted => {
                parts.push(details[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(details[start..].trim());
    parts.retain(|p| !p.is_empty());
    parts
}

/// A value without its surrounding quotes.
fn unquote(text: &str) -> &str {
    let text = text.strip_prefix('"').unwrap_or(text);
    text.strip_suffix('"').unwrap_or(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfers_and_commands() {
        let entry = parse(r#"Mon Jun  6 18:43:59 2016 [pid 3] [jean] OK UPLOAD: Client "192.168.1.9", "/home/jean/a, b.png", 1884648 bytes, 41264.44Kbyte/sec"#, 1).unwrap();
        assert_eq!((entry.pid, entry.user.as_deref()), (Some(3), Some("jean")));
        assert_eq!(
            ["result", "action", "client", "path", "bytes", "rate"].map(|f| entry.get(f)),
            [
                "OK",
                "UPLOAD",
                "192.168.1.9",
                "/home/jean/a, b.png",
                "1884648",
                "41264.44Kbyte/sec"
            ]
            .map(Some)
        );
        assert_eq!(entry.time_text, "Mon Jun  6 18:43:59 2016");
        let command = parse(
            r#"Sat Jul  1 10:00:00 2023 [pid 9] FTP command: Client "::1", "USER jean""#,
            2,
        )
        .unwrap();
        assert_eq!(
            (command.get("action"), command.get("command")),
            (Some("FTP command"), Some("USER jean"))
        );
        assert!(parse("Mon Jun 31 18:43:59 2016 [pid 3] CONNECT", 3).is_err());
        assert!(parse("Mon Jun  6 18:43:59", 4).is_err());
    }
}
