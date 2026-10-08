//! Google logging (glog, and Abseil's logging after it):
//! `<program>.<host>.<user>.log.<LEVEL>.<date>-<time>.<pid>`, local time,
//! a header, then one line per message:
//!
//! ```text
//! Log file created at: 2019/07/18 06:07:40
//! Running on machine: plasotest1
//! Binary: Built for gcc-4.X.Y
//! Log line format: [IWEF]mmdd hh:mm:ss.uuuuuu threadid file:line] msg
//! I1231 23:59:59.000003 12345 logging_functional_test_helper.py:70] Interesting Stuff
//!     that spans two lines
//! F1231 23:59:59.000004 12345 logging_functional_test_helper.py:75] This line is a fatal log
//! ```
//!
//! Each line has its level (`I`, `W`, `E`, `F`: info, warning, error,
//! fatal), month and day, time, thread id (padded), and the source file
//! and line that logged it. No year: the header's gives the first, which
//! goes up when the month goes back. The header itself is an entry: when
//! the file was created, on which machine, by which binary. A line that
//! isn't a message continues the one before.

use crate::time::{date, iso, undated, Anchor, Clock};
use crate::{digits, value_of, Context, Entry, Log};

const CREATED: &str = "Log file created at: ";
const MACHINE: &str = "Running on machine: ";

/// Whether a line starts a glog file (its header) or is a glog message.
pub(crate) fn is_line(line: &str) -> bool {
    created(line).is_some() || message(line, 0).is_some()
}

/// Read a glog file.
pub(crate) fn read(text: &str, context: Context) -> Log {
    let mut log = Log::default();
    let mut clocks = Vec::new();
    let mut anchor = Anchor::end(context.modified);
    let mut host = None;
    let mut in_header = false;
    for (number, line) in crate::lines(text) {
        if let Some((year, clock)) = created(line) {
            let mut header = Entry {
                line: number,
                time: clock.local_in(year),
                time_text: line[CREATED.len()..].trim().to_owned(),
                ..Entry::default()
            };
            header.message = value_of(line);
            anchor = Anchor::Start {
                year,
                month: clock.month,
            };
            log.entries.push(header);
            in_header = true;
        } else if let Some((entry, clock)) = message(line, number) {
            clocks.push((log.entries.len(), clock));
            log.entries.push(entry);
            in_header = false;
        } else if in_header {
            header_line(line, &mut host, log.entries.last_mut());
        } else if let Some(previous) = log.entries.last_mut() {
            let message = previous.message.get_or_insert_with(String::new);
            message.push('\n');
            message.push_str(line);
        } else {
            log.problem(number, "neither a header nor a message");
        }
    }
    for entry in &mut log.entries {
        entry.host.clone_from(&host);
    }
    date(&mut log, &clocks, anchor);
    log
}

/// `Log file created at: YYYY/MM/DD hh:mm:ss`.
fn created(line: &str) -> Option<(i64, Clock)> {
    let stamp = line.strip_prefix(CREATED)?.trim();
    iso(&stamp.replace('/', "-"), ' ')
}

/// A header line after the first: the machine, or another value
/// (`Binary`, `Running duration (h:mm:ss)`, `Log line format`) kept on
/// the header's entry.
fn header_line(line: &str, host: &mut Option<String>, header: Option<&mut Entry>) {
    if let Some(machine) = line.strip_prefix(MACHINE) {
        *host = value_of(machine);
        return;
    }
    let (name, value) = line.split_once(": ").unwrap_or((line, ""));
    let name: String = name
        .split(" (")
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_lowercase()
        .replace(' ', "_");
    if let Some(header) = header {
        header.push(&name, value);
    }
}

/// `Lmmdd hh:mm:ss.uuuuuu threadid file:line] msg`: the entry, its year
/// to come, and its clock.
fn message(line: &str, number: usize) -> Option<(Entry, Clock)> {
    let level = match line.get(..1)? {
        "I" => "INFO",
        "W" => "WARNING",
        "E" => "ERROR",
        "F" => "FATAL",
        _ => return None,
    };
    let date = line.get(1..5).filter(|d| digits(d).is_some())?;
    let rest = line.get(5..)?.strip_prefix(' ')?;
    let (clock_text, rest) = rest.split_once(' ')?;
    let month = digits(&date[..2])?;
    let day = digits(&date[2..])?;
    let clock = Clock::parse(month as u32, day as u32, clock_text)?;
    let (thread, rest) = rest
        .trim_start()
        .split_once(' ')
        .filter(|(thread, _)| digits(thread).is_some())?;
    let (source, text) = rest
        .split_once("] ")
        .or_else(|| Some((rest.strip_suffix(']')?, "")))?;
    let (file, source_line) = source
        .rsplit_once(':')
        .filter(|(_, line)| digits(line).is_some())?;
    let mut entry = undated(number, &line[1..5 + 1 + clock_text.len()]);
    entry.level = Some(level.to_owned());
    entry.message = Some(text.to_owned());
    entry.push("thread", thread);
    entry.push("file", file);
    entry.push("source_line", source_line);
    Some((entry, clock))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_and_messages() {
        let log = read(
            "Log file created at: 2019/07/18 06:07:40\n\
             Running on machine: host1\n\
             Running duration (h:mm:ss): 0:00:01\n\
             I1231 23:59:59.000003  1234 a.cc:70] two\n    lines\n\
             W0101 00:00:00.000001 1234 b.cc:7] next year\n",
            Context::default(),
        );
        assert!(log.problems.is_empty(), "{:?}", log.problems);
        let header = &log.entries[0];
        assert_eq!(
            header.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2019-07-18T06:07:40.0000000")
        );
        assert_eq!(header.get("running_duration"), Some("0:00:01"));
        let first = &log.entries[1];
        assert_eq!(
            (
                first.message.as_deref(),
                first.get("thread"),
                first.host.as_deref(),
                first.time_text.as_str()
            ),
            (
                Some("two\n    lines"),
                Some("1234"),
                Some("host1"),
                "1231 23:59:59.000003"
            )
        );
        assert_eq!(
            log.entries[2].time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2020-01-01T00:00:00.0000010")
        );
    }
}
