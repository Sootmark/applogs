//! What macOS's older text logs share with classic syslog: a time without
//! a year (`Nov  2 04:07:35`, the day padded with a space), and the line
//! syslogd writes in place of repeats (`--- last message repeated 3 times
//! ---`): an entry of its own, a copy of the one repeated at its own time,
//! with the count in `repeated`.

use crate::time::{date, month, undated, Anchor, Clock};
use crate::{digits, Context, Entry, Log};

/// Read a log of such lines, `parse` reading what follows the time into
/// an entry; the years inferred.
pub(crate) fn read(
    text: &str,
    context: Context,
    parse: fn(&str, &mut Entry) -> Result<(), String>,
) -> Log {
    let mut log = Log::default();
    let mut clocks = Vec::new();
    let mut last: Option<Entry> = None;
    for (number, line) in crate::lines(text) {
        let Some((time_text, clock, rest)) = stamp(line) else {
            log.problem(number, "no time");
            continue;
        };
        let parsed = match (repeated(rest), &last) {
            (Some(count), Some(last)) => {
                let mut entry = Entry {
                    line: number,
                    time_text: time_text.to_owned(),
                    ..last.clone()
                };
                entry.push("repeated", &count.to_string());
                Ok(entry)
            }
            (Some(_), None) => Err("a repeat of no message".to_owned()),
            (None, _) => {
                let mut entry = undated(number, time_text);
                parse(rest, &mut entry).map(|()| {
                    last = Some(entry.clone());
                    entry
                })
            }
        };
        match parsed {
            Ok(entry) => {
                clocks.push((log.entries.len(), clock));
                log.entries.push(entry);
            }
            Err(why) => log.problem(number, &why),
        }
    }
    date(&mut log, &clocks, Anchor::end(context.modified));
    log
}

/// The length of `Mmm dd hh:mm:ss`.
const STAMP_LENGTH: usize = 15;

/// A line's year-less time, as written and read, and the rest after the
/// space that follows it.
pub(crate) fn stamp(line: &str) -> Option<(&str, Clock, &str)> {
    let text = line.get(..STAMP_LENGTH)?;
    let rest = line.get(STAMP_LENGTH..)?.strip_prefix(' ')?;
    let month = month(text.get(..3)?)?;
    let day = text.get(4..6)?.trim_start();
    let day = digits(day).filter(|_| text.get(3..4) == Some(" "))?;
    let clock = Clock::parse(month, day as u32, text.get(7..)?)?;
    (text.get(6..7) == Some(" ")).then_some((text, clock, rest))
}

/// How many times the previous message was repeated, if `rest` (what
/// follows the time) says so.
pub(crate) fn repeated(rest: &str) -> Option<u32> {
    let count = rest
        .trim()
        .strip_prefix("--- last message repeated ")?
        .strip_suffix(" ---")?;
    let count = count
        .strip_suffix(" times")
        .or_else(|| count.strip_suffix(" time"))?;
    digits(count).and_then(|n| u32::try_from(n).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps() {
        let (text, clock, rest) = stamp("Nov  2 04:07:35 host x[1]: y").unwrap();
        assert_eq!(
            (text, clock.month, clock.day, rest),
            ("Nov  2 04:07:35", 11, 2, "host x[1]: y")
        );
        assert!(stamp("Feb 26 19:11:56 secd[1]").is_some());
        assert!(stamp("Feb 26 19:11:56").is_none());
        assert!(stamp("Foo 26 19:11:56 x").is_none());
        assert!(stamp("Feb 2619:11:56 x").is_none());
        assert!(stamp("Fé 26 19:11:56 x").is_none());
    }

    #[test]
    fn repeats() {
        assert_eq!(repeated("--- last message repeated 3 time ---"), Some(3));
        assert_eq!(repeated("--- last message repeated 12 times ---"), Some(12));
        assert_eq!(repeated("--- last message repeated x times ---"), None);
        assert_eq!(repeated("host prog[1]: hello"), None);
    }
}
