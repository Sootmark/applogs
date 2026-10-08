//! Snort's and Suricata's fast alert logs (Snort 3's `alert_fast.txt`,
//! Snort 2's `alert`, Suricata's `fast.log`), one alert per line, local
//! time:
//!
//! ```text
//! 12/28-12:55:38.765402 [**] [1:366:11] "PROTOCOL-ICMP PING Unix" [**] [Priority: 3] {ICMP} 2001:df1:c200:c:0:0:0:35 -> 2001:4860:4860:0:0:0:0:8888
//! 10/05/10-10:08:59.667372  [**] [1:2009187:4] ET WEB_CLIENT ACTIVEX … [**] [Classification: Web Application Attack] [Priority: 3] {TCP} 11.11.232.144:80 -> 192.168.1.4:56068
//! ```
//!
//! The time is `MM/DD-hh:mm:ss.uuuuuu`, with the year first (`YY/`) when
//! Snort runs with `-y` and in Suricata's; without it the year is
//! inferred. Then the rule (generator, signature and revision), the
//! message (quoted by Snort 3), the classification and priority when the
//! rule has them, the protocol, and the source and destination, each with
//! its port when the protocol has ports (IPv6 too: the last group is the
//! port).

use std::net::IpAddr;

use crate::time::{date, undated, Anchor, Clock};
use crate::{digits, value_of, Context, Entry, Log};

/// Whether a line is a fast alert.
pub(crate) fn is_line(line: &str) -> bool {
    parse(line, 0).is_ok()
}

/// Read a fast alert log.
pub(crate) fn read(text: &str, context: Context) -> Log {
    let mut log = Log::default();
    let mut clocks = Vec::new();
    for (number, line) in crate::lines(text) {
        match parse(line, number) {
            Ok((entry, undated)) => {
                if let Some(clock) = undated {
                    clocks.push((log.entries.len(), clock));
                }
                log.entries.push(entry);
            }
            Err(why) => log.problem(number, &why),
        }
    }
    date(&mut log, &clocks, Anchor::end(context.modified));
    log
}

/// A line's entry, and its clock when the line has no year (the entry
/// is timed once the year is inferred).
fn parse(line: &str, number: usize) -> Result<(Entry, Option<Clock>), String> {
    let (stamp, rest) = line.split_once(' ').ok_or("no time")?;
    let (year, clock) = time(stamp).ok_or_else(|| format!("a time {stamp:?} not read"))?;
    let (mut entry, undated_clock) = match year {
        Some(year) => {
            let time = clock
                .local_in(year)
                .ok_or_else(|| format!("a time {stamp:?} not read"))?;
            let entry = Entry {
                line: number,
                time: Some(time),
                time_text: stamp.to_owned(),
                ..Entry::default()
            };
            (entry, None)
        }
        None => (undated(number, stamp), Some(clock)),
    };
    let rest = rest
        .trim_start()
        .strip_prefix("[**] [")
        .ok_or("no [**] [rule]")?;
    let (rule, rest) = rest.split_once(']').ok_or("no [rule]")?;
    entry.push("rule", rule);
    let (message, rest) = rest.split_once("[**]").ok_or("no [**] after the message")?;
    let message = message.trim();
    let message = message
        .strip_prefix('"')
        .and_then(|m| m.strip_suffix('"'))
        .unwrap_or(message);
    entry.message = value_of(message);
    let mut rest = rest.trim_start();
    while let Some((inside, after)) = rest.strip_prefix('[').and_then(|r| r.split_once(']')) {
        let (name, value) = inside.split_once(':').unwrap_or((inside, ""));
        entry.push(&name.trim().to_ascii_lowercase(), value);
        rest = after.trim_start();
    }
    let (protocol, rest) = rest
        .strip_prefix('{')
        .and_then(|r| r.split_once('}'))
        .ok_or("no {protocol}")?;
    entry.push("protocol", protocol);
    let (source, destination) = rest.split_once(" -> ").ok_or("no source -> destination")?;
    for (name, endpoint) in [("source", source), ("destination", destination)] {
        let (address, port) = endpoint_parts(endpoint.trim());
        entry.push(name, address);
        entry.push(&format!("{name}_port"), port);
    }
    Ok((entry, undated_clock))
}

/// `[YY/]MM/DD-hh:mm:ss.uuuuuu`: the year if written (20YY) and the
/// clock.
fn time(stamp: &str) -> Option<(Option<i64>, Clock)> {
    let (date, clock) = stamp.split_once('-')?;
    let parts: Vec<i64> = date
        .split('/')
        .map(|p| digits(p).filter(|_| p.len() == 2))
        .collect::<Option<_>>()?;
    let (year, month, day) = match parts[..] {
        [year, month, day] => (Some(2000 + year), month, day),
        [month, day] => (None, month, day),
        _ => return None,
    };
    Some((year, Clock::parse(month as u32, day as u32, clock)?))
}

/// An address and its port: `10.0.0.1:80`, `[2001:db8::1]:80`, or an
/// IPv6 address followed by `:port` (`2001:df1:c200:c:0:0:0:35:60884`).
fn endpoint_parts(text: &str) -> (&str, &str) {
    if let Some((address, port)) = text.strip_prefix('[').and_then(|t| t.split_once("]:")) {
        return (address, port);
    }
    if text.parse::<IpAddr>().is_ok() {
        return (text, "");
    }
    match text.rsplit_once(':') {
        Some((address, port)) if address.parse::<IpAddr>().is_ok() && digits(port).is_some() => {
            (address, port)
        }
        _ => (text, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert_eq!(endpoint_parts("10.6.6.254:80"), ("10.6.6.254", "80"));
        assert_eq!(
            endpoint_parts("2001:df1:c200:c:0:0:0:35"),
            ("2001:df1:c200:c:0:0:0:35", "")
        );
        assert_eq!(
            endpoint_parts("2001:df1:c200:c:0:0:0:35:60884"),
            ("2001:df1:c200:c:0:0:0:35", "60884")
        );
        assert_eq!(endpoint_parts("[2001:db8::1]:443"), ("2001:db8::1", "443"));
        assert_eq!(endpoint_parts("host"), ("host", ""));
    }

    #[test]
    fn years_written_or_not() {
        let line = "21/12/28-12:55:38.765402 [**] [1:366:11] PROTOCOL-ICMP PING Unix [**] [Priority: 3] {ICMP} 10.0.0.1 -> 10.0.0.2";
        let log = read(line, Context::default());
        assert_eq!(
            log.entries[0].time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2021-12-28T12:55:38.7654020")
        );
        assert!(!log.entries[0].year_inferred);
        let log = read(&line[3..], Context::default());
        assert_eq!(
            (log.entries[0].time, log.entries[0].year_inferred),
            (None, true)
        );
        assert_eq!(
            ["rule", "priority", "protocol", "source", "destination"]
                .map(|f| log.entries[0].get(f)),
            ["1:366:11", "3", "ICMP", "10.0.0.1", "10.0.0.2"].map(Some)
        );
        assert!(read(
            "12/28-12:55:38.765402 [**] [1:366:11] x",
            Context::default()
        )
        .entries
        .is_empty());
    }
}
