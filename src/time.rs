//! Times as the logs write them, and the years of those that write none.

use common::time::{civil_from_days, days_from_civil, Precision, Ts};

use crate::{digits, Entry, Log};

pub(crate) const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
/// The most fraction digits a tick (100 ns) holds.
const TICK_DIGITS: usize = 7;
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// A month's number from its English abbreviation (`Jan` is 1).
pub(crate) fn month(name: &str) -> Option<u32> {
    MONTHS
        .iter()
        .position(|m| m.eq_ignore_ascii_case(name))
        .map(|at| at as u32 + 1)
}

/// A date and time of day whose year may not be known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Clock {
    pub(crate) month: u32,
    pub(crate) day: u32,
    /// Ticks since midnight.
    ticks: i64,
    precision: Precision,
}

impl Clock {
    /// A clock from its parts, `fraction` the digits after the second's
    /// point (empty for none); `None` when a part is out of range.
    pub(crate) fn new(
        month: u32,
        day: u32,
        clock: (i64, i64, i64),
        fraction: &str,
    ) -> Option<Self> {
        let (hour, minute, second) = clock;
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || !(0..24).contains(&hour)
            || !(0..60).contains(&minute)
            || !(0..=60).contains(&second)
        {
            return None;
        }
        let (sub, precision) = fraction_ticks(fraction)?;
        Some(Self {
            month,
            day,
            ticks: (hour * 3600 + minute * 60 + second) * TICKS_PER_SECOND + sub,
            precision,
        })
    }

    /// `hh:mm:ss` and the fraction after it (`hh:mm:ss.uuuuuu`).
    pub(crate) fn parse(month: u32, day: u32, text: &str) -> Option<Self> {
        let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
        let mut parts = whole.split(':');
        let mut next = || parts.next().filter(|p| p.len() == 2).and_then(digits);
        let clock = (next()?, next()?, next()?);
        if parts.next().is_some() {
            return None;
        }
        Self::new(month, day, clock, fraction)
    }

    /// The time in `year`, local; `None` if the date isn't one that year
    /// (February 29).
    pub(crate) fn local_in(self, year: i64) -> Option<Ts> {
        self.ticks_in(year)
            .map(|ticks| Ts::from_local_ticks(ticks, self.precision))
    }

    /// The time in `year`, UTC.
    pub(crate) fn utc_in(self, year: i64) -> Option<Ts> {
        self.ticks_in(year)
            .map(|ticks| Ts::from_ticks(ticks, self.precision))
    }

    fn ticks_in(self, year: i64) -> Option<i64> {
        if !(1..=9999).contains(&year) || self.day > days_in_month(year, self.month) {
            return None;
        }
        Some(days_from_civil(year, self.month, self.day) * TICKS_PER_DAY + self.ticks)
    }
}

/// `YYYY-MM-DD` and `hh:mm:ss[.fraction]` (or `T` between them, as
/// `separator` says) as a clock and its year.
pub(crate) fn iso(text: &str, separator: char) -> Option<(i64, Clock)> {
    let (date, clock) = text.split_once(separator)?;
    let mut date = date.split('-');
    let mut next = |width: usize| date.next().filter(|p| p.len() == width).and_then(digits);
    let (year, month, day) = (next(4)?, next(2)?, next(2)?);
    if date.next().is_some() {
        return None;
    }
    Some((year, Clock::parse(month as u32, day as u32, clock)?))
}

/// Ticks of a second's fraction (`526`, `667372`), and its precision.
fn fraction_ticks(fraction: &str) -> Option<(i64, Precision)> {
    if fraction.is_empty() {
        return Some((0, Precision::Second));
    }
    if fraction.len() > TICK_DIGITS || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ticks = format!("{fraction:0<TICK_DIGITS$}").parse().ok()?;
    let precision = match fraction.len() {
        1..=3 => Precision::Millisecond,
        4..=6 => Precision::Microsecond,
        _ => Precision::Tick,
    };
    Some((ticks, precision))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Where the years of year-less times come from.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Anchor {
    /// The first time is at or after this year and month (glog's header).
    Start { year: i64, month: u32 },
    /// The last time is in the year of this one, or the year before when
    /// its month is later (the file's last modification).
    End(Option<Ts>),
}

impl Anchor {
    /// The last line's year from the file's modification time, if known.
    pub(crate) fn end(modified: Option<Ts>) -> Self {
        Self::End(modified)
    }
}

/// Date the year-less `clocks` (an entry's index and its clock, in file
/// order): the year goes up whenever the month goes back. Entries left
/// untimed when the anchor is unknown; a date that doesn't exist in its
/// year (February 29) reported.
pub(crate) fn date(log: &mut Log, clocks: &[(usize, Clock)], anchor: Anchor) {
    let mut relative = Vec::with_capacity(clocks.len());
    let mut year = 0i64;
    let mut previous = match anchor {
        Anchor::Start { month, .. } => Some(month),
        Anchor::End(_) => None,
    };
    for (_, clock) in clocks {
        if previous.is_some_and(|p| clock.month < p) {
            year += 1;
        }
        previous = Some(clock.month);
        relative.push(year);
    }
    let Some(base) = base_year(anchor, clocks.last().map(|(_, c)| c.month), year) else {
        return;
    };
    for ((index, clock), relative) in clocks.iter().zip(relative) {
        let year = base + relative;
        let Some(entry) = log.entries.get_mut(*index) else {
            continue;
        };
        entry.time = clock.local_in(year);
        if entry.time.is_none() {
            let why = format!(
                "{} isn't a date in {year} (the inferred year)",
                entry.time_text
            );
            let line = entry.line;
            log.problem(line, &why);
        }
    }
}

/// The year of the first clock: the start's, or the end's less the years
/// the file spans.
fn base_year(anchor: Anchor, last_month: Option<u32>, span: i64) -> Option<i64> {
    match anchor {
        Anchor::Start { year, .. } => Some(year),
        Anchor::End(modified) => {
            let days = modified?.ticks()?.div_euclid(TICKS_PER_DAY);
            let (year, month, _) = civil_from_days(days);
            let last_year = if last_month? <= month { year } else { year - 1 };
            Some(last_year - span)
        }
    }
}

/// An entry stamped with a year-less clock, its year to come.
pub(crate) fn undated(line: usize, time_text: &str) -> Entry {
    Entry {
        line,
        time_text: time_text.to_owned(),
        year_inferred: true,
        ..Entry::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso_of(time: Option<Ts>) -> Option<String> {
        time.and_then(|t| t.to_iso8601())
    }

    #[test]
    fn clocks() {
        let clock = Clock::parse(12, 28, "12:55:38.765402").unwrap();
        assert_eq!(
            iso_of(clock.local_in(2021)).as_deref(),
            Some("2021-12-28T12:55:38.7654020")
        );
        assert_eq!(Clock::parse(12, 28, "24:00:00"), None);
        assert_eq!(Clock::parse(12, 28, "12:5:38"), None);
        assert_eq!(Clock::parse(12, 28, "12:55:38.12345678"), None);
        assert_eq!(
            Clock::parse(2, 29, "00:00:00").unwrap().local_in(2023),
            None
        );
        let (year, clock) = iso("2022-04-12 00:16:05.526", ' ').unwrap();
        assert_eq!(
            iso_of(clock.utc_in(year)).as_deref(),
            Some("2022-04-12T00:16:05.5260000Z")
        );
        assert_eq!(month("dec"), Some(12));
        assert_eq!(month("Dez"), None);
    }

    fn dated(months: &[u32], anchor: Anchor) -> Vec<Option<String>> {
        let mut log = Log::default();
        let mut clocks = Vec::new();
        for (index, &month) in months.iter().enumerate() {
            log.entries.push(undated(index + 1, "x"));
            clocks.push((index, Clock::parse(month, 1, "00:00:00").unwrap()));
        }
        date(&mut log, &clocks, anchor);
        log.entries
            .iter()
            .map(|e| iso_of(e.time).map(|t| t[..7].to_owned()))
            .collect()
    }

    #[test]
    fn inferred_years() {
        let june_2024 = Ts::from_unix_seconds(1_717_200_000);
        assert_eq!(
            dated(&[12, 1, 2], Anchor::end(Some(june_2024))),
            ["2023-12", "2024-01", "2024-02"].map(|t| Some(t.to_owned()))
        );
        assert_eq!(
            dated(&[11, 12], Anchor::end(Some(june_2024))),
            ["2023-11", "2023-12"].map(|t| Some(t.to_owned()))
        );
        assert_eq!(dated(&[3], Anchor::end(None)), [None]);
        assert_eq!(
            dated(
                &[12, 1],
                Anchor::Start {
                    year: 2019,
                    month: 7
                }
            ),
            ["2019-12", "2020-01"].map(|t| Some(t.to_owned()))
        );
        assert_eq!(
            dated(
                &[3],
                Anchor::Start {
                    year: 2019,
                    month: 7
                }
            ),
            [Some("2020-03".to_owned())]
        );
    }
}
