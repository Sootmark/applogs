//! plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`):
//! every event plaso's parsers read from them (`tests/oracle/plaso.tsv`,
//! written from plaso's own output, see `tests/oracle/README`), read the
//! same, but where plaso is wrong or this crate reads more:
//!
//! - Years: plaso dates a year-less log's first line in the year of the
//!   file's earliest timestamp (here its modification, 2024-06-01), so a
//!   log that crosses New Year ends after it was last written. Here, as in
//!   `sootmark-syslog`, the last line is dated in the year the file was
//!   last modified (the year before when its month is later), the years
//!   counted back from there. And plaso ignores glog's header, which gives
//!   the year the file was created.
//! - A PostgreSQL time in Australian Eastern Standard Time (`AEST`): plaso
//!   reads it as Brisbane's; here the zone's abbreviation is kept and the
//!   time local, for abbreviations are ambiguous.
//! - Santa's disks with no appearance time (2001-01-01, the Cocoa epoch):
//!   plaso dates them then; here they have none.
//! - Beyond plaso: Santa's lines saying messages were dropped, a
//!   popularity-contest package without files, glog's header.

use std::io::Read;

use applogs::{Context, Entry, Kind, Log};
use common::time::Ts;

/// When the fixtures were last modified, as plaso was run on them.
const MODIFIED: i64 = 1_717_200_000; // 2024-06-01T00:00:00Z

/// The years plaso's dates are ahead of this crate's, per year-less file
/// (see above).
const YEARS_AHEAD: [(&str, i64); 4] = [
    ("appfirewall.log", 1),
    ("googlelog_test.INFO", 5),
    ("security.log", 2),
    ("snort3_alert_fast.log", 1),
];

/// Every fixture's name, kind and log.
fn fixtures() -> Vec<(String, Kind, Log)> {
    let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/plaso");
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n != "LICENSE" && n != "NOTICE")
        .collect();
    names.sort();
    let context = Context {
        modified: Some(Ts::from_unix_seconds(MODIFIED)),
    };
    names
        .into_iter()
        .map(|file| {
            let mut data = std::fs::read(format!("{folder}/{file}")).unwrap();
            let name = match file.strip_suffix(".gz") {
                Some(name) => {
                    data = gunzip(&data);
                    name.to_owned()
                }
                None => file,
            };
            let kind =
                applogs::detect(&name, &data).unwrap_or_else(|| panic!("{name}: not detected"));
            let log = applogs::read(kind, &data, context);
            (name, kind, log)
        })
        .collect()
}

fn gunzip(compressed: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    common::gzip::Decoder::new(compressed)
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// A time as the oracle writes it: ISO 8601, no zone, `years` later.
fn iso(time: Ts, years: i64) -> String {
    let text = time.to_iso8601().unwrap();
    let text = text.trim_end_matches('Z');
    let year: i64 = text[..4].parse().unwrap();
    format!("{}{}", year + years, &text[4..])
}

/// What plaso calls an entry's time, by its name here (`time` the main
/// one), and its parser.
fn plaso_time(kind: Kind, entry: &Entry, name: &str) -> (&'static str, &'static str) {
    let desc = match (kind, name) {
        (Kind::Vsftpd | Kind::Securityd | Kind::AppFirewall, _) => "Added Time",
        (Kind::PostgreSql, _) => "Recorded Time",
        (Kind::PopularityContest, "ctime") => "Metadata Modification Time",
        (Kind::PopularityContest, "end") => "End Time",
        (Kind::PopularityContest, _) if entry.get("session").is_some() => "Start Time",
        (Kind::PopularityContest, _) => "Last Access Time",
        (Kind::Santa, "appearance") => "First Connection Time",
        (Kind::Santa, _) => match entry.get("action") {
            Some("EXEC") => "Last Time Executed",
            Some("EXIT") => "Exit Time",
            _ => "Content Modification Time",
        },
        (Kind::SnortFast | Kind::Glog, _) => "Content Modification Time",
    };
    let parser = match kind {
        Kind::Vsftpd => "text/vsftpd",
        Kind::PostgreSql => "text/postgresql",
        Kind::PopularityContest => "text/popularity_contest",
        Kind::SnortFast => "text/snort_fastlog",
        Kind::Glog => "text/googlelog",
        Kind::Santa => "text/santa",
        Kind::Securityd => "text/mac_securityd",
        Kind::AppFirewall => "text/mac_appfirewall_log",
    };
    (desc, parser)
}

/// Santa's names and plaso's, per kind of line.
const SANTA_EXECUTION: [(&str, &str); 17] = [
    ("cert_cn", "certificate_common_name"),
    ("cert_sha256", "certificate_hash"),
    ("decision", "decision"),
    ("gid", "gid"),
    ("group", "group"),
    ("explain", "long_reason"),
    ("mode", "mode"),
    ("pid", "pid"),
    ("pidversion", "pid_version"),
    ("ppid", "ppid"),
    ("args", "process_arguments"),
    ("sha256", "process_hash"),
    ("path", "process_path"),
    ("quarantine_url", "quarantine_url"),
    ("reason", "reason"),
    ("uid", "uid"),
    ("user", "username"),
];
const SANTA_FILE: [(&str, &str); 11] = [
    ("newpath", "file_new_path"),
    ("path", "file_path"),
    ("gid", "gid"),
    ("group", "group"),
    ("pid", "pid"),
    ("pidversion", "pid_version"),
    ("ppid", "ppid"),
    ("process", "process"),
    ("processpath", "process_path"),
    ("uid", "uid"),
    ("user", "username"),
];
const SANTA_EXIT: [(&str, &str); 5] = [
    ("gid", "gid"),
    ("pid", "pid"),
    ("pidversion", "pid_version"),
    ("ppid", "ppid"),
    ("uid", "uid"),
];
const SANTA_DISK: [(&str, &str); 8] = [
    ("bsdname", "bsd_name"),
    ("bus", "bus"),
    ("dmgpath", "dmg_path"),
    ("fs", "fs"),
    ("model", "model"),
    ("mount", "mount"),
    ("serial", "serial"),
    ("volume", "volume"),
];

/// A value, plaso's name and ours.
type Pair = (&'static str, Option<String>);

/// An entry's values under plaso's names, sorted.
fn plaso_values(kind: Kind, e: &Entry) -> Vec<(String, String)> {
    let pairs = match kind {
        Kind::Vsftpd => vec![("text", e.message.clone())],
        Kind::PostgreSql => postgresql(e),
        Kind::PopularityContest => popularity_contest(e),
        Kind::SnortFast => snort(e),
        Kind::Glog => vec![
            ("filename", field(e, "file")),
            ("line_number", field(e, "source_line")),
            ("message_body", e.message.clone()),
            ("priority", e.level.as_ref().map(|l| l[..1].to_owned())),
            ("thread_identifier", field(e, "thread")),
        ],
        Kind::Santa => santa(e),
        Kind::Securityd => securityd(e),
        Kind::AppFirewall => vec![
            ("action", e.message.clone()),
            (
                "agent",
                e.program
                    .as_ref()
                    .zip(e.pid)
                    .map(|(program, pid)| format!("{program}[{pid}]")),
            ),
            ("hostname", e.host.clone()),
            ("process_name", field(e, "process")),
            ("status", e.level.clone()),
        ],
    };
    let mut values: Vec<(String, String)> = pairs
        .into_iter()
        .filter_map(|(name, value)| Some((name.to_owned(), value?)))
        .collect();
    values.sort();
    values
}

fn field(e: &Entry, name: &str) -> Option<String> {
    e.get(name).map(str::to_owned)
}

/// plaso joins the process id and session line, and the user and
/// database.
fn postgresql(e: &Entry) -> Vec<Pair> {
    let pid = e.pid.map(|pid| match e.get("session_line") {
        Some(line) => format!("{pid}-{line}"),
        None => pid.to_string(),
    });
    let user = e
        .user
        .as_ref()
        .map(|user| format!("{user}@{}", e.get("database").unwrap_or_default()));
    vec![
        ("message_body", e.message.clone()),
        ("pid", pid),
        ("severity", e.level.clone()),
        ("username", user),
    ]
}

/// plaso keeps a session header's values after the host as one text.
fn popularity_contest(e: &Entry) -> Vec<Pair> {
    if e.get("session").is_none() {
        return vec![
            ("mru", field(e, "path")),
            ("package", field(e, "package")),
            ("record_tag", field(e, "tag")),
        ];
    }
    let details = e
        .fields
        .iter()
        .filter(|(name, _)| name != "session" && name != "host_id")
        .map(|(name, value)| format!("{name}:{value}"))
        .collect::<Vec<_>>()
        .join(" ");
    vec![
        ("details", Some(details)),
        ("host_identifier", field(e, "host_id")),
        ("session", field(e, "session")),
    ]
}

fn snort(e: &Entry) -> Vec<Pair> {
    [
        ("classification", "classification"),
        ("destination_ip", "destination"),
        ("destination_port", "destination_port"),
        ("priority", "priority"),
        ("protocol", "protocol"),
        ("rule_identifier", "rule"),
        ("source_ip", "source"),
        ("source_port", "source_port"),
    ]
    .into_iter()
    .map(|(plaso, ours)| (plaso, field(e, ours)))
    .chain([("message_body", e.message.clone())])
    .collect()
}

fn santa(e: &Entry) -> Vec<Pair> {
    let names: &[(&str, &'static str)] = match e.get("action") {
        Some("EXEC") => &SANTA_EXECUTION,
        Some("EXIT") => &SANTA_EXIT,
        Some("DISKAPPEAR" | "DISKDISAPPEAR") => &SANTA_DISK,
        _ => &SANTA_FILE,
    };
    names
        .iter()
        .map(|(ours, plaso)| (*plaso, field(e, ours)))
        .chain([("action", field(e, "action"))])
        .collect()
}

/// plaso writes a repeat line's message as `Repeated <n> times: …`.
fn securityd(e: &Entry) -> Vec<Pair> {
    let message = match (e.get("repeated"), e.message.as_ref()) {
        (Some(count), Some(message)) => Some(format!("Repeated {count} times: {message}")),
        (_, message) => message.cloned(),
    };
    vec![
        ("caller", field(e, "caller")),
        ("facility", field(e, "facility")),
        ("level", e.level.clone()),
        ("message_body", message),
        ("security_api", field(e, "api")),
        ("sender", e.program.clone()),
        ("sender_pid", e.pid.map(|p| p.to_string())),
    ]
}

/// An entry's events, as the oracle's lines.
fn events(name: &str, kind: Kind, entry: &Entry) -> Vec<String> {
    let years = YEARS_AHEAD
        .iter()
        .find(|(file, _)| *file == name)
        .map_or(0, |(_, years)| *years);
    let values: Vec<String> = plaso_values(kind, entry)
        .into_iter()
        .map(|(name, value)| format!("{name}={}", value.replace('\n', "\\n").replace('\t', "\\t")))
        .collect();
    entry
        .time
        .map(|time| ("time", time))
        .into_iter()
        .chain(entry.times.iter().copied())
        .map(|(time_name, time)| {
            let (desc, parser) = plaso_time(kind, entry, time_name);
            [
                vec![
                    name.to_owned(),
                    iso(time, years),
                    desc.to_owned(),
                    parser.to_owned(),
                ],
                values.clone(),
            ]
            .concat()
            .join("\t")
        })
        .collect()
}

#[test]
fn every_event_as_plaso_reads_it() {
    let mut got: Vec<String> = Vec::new();
    let mut beyond: Vec<String> = Vec::new();
    for (name, kind, log) in fixtures() {
        for entry in &log.entries {
            let is_beyond = entry
                .message
                .as_deref()
                .is_some_and(|m| m.contains("QUOTA EXCEEDED"))
                || entry.get("tag") == Some("NOFILES")
                || (kind == Kind::Glog && entry.level.is_none());
            if is_beyond {
                beyond.push(format!("{name}:{}", entry.line));
            } else {
                got.extend(events(&name, kind, entry));
            }
        }
    }
    assert_eq!(
        beyond,
        [
            "googlelog_test.INFO:1",
            "popcontest1.log:14",
            "santa.log:16",
            "santa.log:101",
            "santa.log:150",
        ]
    );
    got.sort();
    let cocoa = "\t2001-01-01T00:00:00.0000000\tFirst Connection Time\t";
    let aest = "postgresql.log\t2022-07-15T13:04:27.0000000\t";
    let oracle = include_str!("oracle/plaso.tsv");
    assert_eq!(oracle.lines().filter(|l| l.contains(cocoa)).count(), 2);
    assert_eq!(oracle.lines().filter(|l| l.starts_with(aest)).count(), 1);
    let mut expected: Vec<String> = oracle
        .lines()
        .filter(|l| !l.contains(cocoa))
        .map(|l| l.replace(aest, "postgresql.log\t2022-07-15T23:04:27.0000000\t"))
        .collect();
    expected.sort();
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(g, e);
    }
    assert_eq!(got.len(), expected.len());
}

#[test]
fn every_line_is_read() {
    for (name, _, log) in fixtures() {
        assert_eq!(log.problems, Vec::<String>::new(), "{name}");
    }
}

#[test]
fn times_are_utc_only_where_the_log_says_so() {
    for (name, kind, log) in fixtures() {
        let utc = matches!(kind, Kind::Santa | Kind::PopularityContest);
        for entry in &log.entries {
            let time = entry.time.or(entry.times.first().map(|(_, t)| *t));
            let Some(time) = time else { continue };
            let is_utc = time.to_iso8601().unwrap().ends_with('Z');
            let postgres_utc = kind == Kind::PostgreSql && entry.get("zone").is_none();
            assert_eq!(is_utc, utc || postgres_utc, "{name}:{}", entry.line);
            let glog_header = kind == Kind::Glog && entry.level.is_none();
            let year_less = YEARS_AHEAD.iter().any(|(file, _)| *file == name) && !glog_header;
            assert_eq!(entry.year_inferred, year_less, "{name}:{}", entry.line);
        }
    }
}
