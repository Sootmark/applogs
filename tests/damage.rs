//! Any input gives entries, problems or nothing, never a panic.

use applogs::{Context, Kind};
use common::time::Ts;
use proptest::prelude::*;

const KINDS: [Kind; 8] = [
    Kind::Vsftpd,
    Kind::PostgreSql,
    Kind::PopularityContest,
    Kind::SnortFast,
    Kind::Glog,
    Kind::Santa,
    Kind::Securityd,
    Kind::AppFirewall,
];

/// One line of each log, to cut anywhere.
const LINES: [&str; 9] = [
    r#"Mon Jun  6 18:43:59 2016 [pid 3] [jean] OK UPLOAD: Client "192.168.1.9", "/home/jean/a.png", 1884648 bytes, 41264.44Kbyte/sec"#,
    "2022-07-15 23:04:27.123 +05:30 [203851-1] user@databasename LOG:  could not receive data from client",
    "POPULARITY-CONTEST-0 TIME:1277185301 ID:12345678901234567890123456789012 ARCH:i386 POPCONVER:1.38\n1277192082 1270556742 at /usr/sbin/atd <OLD>\nEND-POPULARITY-CONTEST-0 TIME:1277185301",
    "21/12/28-12:55:38.765402 [**] [1:366:11] \"PING\" [**] [Classification: x] [Priority: 3] {TCP} [2001:db8::1]:80 -> 10.0.0.1:443",
    "Log file created at: 2019/07/18 06:07:40\nRunning on machine: h\nI1231 23:59:59.000003 12345 a.py:70] x",
    "[2022-02-09T16:47:01.893Z] I santad: action=EXEC|decision=ALLOW|pid=75780|user=root|args=/bin/ps -x|y",
    "Dec 26 19:11:59 secd[1111] <Error> [user{SOSCCThisDeviceIsInCircle} C0x7fff872fa482]: handler\nDec 26 19:12:00 --- last message repeated 3 time ---",
    "Nov  2 04:07:35 host.local socketfilterfw[112] <Info>: Dropbox: Allow TCP LISTEN  (in:0 out:1)",
    "Feb 29 04:07:35 host.local socketfilterfw[112] <Info>: Dropbox: leap",
];

fn contexts() -> [Context; 4] {
    [
        Context::default(),
        Context {
            modified: Some(Ts::from_unix_seconds(1_717_200_000)),
        },
        Context {
            modified: Some(Ts::from_unix_seconds(i64::MAX)),
        },
        Context {
            modified: Some(Ts::from_unix_seconds(-62_000_000_000)),
        },
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_text(text in "[ -~\t\n|\\[\\]{}<>\"/:=@*.-]{0,600}") {
        for kind in KINDS {
            for context in contexts() {
                let _ = applogs::read(kind, text.as_bytes(), context);
            }
        }
        let _ = applogs::detect("x.log", text.as_bytes());
    }

    #[test]
    fn arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..1500)) {
        for kind in KINDS {
            let _ = applogs::read(kind, &data, Context::default());
        }
        let _ = applogs::detect("x.log", &data);
    }

    #[test]
    fn lines_cut_anywhere(cut in 0usize..300, extra in "[ -~é]{0,8}") {
        for line in LINES {
            let mut text = line.as_bytes()[..cut.min(line.len())].to_vec();
            text.extend_from_slice(extra.as_bytes());
            for kind in KINDS {
                for context in contexts() {
                    let _ = applogs::read(kind, &text, context);
                }
            }
            let _ = applogs::detect("x.log", &text);
        }
    }
}

#[test]
fn every_kind_reads_its_own_line() {
    let june_2024 = contexts()[1];
    for (kind, line) in KINDS.iter().zip(LINES) {
        assert_eq!(applogs::detect("x", line.as_bytes()), Some(*kind), "{line}");
        let log = applogs::read(*kind, line.as_bytes(), june_2024);
        assert!(log.problems.is_empty(), "{kind:?}: {:?}", log.problems);
        assert!(log.entries.iter().all(|e| e.time.is_some()), "{kind:?}");
    }
}

#[test]
fn a_date_missing_from_the_inferred_year_is_reported() {
    let june_2025 = Context {
        modified: Some(Ts::from_unix_seconds(1_748_736_000)),
    };
    let log = applogs::read(Kind::AppFirewall, LINES[8].as_bytes(), june_2025);
    assert_eq!(
        log.problems,
        ["line 1: Feb 29 04:07:35 isn't a date in 2025 (the inferred year)"]
    );
    assert_eq!(log.entries[0].time, None);
}
