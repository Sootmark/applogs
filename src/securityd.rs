//! macOS securityd's `/var/log/security.log` (OS X 10.9 to 10.11), local
//! time without a year:
//!
//! ```text
//! Feb 26 19:11:56 secd[1] <Error> [user{} ]: securityd_xpc_dictionary_handler EscrowSecurityAl[3273] DeviceInCircle
//! Dec 26 19:11:59 secd[1111] <Error> [user{SOSCCThisDeviceIsInCircle} C0x7fff872fa482]: securityd_xpc_dictionary_handler …
//! Dec 24 01:21:47 --- last message repeated 3 time ---
//! ```
//!
//! The sender and its process id, the level (`<Error>`, `<Notice>`,
//! `<Debug>`), then in brackets the facility, the security API in braces
//! and the caller's addresses, and the message. A repeat line is an entry
//! of its own, the message repeated, its count in `repeated`. The year is
//! inferred.

use crate::classic::{self, stamp};
use crate::{value_of, Context, Entry, Log};

/// Whether a line is a securityd line.
pub(crate) fn is_line(line: &str) -> bool {
    stamp(line).is_some_and(|(_, _, rest)| parse(rest, &mut Entry::default()).is_ok())
}

/// Read a securityd log.
pub(crate) fn read(text: &str, context: Context) -> Log {
    classic::read(text, context, parse)
}

/// `sender[pid] <Level> [facility{api} caller]: message`.
fn parse(rest: &str, entry: &mut Entry) -> Result<(), String> {
    let (sender, rest) = rest.split_once('[').ok_or("no sender[pid]")?;
    let (pid, rest) = rest.split_once("] <").ok_or("no sender[pid] <level>")?;
    let (level, rest) = rest.split_once("> [").ok_or("no <level> [facility]")?;
    let (facility, rest) = rest.split_once('{').ok_or("no facility{")?;
    let (api, rest) = rest.split_once('}').ok_or("no {api}")?;
    let (caller, message) = rest.split_once("]:").ok_or("no ]: before the message")?;
    entry.program = value_of(sender);
    entry.pid = Some(
        pid.parse()
            .map_err(|_| format!("a process id {pid:?} not read"))?,
    );
    entry.level = value_of(level);
    entry.message = value_of(message);
    entry.push("facility", facility);
    entry.push("api", api);
    entry.push("caller", caller);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_and_repeats() {
        let june_2024 = Context {
            modified: Some(common::time::Ts::from_unix_seconds(1_717_200_000)),
        };
        let log = read(
            "Dec 24 01:21:47 --- last message repeated 3 time ---\n\
             Dec 26 19:11:59 secd[1111] <Error> [user{SOSCCThisDeviceIsInCircle} C0x7fff872fa482]: handler\n\
             Mar  1 00:00:01 secd[456] <Error> [user{} ]: Happy new year!\n\
             Mar  1 00:00:02 --- last message repeated 2 times ---\n",
            june_2024,
        );
        assert_eq!(log.problems, ["line 1: a repeat of no message"]);
        let first = &log.entries[0];
        assert_eq!(
            (
                first.program.as_deref(),
                first.pid,
                first.level.as_deref(),
                first.get("api"),
                first.get("caller")
            ),
            (
                Some("secd"),
                Some(1111),
                Some("Error"),
                Some("SOSCCThisDeviceIsInCircle"),
                Some("C0x7fff872fa482")
            )
        );
        assert_eq!(
            first.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2023-12-26T19:11:59.0000000")
        );
        let repeat = &log.entries[2];
        assert_eq!(
            (
                repeat.message.as_deref(),
                repeat.get("repeated"),
                repeat.pid,
                repeat.line
            ),
            (Some("Happy new year!"), Some("2"), Some(456), 4)
        );
        assert_eq!(
            repeat.time.and_then(|t| t.to_iso8601()).as_deref(),
            Some("2024-03-01T00:00:02.0000000")
        );
    }
}
