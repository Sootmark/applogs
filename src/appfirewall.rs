//! The macOS application firewall's `/var/log/appfirewall.log` (OS X up
//! to 10.11; later in the unified log), local time without a year:
//!
//! ```text
//! Nov  2 04:07:35 DarkTemplar-2.local socketfilterfw[112] <Error>: Logging: creating /var/log/appfirewall.log
//! Nov  2 04:07:35 DarkTemplar-2.local socketfilterfw[112] <Info>: Dropbox: Allow TCP LISTEN  (in:0 out:1)
//! Nov 11 22:44:00 DarkTemplar-2.local socketfilterfw[87] <Info>: Skype: Allow TCP CONNECT (in:1 out:0)
//! Nov 29 22:18:29 --- last message repeated 1 time ---
//! ```
//!
//! The host, the firewall's process (`socketfilterfw`) and id, the level,
//! the application concerned (`process`) and what was done (the message:
//! allowed or denied, the protocol, listening or connecting). A repeat
//! line is an entry of its own, the message repeated, its count in
//! `repeated`. The year is inferred.

use crate::classic::{self, stamp};
use crate::{value_of, Context, Entry, Log};

/// Whether a line is an application firewall line.
pub(crate) fn is_line(line: &str) -> bool {
    stamp(line).is_some_and(|(_, _, rest)| {
        parse(rest, &mut Entry::default()).is_ok() && rest.contains("socketfilterfw[")
    })
}

/// Read an application firewall log.
pub(crate) fn read(text: &str, context: Context) -> Log {
    classic::read(text, context, parse)
}

/// `host agent[pid] <Level>: process: what`.
fn parse(rest: &str, entry: &mut Entry) -> Result<(), String> {
    let (host, rest) = rest.split_once(' ').ok_or("no host")?;
    let (agent, rest) = rest.split_once('[').ok_or("no agent[pid]")?;
    let (pid, rest) = rest.split_once("] <").ok_or("no agent[pid] <level>")?;
    let (level, rest) = rest.split_once(">: ").ok_or("no <level>:")?;
    let (process, message) = rest
        .split_once(": ")
        .ok_or("no process: before the message")?;
    entry.host = value_of(host);
    entry.program = value_of(agent);
    entry.pid = Some(
        pid.parse()
            .map_err(|_| format!("a process id {pid:?} not read"))?,
    );
    entry.level = value_of(level);
    entry.message = value_of(message);
    entry.push("process", process);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_and_repeats() {
        let log = read(
            "Nov 29 22:17:30 host.local socketfilterfw[87] <Info>: Spotify: Allow TCP LISTEN  (in:0 out:1)\n\
             Nov 29 22:18:29 --- last message repeated 1 time ---\n\
             Nov 29 22:18:30 host.local socketfilterfw[x] <Info>: Spotify: y\n",
            Context::default(),
        );
        assert_eq!(log.problems, ["line 3: a process id \"x\" not read"]);
        let first = &log.entries[0];
        assert_eq!(
            (
                first.host.as_deref(),
                first.program.as_deref(),
                first.get("process"),
                first.message.as_deref()
            ),
            (
                Some("host.local"),
                Some("socketfilterfw"),
                Some("Spotify"),
                Some("Allow TCP LISTEN  (in:0 out:1)")
            )
        );
        assert_eq!((first.time, first.year_inferred), (None, true));
        assert_eq!(log.entries[1].get("repeated"), Some("1"));
    }
}
