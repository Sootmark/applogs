# applogs

Application text logs, for forensics: who connected to the FTP server and what they took, who failed to log in to the database, which programs a Debian host last ran, what the IDS raised, what Santa let run on a Mac and what its firewall let listen. One dependency, its sibling `sootmark-common` (times).

```toml
[dependencies]
sootmark-applogs = "0.1"
```

```rust
let data = std::fs::read("/var/log/vsftpd.log")?;
if let Some(kind) = applogs::detect("vsftpd.log", &data) {
    for entry in applogs::read(kind, &data, applogs::Context::default()).entries {
        println!("{:?} {:?} {:?}", entry.time, entry.user, entry.message);
    }
}
```

## What you get

- `detect(name, head)`: the log, from its first line (glog: its header).
- vsftpd's `vsftpd.log`: connections, logins, uploads, downloads, directories made, deletions and renames, each with its process, account, result (`OK`, `FAIL`), client, path, bytes and rate; with `log_ftp_protocol`, the commands and responses.
- PostgreSQL's server log with the default prefix (`%m [%p] `, Debian's `%q%u@%d `): severity, process (and session line), user and database, the message with its continuation lines (`DETAIL`, `HINT`, statements).
- Debian's popularity-contest log: each package's most recently used file, its access time (when a program last ran) and change time, its tag (`<OLD>`, `<RECENT-CTIME>`, `<NOFILES>`); each session's start and end, host identifier and architecture.
- Snort's and Suricata's fast alerts: rule, message, classification, priority, protocol, source and destination with their ports (IPv6 too).
- Google logging (glog): level, thread, source file and line, message (several lines too); the header's creation time, machine and binary.
- Santa's `santa.log`: executions allowed or blocked (decision, reason, hashes, signer, command line), file writes, renames, links and deletions, processes exiting, disks appearing (with when) and disappearing, each value by Santa's name; the lines saying messages were dropped.
- macOS securityd's `security.log` and the application firewall's `appfirewall.log`: sender, level, facility, security API and caller; the application allowed or denied, and how; repeat lines as entries of their own.
- Each as an `Entry`: time, the time as written, host, program, pid, level, user, message, other times by name (`ctime`, `end`, `appearance`) and the rest by name. Lines that can't be read go to `problems`, never a panic.

## Times

As each log writes them: UTC where it says so (Santa; popularity-contest's Unix times; PostgreSQL's `UTC` or a numeric offset), otherwise local wall-clock times, the zone unknown, never passed off as UTC; a PostgreSQL zone abbreviation (`AEST`) is kept, for abbreviations are ambiguous. Logs without a year (Snort without `-y`, glog, securityd, the application firewall) have it inferred and marked, as `sootmark-syslog` does: lines are in order, so it goes up when the month goes back; glog's header gives the first year, otherwise the last line is dated in the year the file was last modified (`Context::modified`), and without that the time is left unset, its text kept.

Not yet: vsftpd's `xferlog` format, PostgreSQL's other prefixes, CSV and JSON logs, Santa's protobuf logs.

## How it's checked

- plaso's test logs (Apache-2.0, `tests/fixtures/plaso/`, see `NOTICE`): every one of the 358 events plaso's parsers read from them, read the same (`tests/oracle/`), but where plaso is wrong: the years of logs that cross New Year (plaso dates the first line in the year of the file's earliest timestamp, so they end after the file was last written) and of glog (plaso ignores the header's year); a PostgreSQL time in `AEST`, which plaso takes for Brisbane's; and two Santa disks dated 2001-01-01 by plaso, Santa's zero. Beyond plaso: a package without files, glog's header, Santa's dropped-messages lines.
- Property tests: arbitrary text and bytes, and lines cut anywhere, give entries, problems or nothing, never a panic.

## Licence

MIT or Apache-2.0, at your option.
