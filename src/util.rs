//! Small helpers: hashing, time formatting, logging, address helpers.

use md5::{Digest, Md5};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub fn md5_hex(data: &str) -> String {
    let digest = Md5::digest(data.as_bytes());
    let mut s = String::with_capacity(32);
    for b in digest {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn md5_bytes(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// Wall-clock time (seconds since 1970). Only for what must survive a
/// restart (the state file, nonces) or is shown to people (logs, Date):
/// it jumps when NTP sets the clock, e.g. on a Raspberry Pi without RTC
/// that booted with the time of its last shutdown.
pub fn now_unix() -> u64 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    #[cfg(test)]
    let t = t.saturating_add_signed(test_clock::WALL.with(|c| c.get()));
    t
}

/// Monotonic time for everything that expires in memory (registrations):
/// unaffected by changes of the wall clock.
pub fn mono_now() -> Instant {
    let now = Instant::now();
    #[cfg(test)]
    let now = now + test_clock::MONO.with(|c| c.get());
    now
}

/// Simulated time for tests, per test thread (each test runs in its own):
/// `advance` lets time pass on both clocks, `step_wall` only sets the wall
/// clock, like NTP or an administrator does.
#[cfg(test)]
pub mod test_clock {
    use std::cell::Cell;
    use std::time::Duration;

    thread_local! {
        pub static MONO: Cell<Duration> = const { Cell::new(Duration::ZERO) };
        pub static WALL: Cell<i64> = const { Cell::new(0) };
    }

    pub fn advance(secs: u64) {
        MONO.with(|c| c.set(c.get() + Duration::from_secs(secs)));
        step_wall(secs as i64);
    }

    pub fn step_wall(secs: i64) {
        WALL.with(|c| c.set(c.get() + secs));
    }
}

#[cfg(test)]
pub use test_dir::TestDir;

/// A fresh directory for a test's files, removed again when it goes out of
/// scope: also when the test fails.
#[cfg(test)]
mod test_dir {
    use std::path::{Path, PathBuf};

    pub struct TestDir(PathBuf);

    impl TestDir {
        pub fn create() -> TestDir {
            let dir = std::env::temp_dir().join(format!("tiny-pbx-test-{}", super::random_hex()));
            std::fs::create_dir(&dir).unwrap();
            TestDir(dir)
        }
    }

    impl std::ops::Deref for TestDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// 16 random bytes as hex, from /dev/urandom (falls back to time + pid).
pub fn random_hex() -> String {
    use std::io::Read;
    let mut buf = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf.iter().map(|b| format!("{:02x}", b)).collect();
        }
    }
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    md5_hex(&format!("{}:{}", t, std::process::id()))
}

/// Convert days since 1970-01-01 to (year, month, day). (Howard Hinnant's algorithm)
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// RFC 1123 date as used in the SIP Date header, e.g. "Sat, 13 Nov 2010 23:29:00 GMT".
pub fn http_date(unix: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAYS[(days % 7) as usize],
        d,
        MONTHS[(m - 1) as usize],
        y,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

pub fn log_time(unix: u64) -> String {
    let (y, m, d) = civil_from_days((unix / 86_400) as i64);
    let s = unix % 86_400;
    format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        s / 3600,
        (s % 3600) / 60,
        s % 60
    )
}

// ---------------------------------------------------------------- logging

pub const ERROR: u8 = 0;
pub const WARN: u8 = 1;
pub const INFO: u8 = 2;
pub const DEBUG: u8 = 3;

static LEVEL: AtomicU8 = AtomicU8::new(INFO);

pub fn set_log_level(l: u8) {
    LEVEL.store(l, Ordering::Relaxed);
}

pub fn log_enabled(l: u8) -> bool {
    #[cfg(test)]
    if (l <= INFO || test_log::debug()) && test_log::capturing() {
        return true;
    }
    l <= LEVEL.load(Ordering::Relaxed)
}

pub fn log_write(l: u8, args: std::fmt::Arguments) {
    let tag = match l {
        ERROR => "ERROR",
        WARN => "WARN ",
        INFO => "INFO ",
        _ => "DEBUG",
    };
    let text = for_log(&args.to_string(), l >= DEBUG);
    #[cfg(test)]
    if test_log::capture(format!("{} {}", tag, text)) {
        return;
    }
    // Not eprintln!, which panics if stderr cannot be written (whatever read
    // it is gone: `| tee`, journald): better to go on serving without a log.
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "{} {} {}", log_time(now_unix()), tag, text);
}

/// Make a log message safe to print: control characters (ESC, CR, ...)
/// and invisible bidirectional-text controls in it, which may come from
/// any packet, are escaped, so they can neither forge log lines nor play
/// tricks on a terminal. Line breaks are kept only in `multiline` (debug)
/// messages, i.e. the packet dumps, whose credential headers (including
/// folded lines) are replaced by "…": they would allow trying passwords
/// offline. Redaction is deliberately conservative: header-looking text is
/// hidden even in a body or after leading CRLF keep-alives.
pub fn for_log(text: &str, multiline: bool) -> String {
    let mut out = String::with_capacity(text.len());
    let mut credentials = false;
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            if multiline {
                out.push('\n');
            } else {
                out.push_str("\\n");
            }
        }
        let line = match multiline {
            true => line.strip_suffix('\r').unwrap_or(line),
            false => line,
        };
        if multiline {
            if credentials && line.starts_with([' ', '\t']) {
                let value = line.trim_start_matches([' ', '\t']);
                out.push_str(&line[..line.len() - value.len()]);
                out.push('…');
                continue;
            } else {
                credentials = false;
                if let Some((name, _)) = line.split_once(':') {
                    if name.trim().eq_ignore_ascii_case("Authorization")
                        || name.trim().eq_ignore_ascii_case("Proxy-Authorization")
                    {
                        escape_into(&mut out, name);
                        out.push_str(": …");
                        credentials = true;
                        continue;
                    }
                }
            }
        }
        escape_into(&mut out, line);
    }
    out
}

fn needs_escape(c: char) -> bool {
    c.is_control() || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '\t' => out.push(c),
            c if needs_escape(c) && (c as u32) < 0x80 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if needs_escape(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
}

/// Text from a packet (a user name, URI, User-Agent, ...) for a log line or
/// the terminal: control characters escaped, cut to about 100 characters.
pub fn clip(s: &str) -> Clip<'_> {
    Clip(s)
}

pub struct Clip<'a>(&'a str);

/// Characters of packet text shown in a log line.
pub const CLIP: usize = 100;

impl std::fmt::Display for Clip<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut out = String::new();
        let mut chars = self.0.chars();
        let head: String = chars.by_ref().take(CLIP).collect();
        escape_into(&mut out, &head);
        if chars.next().is_some() {
            out.push('…');
        }
        f.write_str(&out)
    }
}

/// Log lines (info and above) of the current test thread, independent of
/// the global log level that other tests set.
#[cfg(test)]
pub mod test_log {
    use std::cell::RefCell;

    thread_local! {
        static LINES: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
        static DEBUG: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    pub fn start() {
        LINES.with(|l| *l.borrow_mut() = Some(Vec::new()));
        DEBUG.with(|d| d.set(false));
    }

    /// Like `start`, including debug messages (packet dumps).
    pub fn start_debug() {
        start();
        DEBUG.with(|d| d.set(true));
    }

    pub(super) fn debug() -> bool {
        DEBUG.with(|d| d.get())
    }

    /// The lines logged since `start` or the last `take`.
    pub fn take() -> Vec<String> {
        LINES.with(|l| l.borrow_mut().as_mut().map(std::mem::take).unwrap_or_default())
    }

    pub(super) fn capturing() -> bool {
        LINES.with(|l| l.borrow().is_some())
    }

    pub(super) fn capture(line: String) -> bool {
        LINES.with(|l| l.borrow_mut().as_mut().map(|v| v.push(line)).is_some())
    }
}

#[macro_export]
macro_rules! log {
    ($lvl:expr, $($t:tt)*) => {
        if $crate::util::log_enabled($lvl) {
            $crate::util::log_write($lvl, format_args!($($t)*))
        }
    };
}

// ---------------------------------------------------------------- addresses

/// Which of our local addresses would the kernel use to reach `dst`?
/// (UDP "connect" does a route lookup without sending anything.)
pub fn local_ip_for(dst: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match dst {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let s = UdpSocket::bind(bind).ok()?;
    s.connect(SocketAddr::new(dst, 9)).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// All addresses currently assigned to this host's interfaces.
#[allow(unsafe_code)] // getifaddrs: std has no wrapper
pub fn interface_ips() -> Vec<IpAddr> {
    let mut out = Vec::new();
    // SAFETY: plain getifaddrs()/freeifaddrs() walk. Every pointer read
    // comes from the list libc made, is null-checked, and is only read
    // before the list is freed; ifa_addr is read as a sockaddr_in/_in6 only
    // once its family says it is one.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut p = ifap;
        while !p.is_null() {
            let a = (*p).ifa_addr;
            if !a.is_null() {
                match (*a).sa_family as libc::c_int {
                    libc::AF_INET => {
                        let sin = &*(a as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(a as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}

/// An address/prefix pair, e.g. 192.168.0.0/16.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cidr {
    pub net: IpAddr,
    pub len: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let (ip, len) = match s.trim().split_once('/') {
            Some((ip, len)) => (
                ip.trim().parse::<IpAddr>().ok()?,
                Some(len.trim().parse::<u8>().ok()?),
            ),
            None => (s.trim().parse::<IpAddr>().ok()?, None),
        };
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let len = len.unwrap_or(max);
        (len <= max).then_some(Cidr { net: ip, len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        fn bits(ip: IpAddr) -> (u128, u8) {
            match ip {
                IpAddr::V4(v4) => (u32::from(v4) as u128, 32),
                IpAddr::V6(v6) => (u128::from(v6), 128),
            }
        }
        let ((a, wa), (b, wb)) = (bits(self.net), bits(ip));
        if wa != wb {
            return false;
        }
        if self.len == 0 {
            return true;
        }
        let shift = (wa - self.len) as u32;
        (a >> shift) == (b >> shift)
    }
}

/// Default for `allow`: loopback, private, link-local and CGNAT ranges.
pub const PRIVATE_NETS: &str =
    "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, ::1/128, fc00::/7, fe80::/10";

/// Host part as it appears in a SIP URI / Via (IPv6 in brackets).
pub fn fmt_host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{}]", v6),
    }
}

/// Parse a URI/Via host into an IP if it's a literal.
pub fn parse_ip_host(host: &str) -> Option<IpAddr> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    h.parse().ok()
}

/// host:port as a socket address if host is an IP literal. There is
/// deliberately no DNS: lookups would block the only thread, and phones on a
/// LAN use IP addresses in Contact/Via anyway.
pub fn ip_addr(host: &str, port: u16) -> Option<SocketAddr> {
    parse_ip_host(host).map(|ip| SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1289690940), "Sat, 13 Nov 2010 23:29:00 GMT");
        assert_eq!(http_date(1709251199), "Thu, 29 Feb 2024 23:59:59 GMT");
        assert_eq!(log_time(951782400), "2000-02-29 00:00:00");
    }

    #[test]
    fn md5() {
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn local() {
        let ips = interface_ips();
        assert!(ips.iter().any(|ip| ip.is_loopback()));
        for other in ["203.0.113.77", "224.0.0.1", "255.255.255.255"] {
            assert!(!ips.contains(&other.parse().unwrap()), "{other}");
        }
    }

    #[test]
    fn log_text_is_escaped_and_clipped() {
        let evil = "\u{1b}[2K\r2025-01-01 00:00:00 INFO 101 registered\u{1b}]0;pwned\u{7}\u{202e}x";
        let line = for_log(&format!("call {} -> 102\nWARN fake", evil), false);
        assert!(!line.chars().any(needs_escape), "{line}");
        assert_eq!(line.lines().count(), 1);
        assert!(line.starts_with("call \\x1b[2K\\x0d2025-01-01"), "{line}");
        assert!(line.contains("\\u{202e}x -> 102\\nWARN fake"), "{line}");
        // debug packet dumps keep their lines, without CRs
        let dump = for_log("<<< 3 bytes from x\nINVITE a SIP/2.0\r\nX: \u{1b}\r\n\r\n", true);
        assert_eq!(dump, "<<< 3 bytes from x\nINVITE a SIP/2.0\nX: \\x1b\n\n");
        let long = "é".repeat(5000);
        let c = clip(&long).to_string();
        assert_eq!(c.chars().count(), CLIP + 1);
        assert!(c.ends_with('…'));
        assert_eq!(clip("101").to_string(), "101");
        assert_eq!(clip("a\u{1b}b").to_string(), "a\\x1bb");
    }

    #[test]
    fn credential_headers_are_redacted_in_packet_dumps() {
        let dump = "REGISTER sip:pbx SIP/2.0\r\n\
            Authorization: Digest username=\"101\", realm=\"pbx\", nonce=\"abc\", uri=\"sip:pbx\", \
            response=\"0123456789abcdef0123456789abcdef\", qop=auth, nc=00000001, cnonce=\"x\"\r\n\
            pRoXy-aUtHoRiZaTiOn:Digest response=fedcba9876543210fedcba9876543210,username=\"response=1\"\r\n\
            Authorization: Digest username=\"a\\\"response=\\\"x\", response = \"0123456789abcdef0123456789abcdef\"\r\n\
            X-Response: response=\"keep\"\r\n\r\n";
        assert_eq!(
            for_log(dump, true),
            "REGISTER sip:pbx SIP/2.0\nAuthorization: …\npRoXy-aUtHoRiZaTiOn: …\nAuthorization: …\n\
             X-Response: response=\"keep\"\n\n"
        );
        assert_eq!(
            for_log(
                "<<< packet\n\r\nREGISTER sip:pbx SIP/2.0\r\nAuthorization: secret\r\n response=secret\r\n",
                true
            ),
            "<<< packet\n\nREGISTER sip:pbx SIP/2.0\nAuthorization: …\n …\n"
        );
        for odd in [
            "Authorization: é responseé=1 éresponse",
            "Authorization: x response=\"\\é",
            "Authorization:",
        ] {
            assert_eq!(for_log(odd, true), "Authorization: …");
        }
    }

    #[test]
    fn folded_credentials_are_redacted_but_not_the_next_header() {
        let dump = concat!(
            "<<< packet\nREGISTER sip:pbx SIP/2.0\r\n",
            "aUtHoRiZaTiOn: Digest username=\"101\",\r\n",
            " response=\"secret\",\r\n",
            "\t nonce=\"é\\\"unclosed\r\n",
            "Via: visible\r\n",
            "\tordinary continuation\r\n",
            "Proxy-Authorization:\r\n",
            "\tresponse=another-secret\r\n",
            "  cnonce=é\r\n",
            "X-Next: visible\u{202e}\x1b\r\n",
            "\r\n",
            "Authorization: body text\r\n",
            " response=not-a-header\r\n",
            "body\x00\u{2066}\r\n",
        );
        assert_eq!(
            for_log(dump, true),
            concat!(
                "<<< packet\nREGISTER sip:pbx SIP/2.0\n",
                "aUtHoRiZaTiOn: …\n …\n\t …\n",
                "Via: visible\n\tordinary continuation\n",
                "Proxy-Authorization: …\n\t…\n  …\n",
                "X-Next: visible\\u{202e}\\x1b\n\n",
                "Authorization: …\n …\n",
                "body\\x00\\u{2066}\n",
            )
        );
    }

    #[test]
    fn cidr() {
        let c = Cidr::parse("192.168.130.0/24").unwrap();
        assert!(c.contains("192.168.130.77".parse().unwrap()));
        assert!(!c.contains("192.168.131.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("10.1.2.3")
            .unwrap()
            .contains("10.1.2.3".parse().unwrap()));
        assert!(Cidr::parse("fc00::/7")
            .unwrap()
            .contains("fd12::1".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        for n in PRIVATE_NETS.split(',') {
            assert!(Cidr::parse(n).is_some(), "{}", n);
        }
    }
}
