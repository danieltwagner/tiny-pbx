//! Config file: `key = value` lines, plus an `[extensions]` section of
//! `number = password` lines and an optional `[groups]` section of
//! `number = member member ...` lines (`*` = every extension). `#` and `;` start comments.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::util::{Cidr, PRIVATE_NETS};

#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    /// IP to put in Via/Record-Route instead of the auto-detected one
    /// (only needed behind NAT / docker port mapping).
    pub advertise: Option<IpAddr>,
    pub realm: String,
    /// Only packets from these networks are looked at.
    pub allow: Vec<Cidr>,
    pub state_file: Option<PathBuf>,
    pub log_level: u8,
    pub min_expires: u32,
    pub max_expires: u32,
    pub default_expires: u32,
    pub record_route: bool,
    /// Challenge calls from sources that aren't a registered phone.
    pub auth_calls: bool,
    pub extensions: BTreeMap<String, String>,
    /// Ring groups: number -> member extensions (calls ring all of them).
    pub groups: BTreeMap<String, Vec<String>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: "0.0.0.0:5060".parse().unwrap(),
            advertise: None,
            realm: "pbx".into(),
            allow: parse_allow("private").unwrap(),
            state_file: None,
            log_level: crate::util::INFO,
            min_expires: 60,
            max_expires: 3600,
            default_expires: 3600,
            record_route: true,
            auth_calls: true,
            extensions: BTreeMap::new(),
            groups: BTreeMap::new(),
        }
    }
}

/// Setting names, which are not allowed as extension or group numbers: a
/// setting written after `[extensions]` would otherwise silently become a
/// phone (`log = debug`: extension "log" with password "debug").
const SETTINGS: &[&str] = &[
    "listen",
    "advertise",
    "realm",
    "allow",
    "state",
    "state_file",
    "log",
    "log_level",
    "min_expires",
    "max_expires",
    "default_expires",
    "record_route",
    "auth_calls",
];

/// `allow` list: networks (CIDR or single address) and the keywords
/// `private` and `any`, separated by commas and/or spaces.
fn parse_allow(v: &str) -> Result<Vec<Cidr>, String> {
    let mut out = Vec::new();
    for n in v.split([',', ' ', '\t']).filter(|n| !n.is_empty()) {
        let nets = match n.to_ascii_lowercase().as_str() {
            "any" | "all" => "0.0.0.0/0, ::/0",
            "private" => PRIVATE_NETS,
            _ => n,
        };
        for net in nets.split(',') {
            out.push(Cidr::parse(net).ok_or_else(|| format!("bad network {:?}", n))?);
        }
    }
    if out.is_empty() {
        return Err(
            "allow is empty, so every packet would be ignored; use private, any or a list of networks".into(),
        );
    }
    Ok(out)
}

/// `error | warn | warning | info | debug`, as in the config and $PBX_LOG.
pub fn parse_log_level(v: &str) -> Option<u8> {
    match v.trim().to_ascii_lowercase().as_str() {
        "error" => Some(crate::util::ERROR),
        "warn" | "warning" => Some(crate::util::WARN),
        "info" => Some(crate::util::INFO),
        "debug" => Some(crate::util::DEBUG),
        _ => None,
    }
}

fn parse_bool(v: &str) -> Result<bool, String> {
    match v.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        _ => Err(format!("expected yes/no, got {:?}", v)),
    }
}

impl Config {
    pub fn allowed(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|c| c.contains(ip))
    }

    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {}", path.display(), e))?;
        let mut cfg = Config::parse(&text).map_err(|e| format!("{}: {}", path.display(), e))?;
        // The state file (default bindings.txt) lives next to the config:
        // relative paths are relative to the config's directory, not to the
        // working directory (which is / in the Docker image).
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let state = cfg
            .state_file
            .take()
            .unwrap_or_else(|| PathBuf::from("bindings.txt"));
        let state = dir.join(state);
        // The cache, its staging file and the routing key need distinct paths
        // from the config. Compare identities to cover links and path aliases.
        let config = path
            .metadata()
            .map_err(|e| format!("{}: {}", path.display(), e))?;
        for suffix in ["", ".tmp", ".key"] {
            let mut name = state.as_os_str().to_owned();
            name.push(suffix);
            let output = Path::new(&name);
            match output.metadata() {
                Ok(m) if (m.dev(), m.ino()) == (config.dev(), config.ino()) => {
                    return Err(format!(
                        "{}: state output {} is the config file",
                        path.display(),
                        output.display()
                    ));
                }
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(format!("{}: {}", output.display(), e)),
            }
        }
        cfg.state_file = Some(state);
        Ok(cfg)
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let mut cfg = Config::default();
        let mut section = String::new();
        let mut set: Vec<String> = Vec::new(); // the settings seen so far

        // Editors on Windows like to start UTF-8 files with a byte order mark.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let err = |m: String| format!("line {}: {}", n + 1, m);
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                if section != "extensions" && section != "groups" && section != "general" {
                    return Err(err(format!("unknown section [{}]", section)));
                }
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| err("expected key = value".into()))?;
            let (k, v) = (k.trim(), v.trim());
            let valid_number =
                |k: &str| !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || "-_.+".contains(c));
            if (section == "extensions" || section == "groups")
                && SETTINGS.contains(&k.to_ascii_lowercase().as_str())
            {
                return Err(err(format!(
                    "{:?} is a setting, not an entry of [{}]; put settings before the first [section] or in [general]",
                    k, section
                )));
            }
            if section == "groups" {
                if !valid_number(k) {
                    return Err(err(format!("bad group number {:?}", k)));
                }
                if cfg.groups.contains_key(k) {
                    return Err(err(format!("group {} is defined twice", k)));
                }
                let members: Vec<String> = v
                    .split([',', ' ', '\t'])
                    .filter(|m| !m.is_empty())
                    .map(str::to_string)
                    .collect();
                if members.is_empty() {
                    return Err(err(format!("group {} has no members", k)));
                }
                cfg.groups.insert(k.to_string(), members);
                continue;
            }
            if section == "extensions" {
                if !valid_number(k) {
                    return Err(err(format!("bad extension {:?}", k)));
                }
                if v.is_empty() {
                    return Err(err(format!("extension {} has no password", k)));
                }
                if cfg.extensions.contains_key(k) {
                    return Err(err(format!("extension {} is defined twice", k)));
                }
                cfg.extensions.insert(k.to_string(), v.to_string());
                continue;
            }
            // A second line would silently replace the first: of two `allow`
            // lines, the phones in the first network would just be ignored.
            let name = match k.to_ascii_lowercase().as_str() {
                "state_file" => "state".to_string(),
                "log_level" => "log".to_string(),
                name => name.to_string(),
            };
            if set.contains(&name) {
                let hint = if name == "allow" {
                    "; list all networks on one line"
                } else {
                    ""
                };
                return Err(err(format!("{} is set twice{}", name, hint)));
            }
            set.push(name);
            match k.to_ascii_lowercase().as_str() {
                "listen" => {
                    cfg.listen = v
                        .parse()
                        .or_else(|_| v.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 5060)))
                        .map_err(|_| err(format!("bad listen address {:?}", v)))?
                }
                "advertise" => {
                    cfg.advertise = if v.is_empty() {
                        None
                    } else {
                        Some(v.parse().map_err(|_| err(format!("bad advertise IP {:?}", v)))?)
                    }
                }
                "realm" => cfg.realm = v.to_string(),
                "allow" => cfg.allow = parse_allow(v).map_err(err)?,
                "state" | "state_file" => {
                    cfg.state_file = if v.is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(v))
                    }
                }
                "log" | "log_level" => {
                    cfg.log_level = parse_log_level(v).ok_or_else(|| err(format!("bad log level {:?}", v)))?
                }
                "min_expires" | "max_expires" | "default_expires" => {
                    let n = v
                        .parse()
                        .map_err(|_| err(format!("{}: bad number of seconds {:?}", k, v)))?;
                    match k.to_ascii_lowercase().as_str() {
                        "min_expires" => cfg.min_expires = n,
                        "max_expires" => cfg.max_expires = n,
                        _ => cfg.default_expires = n,
                    }
                }
                "record_route" => cfg.record_route = parse_bool(v).map_err(err)?,
                "auth_calls" => cfg.auth_calls = parse_bool(v).map_err(err)?,
                _ if section.is_empty() && k.bytes().all(|b| b.is_ascii_digit()) => {
                    return Err(err(format!(
                        "unknown setting {:?}; extensions go under [extensions]",
                        k
                    )))
                }
                _ => return Err(err(format!("unknown setting {:?}", k))),
            }
        }
        if cfg.extensions.is_empty() {
            return Err("no [extensions] configured".into());
        }
        for (g, members) in cfg.groups.iter_mut() {
            if cfg.extensions.contains_key(g) {
                return Err(format!("group {} is also an extension", g));
            }
            if members.iter().any(|m| m == "*") {
                *members = cfg.extensions.keys().cloned().collect();
            }
            let mut seen = Vec::new();
            for m in members.iter() {
                if !cfg.extensions.contains_key(m) {
                    return Err(format!("group {}: {} is not an extension", g, m));
                }
                if !seen.contains(m) {
                    seen.push(m.clone());
                }
            }
            *members = seen;
        }
        // 0 would turn every REGISTER (or every one without an interval)
        // into an unregistration.
        if cfg.max_expires == 0 || cfg.default_expires == 0 {
            return Err("max_expires and default_expires must be at least 1 second".into());
        }
        if cfg.min_expires > cfg.max_expires {
            return Err("min_expires > max_expires".into());
        }
        cfg.default_expires = cfg.default_expires.clamp(cfg.min_expires, cfg.max_expires);
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let c = Config::parse(
            "# comment\nlisten = 0.0.0.0:5070\nrealm = home\nallow = 192.168.130.0/24 10.1.1.1\n\
             record_route = no\n[extensions]\n101 = secret ; not a comment\n102=x\n",
        )
        .unwrap();
        assert_eq!(c.listen.port(), 5070);
        assert_eq!(c.realm, "home");
        assert!(c.allowed("192.168.130.9".parse().unwrap()));
        assert!(c.allowed("10.1.1.1".parse().unwrap()));
        assert!(!c.allowed("10.1.1.2".parse().unwrap()));
        let d = Config::parse("[extensions]\n1=a").unwrap();
        assert!(d.allowed("127.0.0.2".parse().unwrap()));
        assert!(d.allowed("192.168.1.1".parse().unwrap()));
        assert!(!d.allowed("8.8.8.8".parse().unwrap()));
        let any = Config::parse("allow = any\n[extensions]\n1=a").unwrap();
        assert!(any.allowed("8.8.8.8".parse().unwrap()));
        assert!(Config::parse("allow = 1.2.3/8\n[extensions]\n1=a").is_err());
        assert!(!c.record_route);
        assert_eq!(
            c.extensions.get("101").map(String::as_str),
            Some("secret ; not a comment")
        );
        assert_eq!(c.extensions.len(), 2);
        assert!(
            Config::parse("listen = 1.2.3.4\n[extensions]\n1=a")
                .unwrap()
                .listen
                .port()
                == 5060
        );
        assert!(Config::parse("bogus = 1\n[extensions]\n1=a").is_err());
        let g = Config::parse("[groups]\n100 = *\n200 = 2, 1 2\n[extensions]\n1=a\n2=b\n3=c").unwrap();
        assert_eq!(g.groups["100"], vec!["1", "2", "3"]);
        assert_eq!(g.groups["200"], vec!["2", "1"]);
        assert!(Config::parse("[extensions]\n1=a\n[groups]\n1 = 1").is_err());
        assert!(Config::parse("[extensions]\n1=a\n[groups]\n100 = 1 9").is_err());
        assert!(Config::parse("[extensions]\n1=a\n[groups]\n100 =").is_err());
        assert!(Config::parse("realm = x\n").is_err());
    }

    fn err(text: &str) -> String {
        Config::parse(text).expect_err(text)
    }

    #[test]
    fn settings_inside_sections_are_errors() {
        // Appended at the end, after [extensions]: used to create phone "log".
        let e = err("[extensions]\n101 = pw\nlog = debug\n");
        assert!(
            e.contains("line 3") && e.contains("setting") && e.contains("[general]"),
            "{e}"
        );
        assert!(err("[extensions]\n101 = pw\n[groups]\nRealm = x\n").contains("setting"));
        assert!(err("[extensions]\n101 = pw\n[groups]\nauth_calls = no\n").contains("setting"));
        assert!(err("101 = pw\n").contains("[extensions]"));
        // ... but fine in [general], wherever that is.
        let c = Config::parse("[extensions]\n101 = pw\n[general]\nlog = debug\n").unwrap();
        assert_eq!(c.log_level, crate::util::DEBUG);
        assert_eq!(c.extensions.keys().collect::<Vec<_>>(), ["101"]);
    }

    #[test]
    fn duplicates_bom_and_value_checks() {
        assert!(err("[extensions]\n101 = a\n101 = b\n").contains("twice"));
        assert!(err("[extensions]\n1 = a\n2 = b\n[groups]\n100 = 1\n100 = 2\n").contains("twice"));
        let c = Config::parse("\u{feff}realm = home\n[extensions]\n1 = a\n").unwrap();
        assert_eq!(c.realm, "home");
        // A repeated setting is not a list, whatever it is called and wherever.
        let e = err("allow = 192.168.1.0/24\nallow = 10.0.0.0/8\n[extensions]\n1 = a\n");
        assert!(e.contains("line 2") && e.contains("allow is set twice"), "{e}");
        assert!(err("log = info\nLog_Level = debug\n[extensions]\n1 = a\n").contains("log is set twice"));
        assert!(err("realm = a\n[extensions]\n1 = a\n[general]\nrealm = b\n").contains("line 5"));
        // `allow` with nothing in it would ignore every packet.
        assert!(err("allow =\n[extensions]\n1 = a\n").contains("allow"));
        assert!(err("allow = , \n[extensions]\n1 = a\n").contains("allow"));
        let c = Config::parse("allow = private, 203.0.113.0/24\n[extensions]\n1 = a\n").unwrap();
        for ip in ["203.0.113.9", "192.168.1.1", "127.0.0.1", "fd00::1"] {
            assert!(c.allowed(ip.parse().unwrap()), "{ip}");
        }
        assert!(!c.allowed("8.8.8.8".parse().unwrap()));
        let c = Config::parse("allow = 10.0.0.0/8\tANY\n[extensions]\n1 = a\n").unwrap();
        assert!(c.allowed("8.8.8.8".parse().unwrap()) && c.allowed("2001:db8::1".parse().unwrap()));
        assert!(err("allow = private, bogus\n[extensions]\n1 = a\n").contains("bogus"));
        // 0 would make every REGISTER an unregistration.
        assert!(err("min_expires = 0\nmax_expires = 0\n[extensions]\n1 = a\n").contains("max_expires"));
        assert!(err("default_expires = 0\n[extensions]\n1 = a\n").contains("default_expires"));
        assert!(err("max_expires = -1\n[extensions]\n1 = a\n").contains("max_expires"));
        assert!(err("min_expires = 600\nmax_expires = 60\n[extensions]\n1 = a\n").contains("min_expires"));
        let c = Config::parse("min_expires = 0\nmax_expires = 600\n[extensions]\n1 = a\n").unwrap();
        assert_eq!((c.min_expires, c.max_expires, c.default_expires), (0, 600, 600));
        assert_eq!(
            Config::parse("log = Warning\n[extensions]\n1 = a\n")
                .unwrap()
                .log_level,
            crate::util::WARN
        );
        assert_eq!(parse_log_level("warning"), Some(crate::util::WARN));
        assert_eq!(parse_log_level("verbose"), None);
    }

    #[test]
    fn example_config_parses_and_shows_the_defaults() {
        let example = include_str!("../tiny-pbx.conf.example");
        let c = Config::parse(example).unwrap();
        assert_eq!(c.extensions.len(), 2);
        // Uncommenting every `#setting = value` line changes nothing.
        let uncommented: String = example
            .lines()
            .map(|l| match l.strip_prefix('#') {
                Some(s) if SETTINGS.iter().any(|k| s.starts_with(&format!("{k} ="))) => s,
                _ => l,
            })
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(uncommented, example);
        let d = Config::parse(&uncommented).unwrap();
        let fields = |c: &Config| {
            format!(
                "{} {} {:?} {:?} {} {} {} {} {} {}",
                c.listen,
                c.realm,
                c.allow,
                c.advertise,
                c.log_level,
                c.min_expires,
                c.max_expires,
                c.default_expires,
                c.record_route,
                c.auth_calls
            )
        };
        assert_eq!(fields(&d), fields(&c));
        let default_state = Path::new("bindings.txt");
        assert_eq!(d.state_file.as_deref().unwrap_or(default_state), default_state);
    }

    #[test]
    fn state_outputs_must_not_alias_the_config() {
        use std::fs;
        let dir = crate::util::TestDir::create();
        fs::create_dir(dir.join("sub")).unwrap();
        // Only load configs; never try to save state over them.
        let check = |name: &str, setting: &str| {
            let path = dir.join(name);
            fs::write(&path, format!("{setting}\n[extensions]\n1=a\n")).unwrap();
            assert!(Config::load(&path).unwrap_err().contains("is the config file"));
        };
        check("bindings.txt.tmp", ""); // state does not exist yet
        check("bindings.txt.key", "");
        check("bindings.txt", "");
        check("pbx.conf", "state = ./sub/../pbx.conf");
        std::os::unix::fs::symlink("pbx.conf", dir.join("regs.txt.tmp")).unwrap();
        check("pbx.conf", "state = regs.txt");
        fs::hard_link(dir.join("pbx.conf"), dir.join("alias")).unwrap();
        check("pbx.conf", "state = alias");
    }

    #[test]
    fn relative_state_path_is_next_to_the_config() {
        let dir = crate::util::TestDir::create();
        let path = dir.join("tiny-pbx.conf");
        for (state, expect) in [
            ("", dir.join("bindings.txt")),
            ("state = regs.txt\n", dir.join("regs.txt")),
            ("state = sub/regs.txt\n", dir.join("sub/regs.txt")),
            (
                "state = /var/lib/pbx/regs.txt\n",
                PathBuf::from("/var/lib/pbx/regs.txt"),
            ),
        ] {
            std::fs::write(&path, format!("{state}[extensions]\n1 = a\n")).unwrap();
            assert_eq!(Config::load(&path).unwrap().state_file, Some(expect), "{state:?}");
        }
    }
}
