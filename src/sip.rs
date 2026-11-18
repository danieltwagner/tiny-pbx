#![allow(clippy::wrong_self_convention)] // from_tag(), to_user(), ...

//! Minimal SIP message model: just enough parsing to proxy and register.
//!
//! Headers are kept as (name, value) strings in their original order. Headers
//! that a proxy has to manipulate one value at a time (Via, Route,
//! Record-Route, Contact) are split into one entry per value while parsing;
//! everything else is passed through untouched.

#[derive(Debug, Clone, PartialEq)]
pub enum StartLine {
    Request { method: String, uri: String },
    Response { code: u16, reason: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub start: StartLine,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

const COMPACT: &[(&str, &str)] = &[
    ("v", "Via"),
    ("f", "From"),
    ("t", "To"),
    ("i", "Call-ID"),
    ("m", "Contact"),
    ("l", "Content-Length"),
    ("c", "Content-Type"),
    ("k", "Supported"),
    ("e", "Content-Encoding"),
    ("s", "Subject"),
    ("o", "Event"),
    ("u", "Allow-Events"),
    ("r", "Refer-To"),
    ("b", "Referred-By"),
    ("x", "Session-Expires"),
    ("a", "Accept-Contact"),
    ("j", "Reject-Contact"),
    ("d", "Request-Disposition"),
    ("y", "Identity"),
];

const CANONICAL: &[&str] = &[
    "Via",
    "From",
    "To",
    "Call-ID",
    "CSeq",
    "Contact",
    "Max-Forwards",
    "Route",
    "Record-Route",
    "Content-Length",
    "Content-Type",
    "Expires",
    "Min-Expires",
    "Authorization",
    "Proxy-Authorization",
    "WWW-Authenticate",
    "Proxy-Authenticate",
    "User-Agent",
    "Server",
    "Allow",
    "Supported",
    "Require",
    "Proxy-Require",
    "Unsupported",
    "Event",
    "Date",
];

/// Headers whose comma-separated values we split into separate entries.
const SPLIT: &[&str] = &["Via", "Route", "Record-Route", "Contact"];

pub fn canonical_name(name: &str) -> String {
    if name.len() == 1 {
        for (c, full) in COMPACT {
            if name.eq_ignore_ascii_case(c) {
                return full.to_string();
            }
        }
    }
    for c in CANONICAL {
        if name.eq_ignore_ascii_case(c) {
            return c.to_string();
        }
    }
    name.to_string()
}

/// Split a header value on commas that are not inside quotes or <...>.
pub fn split_commas(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut escaped, mut angle) = (false, false, 0i32);
    for ch in v.chars() {
        if quoted {
            cur.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        match ch {
            '"' => {
                quoted = true;
                cur.push(ch)
            }
            '<' => {
                angle += 1;
                cur.push(ch)
            }
            '>' => {
                angle -= 1;
                cur.push(ch)
            }
            ',' if angle <= 0 => {
                let t = cur.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let t = cur.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
    out
}

/// Split `s` on `sep` outside of double quotes.
fn split_unquoted(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut quoted, mut escaped, mut start) = (false, false, 0);
    for (i, ch) in s.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
        } else if ch == sep {
            out.push(&s[start..i]);
            start = i + ch.len_utf8();
        }
    }
    out.push(&s[start..]);
    out
}

pub fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        let inner = &s[1..s.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut esc = false;
        for ch in inner.chars() {
            if esc {
                out.push(ch);
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else {
                out.push(ch);
            }
        }
        out
    } else {
        s.to_string()
    }
}

/// Parse ";a=b;lr;c=\"x\"" into [(a, Some(b)), (lr, None), (c, Some("\"x\""))].
pub fn parse_params(s: &str) -> Vec<(String, Option<String>)> {
    split_unquoted(s, ';')
        .into_iter()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), Some(v.trim().to_string())),
            None => (p.to_string(), None),
        })
        .collect()
}

pub fn find_param<'a>(params: &'a [(String, Option<String>)], name: &str) -> Option<Option<&'a str>> {
    params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_deref())
}

fn fmt_params(params: &[(String, Option<String>)]) -> String {
    let mut s = String::new();
    for (k, v) in params {
        s.push(';');
        s.push_str(k);
        if let Some(v) = v {
            s.push('=');
            s.push_str(v);
        }
    }
    s
}

/// Split "host:port" / "[v6]:port" / "host".
fn split_hostport(hp: &str) -> Option<(String, Option<u16>)> {
    let hp = hp.trim();
    if hp.is_empty() {
        return None;
    }
    if hp.starts_with('[') {
        let end = hp.find(']')?;
        let host = hp[..=end].to_string();
        let rest = &hp[end + 1..];
        let port = match rest.strip_prefix(':') {
            Some(p) => Some(p.trim().parse().ok()?),
            None if rest.is_empty() => None,
            None => return None,
        };
        return Some((host, port));
    }
    match hp.split_once(':') {
        Some((h, p)) => Some((h.trim().to_string(), Some(p.trim().parse().ok()?))),
        None => Some((hp.to_string(), None)),
    }
}

// ---------------------------------------------------------------- URI

#[derive(Debug, Clone, PartialEq)]
pub struct Uri {
    pub scheme: String,
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    /// Raw parameter string including the leading ';' (or empty).
    pub params: String,
    /// Raw header string including the leading '?' (or empty).
    pub headers: String,
}

impl Uri {
    pub fn parse(s: &str) -> Option<Uri> {
        let s = s.trim();
        let (scheme, rest) = s.split_once(':')?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "sip" && scheme != "sips" {
            return None;
        }
        let (rest, headers) = match rest.find('?') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, String::new()),
        };
        let (user, hostpart) = match rest.find('@') {
            Some(i) => {
                let userinfo = &rest[..i];
                let user = userinfo.split(':').next().unwrap_or("");
                (Some(user.to_string()), &rest[i + 1..])
            }
            None => (None, rest),
        };
        let (hostport, params) = match hostpart.find(';') {
            Some(i) => (&hostpart[..i], hostpart[i..].to_string()),
            None => (hostpart, String::new()),
        };
        let (host, port) = split_hostport(hostport)?;
        Some(Uri {
            scheme,
            user,
            host,
            port,
            params,
            headers,
        })
    }

    pub fn port_or_default(&self) -> u16 {
        self.port
            .unwrap_or(if self.scheme == "sips" { 5061 } else { 5060 })
    }

    pub fn param(&self, name: &str) -> Option<Option<String>> {
        let p = parse_params(&self.params);
        find_param(&p, name).map(|v| v.map(str::to_string))
    }
}

impl std::fmt::Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}:", self.scheme)?;
        if let Some(u) = &self.user {
            write!(f, "{}@", u)?;
        }
        write!(f, "{}", self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{}", p)?;
        }
        write!(f, "{}{}", self.params, self.headers)
    }
}

// ---------------------------------------------------------------- name-addr

/// `"Display" <uri>;params` or `uri;params`
#[derive(Debug, Clone, PartialEq)]
pub struct NameAddr {
    pub display: String,
    pub uri: String,
    /// Header parameters, raw, including leading ';' (or empty).
    pub params: String,
}

impl NameAddr {
    pub fn parse(s: &str) -> Option<NameAddr> {
        let s = s.trim();
        // find '<' outside quotes
        let mut quoted = false;
        let mut escaped = false;
        let mut lt = None;
        for (i, ch) in s.char_indices() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    quoted = false;
                }
            } else if ch == '"' {
                quoted = true;
            } else if ch == '<' {
                lt = Some(i);
                break;
            }
        }
        match lt {
            Some(i) => {
                let gt = i + s[i..].find('>')?;
                Some(NameAddr {
                    display: s[..i].trim().to_string(),
                    uri: s[i + 1..gt].trim().to_string(),
                    params: s[gt + 1..].trim().to_string(),
                })
            }
            None => {
                let (uri, params) = match s.find(';') {
                    Some(i) => (&s[..i], &s[i..]),
                    None => (s, ""),
                };
                Some(NameAddr {
                    display: String::new(),
                    uri: uri.trim().to_string(),
                    params: params.trim().to_string(),
                })
            }
        }
    }

    pub fn param(&self, name: &str) -> Option<Option<String>> {
        let p = parse_params(&self.params);
        find_param(&p, name).map(|v| v.map(str::to_string))
    }

    /// Header params with `name` removed (raw string, leading ';').
    pub fn params_without(&self, name: &str) -> String {
        let p: Vec<_> = parse_params(&self.params)
            .into_iter()
            .filter(|(k, _)| !k.eq_ignore_ascii_case(name))
            .collect();
        fmt_params(&p)
    }
}

// ---------------------------------------------------------------- Via

#[derive(Debug, Clone, PartialEq)]
pub struct Via {
    pub proto: String,
    pub host: String,
    pub port: Option<u16>,
    pub params: Vec<(String, Option<String>)>,
}

impl Via {
    pub fn parse(s: &str) -> Option<Via> {
        let s = s.trim();
        // tolerate "SIP / 2.0 / UDP host"
        let mut proto = String::new();
        let mut rest = s;
        let mut slashes = 0;
        let mut seen_transport = false;
        for (i, ch) in s.char_indices() {
            if ch == '/' {
                slashes += 1;
                proto.push(ch);
            } else if ch.is_whitespace() {
                if slashes == 2 && seen_transport {
                    rest = &s[i..];
                    break;
                }
            } else {
                if slashes == 2 {
                    seen_transport = true;
                }
                proto.push(ch);
            }
        }
        if slashes != 2 || !seen_transport || rest.len() == s.len() {
            return None;
        }
        let rest = rest.trim_start();
        let (hostport, params) = match rest.find(';') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let (host, port) = split_hostport(hostport)?;
        Some(Via {
            proto: proto.to_ascii_uppercase(),
            host,
            port,
            params: parse_params(params),
        })
    }

    pub fn param(&self, name: &str) -> Option<Option<&str>> {
        find_param(&self.params, name)
    }

    pub fn set_param(&mut self, name: &str, value: Option<String>) {
        if let Some(p) = self.params.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
            p.1 = value;
        } else {
            self.params.push((name.to_string(), value));
        }
    }

    pub fn branch(&self) -> Option<&str> {
        self.param("branch").flatten()
    }
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} {}", self.proto, self.host)?;
        if let Some(p) = self.port {
            write!(f, ":{}", p)?;
        }
        write!(f, "{}", fmt_params(&self.params))
    }
}

// ---------------------------------------------------------------- Message

#[derive(Debug, PartialEq)]
pub enum ParseError {
    Empty,
    BadStartLine,
    BadHeader,
    Truncated,
}

fn find_header_end(data: &[u8]) -> Option<(usize, usize)> {
    for i in 0..data.len() {
        if data[i..].starts_with(b"\r\n\r\n") {
            return Some((i, i + 4));
        }
        if data[i..].starts_with(b"\n\n") {
            return Some((i, i + 2));
        }
    }
    None
}

impl Message {
    pub fn parse(data: &[u8]) -> Result<Message, ParseError> {
        let (head_end, body_start) = find_header_end(data).unwrap_or((data.len(), data.len()));
        let head = String::from_utf8_lossy(&data[..head_end]);
        let mut lines: Vec<String> = Vec::new();
        for raw in head.split('\n') {
            let line = raw.strip_suffix('\r').unwrap_or(raw);
            if lines.is_empty() && line.trim().is_empty() {
                continue; // leading CRLFs are allowed
            }
            if (line.starts_with(' ') || line.starts_with('\t')) && lines.len() > 1 {
                let last = lines.last_mut().unwrap();
                last.push(' ');
                last.push_str(line.trim());
            } else {
                lines.push(line.to_string());
            }
        }
        let first = lines.first().ok_or(ParseError::Empty)?;
        let start = if let Some(rest) = first.strip_prefix("SIP/2.0 ") {
            let rest = rest.trim_start();
            let (code, reason) = rest.split_once(' ').unwrap_or((rest, ""));
            let code: u16 = code.parse().map_err(|_| ParseError::BadStartLine)?;
            if !(100..700).contains(&code) {
                return Err(ParseError::BadStartLine);
            }
            StartLine::Response {
                code,
                reason: reason.trim().to_string(),
            }
        } else {
            let mut parts = first.split_whitespace();
            let method = parts.next().ok_or(ParseError::BadStartLine)?;
            let uri = parts.next().ok_or(ParseError::BadStartLine)?;
            let ver = parts.next().ok_or(ParseError::BadStartLine)?;
            if !ver.eq_ignore_ascii_case("SIP/2.0")
                || parts.next().is_some()
                || !method
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-.!%*_+`'~".contains(c))
            {
                return Err(ParseError::BadStartLine);
            }
            StartLine::Request {
                method: method.to_ascii_uppercase(),
                uri: uri.to_string(),
            }
        };
        let mut headers = Vec::new();
        for line in &lines[1..] {
            if line.trim().is_empty() {
                continue;
            }
            let (name, value) = line.split_once(':').ok_or(ParseError::BadHeader)?;
            let name = canonical_name(name.trim());
            if name.is_empty() || name.contains(' ') {
                return Err(ParseError::BadHeader);
            }
            let value = value.trim();
            if SPLIT.contains(&name.as_str()) {
                for v in split_commas(value) {
                    headers.push(Header {
                        name: name.clone(),
                        value: v,
                    });
                }
            } else {
                headers.push(Header {
                    name,
                    value: value.to_string(),
                });
            }
        }
        let rest = &data[body_start.min(data.len())..];
        let cl = headers
            .iter()
            .find(|h| h.name == "Content-Length")
            .and_then(|h| h.value.trim().parse::<usize>().ok());
        let body = match cl {
            Some(n) if n > rest.len() => return Err(ParseError::Truncated),
            Some(n) => rest[..n].to_vec(),
            None => rest.to_vec(),
        };
        headers.retain(|h| h.name != "Content-Length");
        Ok(Message { start, headers, body })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut s = String::with_capacity(1024);
        match &self.start {
            StartLine::Request { method, uri } => {
                s.push_str(&format!("{} {} SIP/2.0\r\n", method, uri));
            }
            StartLine::Response { code, reason } => {
                s.push_str(&format!("SIP/2.0 {} {}\r\n", code, reason));
            }
        }
        for h in &self.headers {
            s.push_str(&h.name);
            s.push_str(": ");
            s.push_str(&h.value);
            s.push_str("\r\n");
        }
        s.push_str(&format!("Content-Length: {}\r\n\r\n", self.body.len()));
        let mut out = s.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    pub fn is_request(&self) -> bool {
        matches!(self.start, StartLine::Request { .. })
    }

    pub fn method(&self) -> &str {
        match &self.start {
            StartLine::Request { method, .. } => method,
            StartLine::Response { .. } => "",
        }
    }

    pub fn uri(&self) -> &str {
        match &self.start {
            StartLine::Request { uri, .. } => uri,
            StartLine::Response { .. } => "",
        }
    }

    pub fn set_uri(&mut self, new: String) {
        if let StartLine::Request { uri, .. } = &mut self.start {
            *uri = new;
        }
    }

    pub fn code(&self) -> u16 {
        match &self.start {
            StartLine::Response { code, .. } => *code,
            _ => 0,
        }
    }

    pub fn hdr(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn hdrs<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn remove_first(&mut self, name: &str) -> Option<String> {
        let i = self
            .headers
            .iter()
            .position(|h| h.name.eq_ignore_ascii_case(name))?;
        Some(self.headers.remove(i).value)
    }

    /// Insert before the first header of the same name; if none, at the top
    /// (`front`) or at the bottom.
    pub fn insert_top(&mut self, name: &str, value: String, front: bool) {
        let h = Header {
            name: name.to_string(),
            value,
        };
        match self
            .headers
            .iter()
            .position(|x| x.name.eq_ignore_ascii_case(name))
        {
            Some(i) => self.headers.insert(i, h),
            None if front => self.headers.insert(0, h),
            None => self.headers.push(h),
        }
    }

    /// Replace the first header of that name (or append).
    pub fn set(&mut self, name: &str, value: String) {
        match self
            .headers
            .iter_mut()
            .find(|h| h.name.eq_ignore_ascii_case(name))
        {
            Some(h) => h.value = value,
            None => self.headers.push(Header {
                name: name.to_string(),
                value,
            }),
        }
    }

    pub fn top_via(&self) -> Option<Via> {
        self.hdr("Via").and_then(Via::parse)
    }

    pub fn call_id(&self) -> Option<&str> {
        self.hdr("Call-ID").map(str::trim).filter(|s| !s.is_empty())
    }

    pub fn cseq(&self) -> Option<(u32, String)> {
        let v = self.hdr("CSeq")?;
        let mut it = v.split_whitespace();
        let n = it.next()?.parse().ok()?;
        let m = it.next()?.to_ascii_uppercase();
        Some((n, m))
    }

    fn addr_hdr(&self, name: &str) -> Option<NameAddr> {
        self.hdr(name).and_then(NameAddr::parse)
    }

    pub fn from_tag(&self) -> Option<String> {
        self.addr_hdr("From")?.param("tag").flatten()
    }

    pub fn to_tag(&self) -> Option<String> {
        self.addr_hdr("To")?
            .param("tag")
            .flatten()
            .filter(|t| !t.is_empty())
    }

    pub fn from_user(&self) -> Option<String> {
        Uri::parse(&self.addr_hdr("From")?.uri)?.user
    }

    pub fn to_user(&self) -> Option<String> {
        Uri::parse(&self.addr_hdr("To")?.uri)?.user
    }

    /// Build a response to this request (RFC 3261 8.2.6.2).
    pub fn make_response(&self, code: u16, reason: &str, to_tag: Option<&str>) -> Message {
        let mut headers = Vec::new();
        for h in &self.headers {
            match h.name.as_str() {
                "Via" | "From" | "Call-ID" | "CSeq" => headers.push(h.clone()),
                "To" => {
                    let mut v = h.value.clone();
                    if let Some(tag) = to_tag {
                        if code > 100 && self.to_tag().is_none() {
                            v.push_str(";tag=");
                            v.push_str(tag);
                        }
                    }
                    headers.push(Header {
                        name: "To".into(),
                        value: v,
                    });
                }
                _ => {}
            }
        }
        Message {
            start: StartLine::Response {
                code,
                reason: reason.to_string(),
            },
            headers,
            body: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = "INVITE sip:102@192.168.1.2 SIP/2.0\r\n\
v: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK776;rport, SIP/2.0/UDP 10.0.0.1;branch=z9hG4bKx\r\n\
Max-Forwards: 70\r\n\
f: \"Alice, A\" <sip:101@192.168.1.2>;tag=abc\r\n\
To: <sip:102@192.168.1.2>\r\n\
Call-ID: xyz@192.168.1.10\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:101@192.168.1.10:5060;transport=udp>;+sip.instance=\"<urn:uuid:1,2>\"\r\n\
Subject: folded\r\n  continuation\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 4\r\n\r\nv=0\nGARBAGE";

    #[test]
    fn parse_invite() {
        let m = Message::parse(INVITE.as_bytes()).unwrap();
        assert_eq!(m.method(), "INVITE");
        assert_eq!(m.uri(), "sip:102@192.168.1.2");
        assert_eq!(m.hdrs("Via").count(), 2);
        assert_eq!(m.from_tag().as_deref(), Some("abc"));
        assert_eq!(m.from_user().as_deref(), Some("101"));
        assert_eq!(m.to_tag(), None);
        assert_eq!(m.to_user().as_deref(), Some("102"));
        assert_eq!(m.cseq(), Some((1, "INVITE".into())));
        assert_eq!(m.hdr("subject"), Some("folded continuation"));
        assert_eq!(m.body, b"v=0\n");
        let via = m.top_via().unwrap();
        assert_eq!(via.host, "192.168.1.10");
        assert_eq!(via.port, Some(5060));
        assert_eq!(via.branch(), Some("z9hG4bK776"));
        assert_eq!(via.param("rport"), Some(None));
        let c = NameAddr::parse(m.hdr("Contact").unwrap()).unwrap();
        assert_eq!(c.uri, "sip:101@192.168.1.10:5060;transport=udp");
        assert_eq!(
            c.param("+sip.instance").flatten().as_deref(),
            Some("\"<urn:uuid:1,2>\"")
        );
        // round trip
        let again = Message::parse(&m.to_bytes()).unwrap();
        assert_eq!(again.headers, m.headers);
        assert_eq!(again.body, m.body);
    }

    #[test]
    fn parse_response() {
        let r = "SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP a;branch=z9hG4bK1\r\nContent-Length: 0\r\n\r\n";
        let m = Message::parse(r.as_bytes()).unwrap();
        assert_eq!(m.code(), 180);
        assert!(!m.is_request());
    }

    #[test]
    fn truncated() {
        let r = "SIP/2.0 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        assert_eq!(Message::parse(r.as_bytes()).unwrap_err(), ParseError::Truncated);
    }

    #[test]
    fn uris() {
        let u = Uri::parse("sip:101:pw@[2001:db8::1]:5070;transport=udp;lr?x=y").unwrap();
        assert_eq!(u.user.as_deref(), Some("101"));
        assert_eq!(u.host, "[2001:db8::1]");
        assert_eq!(u.port, Some(5070));
        assert_eq!(u.param("lr"), Some(None));
        assert_eq!(u.param("transport"), Some(Some("udp".into())));
        let u = Uri::parse("sip:pbx.example.com").unwrap();
        assert_eq!(u.user, None);
        assert_eq!(u.port_or_default(), 5060);
        assert_eq!(u.to_string(), "sip:pbx.example.com");
        assert!(Uri::parse("tel:+123").is_none());
    }

    #[test]
    fn vias() {
        let v = Via::parse("SIP / 2.0 / UDP 1.2.3.4;branch=z9hG4bKa;rport").unwrap();
        assert_eq!(v.proto, "SIP/2.0/UDP");
        assert_eq!(v.host, "1.2.3.4");
        assert_eq!(v.port, None);
        let mut v = Via::parse("SIP/2.0/UDP 1.2.3.4:5062;rport;branch=z9hG4bKa").unwrap();
        v.set_param("rport", Some("1234".into()));
        v.set_param("received", Some("5.6.7.8".into()));
        assert_eq!(
            v.to_string(),
            "SIP/2.0/UDP 1.2.3.4:5062;rport=1234;branch=z9hG4bKa;received=5.6.7.8"
        );
    }

    #[test]
    fn name_addrs() {
        let n = NameAddr::parse("sip:101@h;tag=1").unwrap();
        assert_eq!(n.uri, "sip:101@h");
        assert_eq!(n.params, ";tag=1");
        let n = NameAddr::parse("\"a <b>\" <sip:x@y>;expires=60;q=1").unwrap();
        assert_eq!(n.uri, "sip:x@y");
        assert_eq!(n.params_without("expires"), ";q=1");
        assert_eq!(
            split_commas("<sip:a,b>, \"x,y\" <sip:c>"),
            vec!["<sip:a,b>", "\"x,y\" <sip:c>"]
        );
    }
}
