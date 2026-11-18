//! HTTP Digest authentication (RFC 2617 / RFC 3261 22), MD5 with qop=auth.
//!
//! Nonces are stateless: hex timestamp + serial number + MAC(secret,
//! timestamp, serial, client address), so nothing has to be remembered
//! between challenge and response, and a sniffed response can't be replayed
//! from another address. The serial makes every challenge's nonce unique.
//!
//! The nonce is checked before the password: a response to a nonce that
//! isn't ours (forged, garbled, from before a restart, for another address)
//! or has expired says nothing about the password, and gets a fresh
//! challenge whether or not the password was right. Responses are compared
//! in constant time.
//!
//! For each remembered nonce/user pair, counts must increase except on an
//! identical retransmission. A legacy reply without qop has no count and
//! is treated as count one. The digest `uri` must name the Request-URI.
//! At capacity the oldest entry may be forgotten before its nonce expires.

use crate::routing::equal;
use crate::sip::{unquote, Uri};
use crate::util::{md5_hex, now_unix, parse_ip_host};
use std::cell::Cell;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug, Default, Clone)]
pub struct Credentials {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub algorithm: Option<String>,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
}

/// Parse `Digest username="101", realm="pbx", ...`.
pub fn parse_credentials(v: &str) -> Option<Credentials> {
    let v = v.trim();
    let (scheme, rest) = v.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("digest") {
        return None;
    }
    let mut c = Credentials::default();
    for part in split_auth_params(rest) {
        let Some((k, val)) = part.split_once('=') else {
            continue;
        };
        let val = unquote(val);
        match k.trim().to_ascii_lowercase().as_str() {
            "username" => c.username = val,
            "realm" => c.realm = val,
            "nonce" => c.nonce = val,
            "uri" => c.uri = val,
            "response" => c.response = val,
            "algorithm" => c.algorithm = Some(val),
            "qop" => c.qop = Some(val),
            "nc" => c.nc = Some(val),
            "cnonce" => c.cnonce = Some(val),
            _ => {}
        }
    }
    if c.username.is_empty() || c.nonce.is_empty() || c.response.is_empty() {
        return None;
    }
    Some(c)
}

fn split_auth_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut quoted, mut esc) = (false, false);
    for ch in s.chars() {
        if quoted {
            cur.push(ch);
            if esc {
                esc = false;
            } else if ch == '\\' {
                esc = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
            cur.push(ch);
        } else if ch == ',' {
            out.push(cur.trim().to_string());
            cur.clear();
        } else {
            cur.push(ch);
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Ok,
    /// The nonce is not one we gave this client (e.g. we restarted), has
    /// expired, or this response to it was used before (a replay, or nonce
    /// counts out of order): answer with a fresh challenge (stale=true, so
    /// the phone retries without asking its user). The password was not
    /// looked at.
    Stale,
    /// Rejected, for a nonce of ours: see `Bad`.
    Bad(Bad),
}

#[derive(Debug, PartialEq)]
pub enum Bad {
    /// Wrong password or unknown user (indistinguishable).
    Password,
    /// Not answered in a way we can check: other algorithm or qop, qop=auth
    /// without a valid nc / cnonce. The password was not looked at.
    Unsupported(&'static str),
    /// The digest `uri` is not the Request-URI. The password was not
    /// looked at.
    Uri,
}

impl std::fmt::Display for Bad {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Bad::Password => f.write_str("wrong password or unknown extension"),
            Bad::Unsupported(what) => write!(f, "unsupported credentials ({})", what),
            Bad::Uri => f.write_str("credentials for another Request-URI"),
        }
    }
}

/// Maximum nonce/user pairs tracked; only correct responses are recorded.
const MAX_USED: usize = 1024;

/// Retransmissions of this many of the last requests accepted for a nonce
/// are recognised (a phone may have sent another request meanwhile).
const RECENT: usize = 4;

/// The responses accepted for a nonce and user.
struct Used {
    /// The nonce's timestamp: the entry is dropped once it has expired.
    ts: u64,
    /// The highest nonce count accepted.
    nc: u32,
    /// The counts and hashes of the whole request of the last few accepted
    /// ones: only an identical retransmission may use a count again.
    recent: Vec<(u32, [u8; 16])>,
}

/// Hex digits of the timestamp, serial and MAC in a nonce (32 in all).
const TS_HEX: usize = 10;
const SERIAL_HEX: usize = 6;
const MAC_HEX: usize = 16;

pub struct Digest {
    pub realm: String,
    secret: String,
    pub nonce_ttl: u64,
    /// Serial number of the next nonce (wraps; with the timestamp, nonces
    /// are unique unless 16 million are handed out within a second).
    serial: Cell<u32>,
    /// Stands in for the password of an unknown user, so that checking
    /// one takes the same steps as checking a wrong password.
    dummy: String,
    /// "nonce:user" -> the last response accepted.
    used: HashMap<String, Used>,
}

impl Digest {
    pub fn new(realm: &str, secret: &str) -> Digest {
        Digest {
            realm: realm.to_string(),
            secret: secret.to_string(),
            nonce_ttl: 300,
            serial: Cell::new(0),
            dummy: md5_hex(&format!("{}:dummy password", secret)),
            used: HashMap::new(),
        }
    }

    fn nonce_at(&self, ts: u64, serial: u32, client: SocketAddr) -> String {
        let mac = md5_hex(&format!(
            "{}:{}:{}:{}:{}",
            self.secret, ts, serial, self.realm, client
        ));
        format!("{:010x}{:06x}{}", ts, serial, &mac[..MAC_HEX])
    }

    pub fn nonce(&self, client: SocketAddr) -> String {
        let serial = self.serial.get() & 0xff_ffff;
        self.serial.set(serial.wrapping_add(1));
        self.nonce_at(now_unix(), serial, client)
    }

    /// The nonce's timestamp, if we made it for this client.
    fn nonce_ts(&self, nonce: &str, client: SocketAddr) -> Option<u64> {
        if nonce.len() != TS_HEX + SERIAL_HEX + MAC_HEX || !nonce.is_ascii() {
            return None;
        }
        let ts = u64::from_str_radix(&nonce[..TS_HEX], 16).ok()?;
        let serial = u32::from_str_radix(&nonce[TS_HEX..TS_HEX + SERIAL_HEX], 16).ok()?;
        equal(&self.nonce_at(ts, serial, client), &nonce.to_ascii_lowercase()).then_some(ts)
    }

    #[cfg(test)]
    fn nonce_fresh(&self, nonce: &str, client: SocketAddr) -> bool {
        self.nonce_ts(nonce, client).is_some_and(|ts| self.ts_fresh(ts))
    }

    fn ts_fresh(&self, ts: u64) -> bool {
        let now = now_unix();
        ts <= now + 5 && now - ts.min(now) <= self.nonce_ttl
    }

    /// `WWW-Authenticate` / `Proxy-Authenticate` value.
    pub fn challenge(&self, stale: bool, client: SocketAddr) -> String {
        format!(
            "Digest realm=\"{}\", nonce=\"{}\", algorithm=MD5, qop=\"auth\"{}",
            self.realm,
            self.nonce(client),
            if stale { ", stale=true" } else { "" }
        )
    }

    /// Check credentials `c` sent with a request (`method`, `request_uri`)
    /// from `client`; `password` is None for an unknown user. `request`
    /// hashes the whole request (only needed if its nonce count was used
    /// before, or to remember it).
    pub fn verify(
        &mut self,
        c: &Credentials,
        method: &str,
        request_uri: &str,
        password: Option<&str>,
        client: SocketAddr,
        request: &dyn Fn() -> [u8; 16],
    ) -> Verdict {
        let Some(ts) = self.nonce_ts(&c.nonce, client).filter(|&ts| self.ts_fresh(ts)) else {
            return Verdict::Stale;
        };
        if c.algorithm
            .as_deref()
            .is_some_and(|a| !a.eq_ignore_ascii_case("MD5"))
        {
            return Verdict::Bad(Bad::Unsupported("algorithm"));
        }
        // The nonce count, and what the response covers between the nonce
        // and HA2. Without qop (RFC 2069) that is nothing, and there is no
        // count: the answer is the nonce's first and only use.
        let (nc, covered) = match c.qop.as_deref() {
            None => (1, String::new()),
            Some(qop) if qop.eq_ignore_ascii_case("auth") => {
                let nc_text = c.nc.as_deref().unwrap_or("");
                let nc = match u32::from_str_radix(nc_text, 16) {
                    Ok(n)
                        if n > 0 && nc_text.len() <= 8 && nc_text.bytes().all(|b| b.is_ascii_hexdigit()) =>
                    {
                        n
                    }
                    _ => return Verdict::Bad(Bad::Unsupported("nc")),
                };
                let Some(cnonce) = c.cnonce.as_deref() else {
                    return Verdict::Bad(Bad::Unsupported("cnonce"));
                };
                (nc, format!("{}:{}:{}:", nc_text, cnonce, qop))
            }
            Some(_) => return Verdict::Bad(Bad::Unsupported("qop")),
        };
        if !same_uri(&c.uri, request_uri) {
            return Verdict::Bad(Bad::Uri);
        }
        let key = format!("{}:{}", c.nonce.to_ascii_lowercase(), c.username);
        let mut hash = None;
        let mut request = || *hash.get_or_insert_with(request);
        if let Some(u) = self.used.get(&key) {
            if nc <= u.nc && !u.recent.contains(&(nc, request())) {
                return Verdict::Stale;
            }
        }
        let ha1 = md5_hex(&format!(
            "{}:{}:{}",
            c.username,
            c.realm,
            password.unwrap_or(&self.dummy)
        ));
        let ha2 = md5_hex(&format!("{}:{}", method, c.uri));
        let expected = md5_hex(&format!("{}:{}:{}{}", ha1, c.nonce, covered, ha2));
        let right = equal(&expected, &c.response.trim().to_ascii_lowercase());
        if !right || password.is_none() {
            return Verdict::Bad(Bad::Password);
        }
        if self.used.len() >= MAX_USED && !self.used.contains_key(&key) {
            let (now, ttl) = (now_unix(), self.nonce_ttl);
            self.used
                .retain(|_, u| u.ts <= now + 5 && now - u.ts.min(now) <= ttl);
            if self.used.len() >= MAX_USED {
                let oldest = self.used.iter().min_by_key(|(_, u)| u.ts).map(|(k, _)| k.clone());
                self.used.remove(&oldest.unwrap_or_default());
            }
        }
        let this = (nc, request());
        let u = self.used.entry(key).or_insert(Used {
            ts,
            nc,
            recent: Vec::new(),
        });
        if !u.recent.contains(&this) {
            if u.recent.len() == RECENT {
                u.recent.remove(0);
            }
            u.recent.push(this);
        }
        u.nc = u.nc.max(nc);
        Verdict::Ok
    }
}

/// Does the digest `uri` name the Request-URI? Leniently, since the two may
/// be written differently: scheme and host case, an explicit default port,
/// URI parameters (;transport=udp, ;ob, ...) and headers don't matter, and
/// the users are only compared if both have one (sipp, for one, sends
/// sip:host:port for every request).
fn same_uri(digest_uri: &str, request_uri: &str) -> bool {
    if digest_uri.trim() == request_uri.trim() {
        return true;
    }
    let (Some(d), Some(r)) = (Uri::parse(digest_uri), Uri::parse(request_uri)) else {
        return false;
    };
    let host = match (parse_ip_host(&d.host), parse_ip_host(&r.host)) {
        (Some(a), Some(b)) => a == b,
        _ => d.host.eq_ignore_ascii_case(&r.host),
    };
    let user = match (&d.user, &r.user) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    };
    d.scheme == r.scheme && host && d.port_or_default() == r.port_or_default() && user
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &dyn Fn() -> [u8; 16] = &|| [1; 16];
    const OTHER_REQ: &dyn Fn() -> [u8; 16] = &|| [2; 16];

    #[test]
    fn rfc2617_example() {
        // the classic example from RFC 2617 section 3.5 (HTTP, but same math)
        let c = parse_credentials(
            "Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
             nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
             qop=auth, nc=00000001, cnonce=\"0a4f113b\", \
             response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        )
        .unwrap();
        let mut d = Digest::new("testrealm@host.com", "s");
        let a: SocketAddr = "192.168.1.10:5060".parse().unwrap();
        let uri = "/dir/index.html";
        // not our nonce: Stale (the client retries with a fresh one),
        // whether or not the password is right
        for pw in [Some("Circle Of Life"), Some("wrong"), None] {
            assert_eq!(d.verify(&c, "GET", uri, pw, a, REQ), Verdict::Stale);
        }
    }

    /// Credentials for `nonce` as a phone would compute them (qop=auth).
    fn answer(user: &str, pw: &str, method: &str, uri: &str, nonce: &str, nc: u32) -> Credentials {
        let ha1 = md5_hex(&format!("{}:pbx:{}", user, pw));
        let ha2 = md5_hex(&format!("{}:{}", method, uri));
        let resp = md5_hex(&format!("{}:{}:{:08x}:c0ffee:auth:{}", ha1, nonce, nc, ha2));
        parse_credentials(&format!(
            "Digest username=\"{}\",realm=\"pbx\",nonce=\"{}\",uri=\"{}\",response=\"{}\",\
             algorithm=MD5,qop=auth,nc={:08x},cnonce=\"c0ffee\"",
            user, nonce, uri, resp, nc
        ))
        .unwrap()
    }

    #[test]
    fn roundtrip() {
        let mut d = Digest::new("pbx", "secret");
        let a: SocketAddr = "192.168.1.10:5060".parse().unwrap();
        let other: SocketAddr = "192.168.1.66:5060".parse().unwrap();
        let nonce = d.nonce(a);
        assert_eq!(nonce.len(), 32);
        assert!(d.nonce_fresh(&nonce, a));
        assert!(!d.nonce_fresh(&nonce, other));
        assert!(!d.nonce_fresh("0000000000abc", a));
        assert_ne!(d.nonce(a), nonce, "every challenge gets its own nonce");
        let c = answer("101", "pw", "REGISTER", "sip:pbx", &nonce, 1);
        // replayed from elsewhere: the nonce isn't theirs
        assert_eq!(
            d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), other, REQ),
            Verdict::Stale
        );
        assert_eq!(
            d.verify(&c, "INVITE", "sip:pbx", Some("pw"), a, REQ),
            Verdict::Bad(Bad::Password)
        );
        let upper = Credentials {
            response: c.response.to_ascii_uppercase(),
            ..c.clone()
        };
        assert_eq!(
            d.verify(&upper, "REGISTER", "sip:pbx", Some("pw"), a, REQ),
            Verdict::Ok
        );
        let c = answer("101", "pw", "REGISTER", "sip:pbx", &nonce, 2);
        assert_eq!(
            d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), a, REQ),
            Verdict::Ok
        );
    }

    /// Whether a guess was right can only be learnt with a nonce of ours,
    /// i.e. after a round trip; and an unknown user looks like a wrong
    /// password.
    #[test]
    fn nonce_is_checked_before_the_password() {
        let mut d = Digest::new("pbx", "secret");
        let a: SocketAddr = "192.168.1.10:5060".parse().unwrap();
        let ours = d.nonce(a);
        let forged = [
            "0000000000ffffffffffffffffffff".to_string(),
            format!("{}{}", &ours[..31], if ours.ends_with('0') { '1' } else { '0' }),
            format!(
                "{:010x}{}",
                u64::from_str_radix(&ours[..10], 16).unwrap() + 1,
                &ours[10..]
            ),
            ours[..31].to_string(),
            format!("{}0", ours),
            format!("{}é", &ours[..30]),
        ];
        for nonce in &forged {
            for pw in ["pw", "wrong"] {
                let c = answer("101", pw, "REGISTER", "sip:pbx", nonce, 1);
                let v = d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), a, REQ);
                assert_eq!(v, Verdict::Stale, "{nonce} {pw}");
            }
        }
        let c = answer("101", "wrong", "REGISTER", "sip:pbx", &ours, 1);
        let v = d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), a, REQ);
        assert_eq!(v, Verdict::Bad(Bad::Password));
        // unknown user, even with the stand-in password
        let dummy = d.dummy.clone();
        let c = answer("999", &dummy, "REGISTER", "sip:pbx", &ours, 1);
        let v = d.verify(&c, "REGISTER", "sip:pbx", None, a, REQ);
        assert_eq!(v, Verdict::Bad(Bad::Password));
        // expired
        crate::util::test_clock::step_wall(d.nonce_ttl as i64 + 1);
        let c = answer("101", "pw", "REGISTER", "sip:pbx", &ours, 1);
        assert_eq!(
            d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), a, REQ),
            Verdict::Stale
        );
    }

    /// A response is good for one request: the nonce count must go up
    /// (except for a retransmission of the very same request), and a
    /// response without qop, which has no count, uses the nonce up.
    #[test]
    fn responses_cannot_be_replayed() {
        let mut d = Digest::new("pbx", "secret");
        let a: SocketAddr = "192.168.1.10:5060".parse().unwrap();
        let n1 = d.nonce(a);
        let ok =
            |d: &mut Digest, c: &Credentials, req| d.verify(c, "REGISTER", "sip:pbx", Some("pw"), a, req);
        let c1 = answer("101", "pw", "REGISTER", "sip:pbx", &n1, 1);
        assert_eq!(ok(&mut d, &c1, REQ), Verdict::Ok);
        assert_eq!(ok(&mut d, &c1, REQ), Verdict::Ok, "retransmission");
        assert_eq!(
            ok(&mut d, &c1, OTHER_REQ),
            Verdict::Stale,
            "replay in another request"
        );
        let c3 = answer("101", "pw", "REGISTER", "sip:pbx", &n1, 3);
        assert_eq!(ok(&mut d, &c3, OTHER_REQ), Verdict::Ok, "counts may skip");
        let c2 = answer("101", "pw", "REGISTER", "sip:pbx", &n1, 2);
        assert_eq!(ok(&mut d, &c2, OTHER_REQ), Verdict::Stale, "count went down");
        assert_eq!(
            ok(&mut d, &c1, REQ),
            Verdict::Ok,
            "retransmission of an earlier request"
        );
        assert_eq!(ok(&mut d, &c1, OTHER_REQ), Verdict::Stale);
        for nc in 4..4 + RECENT as u32 {
            let c = answer("101", "pw", "REGISTER", "sip:pbx", &n1, nc);
            assert_eq!(ok(&mut d, &c, REQ), Verdict::Ok);
        }
        assert_eq!(ok(&mut d, &c1, REQ), Verdict::Stale, "too long ago");
        // a second line of the same phone keeps its own count for the nonce
        let other = answer("102", "pw", "REGISTER", "sip:pbx", &n1, 1);
        assert_eq!(ok(&mut d, &other, OTHER_REQ), Verdict::Ok);
        // a wrong password doesn't use up a count
        let n2 = d.nonce(a);
        let wrong = answer("101", "nope", "REGISTER", "sip:pbx", &n2, 9);
        assert_eq!(ok(&mut d, &wrong, REQ), Verdict::Bad(Bad::Password));
        let c = answer("101", "pw", "REGISTER", "sip:pbx", &n2, 1);
        assert_eq!(ok(&mut d, &c, REQ), Verdict::Ok);
        // Without qop (RFC 2069) the response doesn't cover a count: it is
        // accepted, and uses the nonce up.
        let rfc2069 = |nonce: &str, pw: &str| {
            let ha1 = md5_hex(&format!("101:pbx:{}", pw));
            let ha2 = md5_hex("REGISTER:sip:pbx");
            let resp = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));
            parse_credentials(&format!(
                "Digest username=\"101\",realm=\"pbx\",nonce=\"{}\",uri=\"sip:pbx\",response=\"{}\"",
                nonce, resp
            ))
            .unwrap()
        };
        let n3 = d.nonce(a);
        assert_eq!(
            ok(&mut d, &rfc2069(&n3, "nope"), REQ),
            Verdict::Bad(Bad::Password)
        );
        let old = rfc2069(&n3, "pw");
        assert_eq!(ok(&mut d, &old, REQ), Verdict::Ok);
        assert_eq!(ok(&mut d, &old, REQ), Verdict::Ok, "retransmission");
        assert_eq!(
            ok(&mut d, &old, OTHER_REQ),
            Verdict::Stale,
            "replay in another request"
        );
        let c1 = answer("101", "pw", "REGISTER", "sip:pbx", &n3, 1);
        assert_eq!(
            ok(&mut d, &c1, OTHER_REQ),
            Verdict::Stale,
            "the first count is used up too"
        );
        let n3 = d.nonce(a);
        let other_qop = Credentials {
            qop: Some("auth-int".into()),
            ..answer("101", "pw", "REGISTER", "sip:pbx", &n3, 1)
        };
        assert_eq!(ok(&mut d, &other_qop, REQ), Verdict::Bad(Bad::Unsupported("qop")));
        for (nc, why) in [
            (None, "nc"),
            (Some("0"), "nc"),
            (Some("x1"), "nc"),
            (Some("100000000"), "nc"),
        ] {
            let c = Credentials {
                nc: nc.map(str::to_string),
                ..answer("101", "pw", "REGISTER", "sip:pbx", &n3, 1)
            };
            assert_eq!(ok(&mut d, &c, REQ), Verdict::Bad(Bad::Unsupported(why)), "{nc:?}");
        }
        let c = Credentials {
            cnonce: None,
            ..answer("101", "pw", "REGISTER", "sip:pbx", &n3, 1)
        };
        assert_eq!(ok(&mut d, &c, REQ), Verdict::Bad(Bad::Unsupported("cnonce")));
    }

    #[test]
    fn digest_uri_must_be_the_request_uri() {
        let mut d = Digest::new("pbx", "secret");
        let a: SocketAddr = "192.168.1.10:5060".parse().unwrap();
        let nonce = d.nonce(a);
        let mut nc = 0;
        let mut check = |uri: &str, ruri: &str| {
            nc += 1;
            let c = answer("101", "pw", "INVITE", uri, &nonce, nc);
            d.verify(&c, "INVITE", ruri, Some("pw"), a, REQ)
        };
        for (uri, ruri) in [
            ("sip:102@pbx", "sip:102@pbx"),
            ("sip:102@PBX:5060", "SIP:102@pbx"),
            ("sip:102@pbx", "sip:102@pbx;transport=udp"),
            ("sip:102@127.0.0.1:5092;ob", "sip:102@127.0.0.1:5092"),
            ("sip:102@[::1]:5060", "sip:102@[0:0::1]"),
            ("sip:127.0.0.2:5060", "sip:102@127.0.0.2:5060"), // sipp
            ("tel:102", "tel:102"),
        ] {
            assert_eq!(check(uri, ruri), Verdict::Ok, "{uri} for {ruri}");
        }
        for (uri, ruri) in [
            ("sip:102@pbx", "sip:103@pbx"),
            ("sip:102@pbx", "sip:102@pbx:5070"),
            ("sip:102@pbx", "sips:102@pbx"),
            ("sip:102@pbx", "sip:102@other"),
            ("sip:102@pbx", "tel:102"),
            ("", "sip:102@pbx"),
        ] {
            assert_eq!(check(uri, ruri), Verdict::Bad(Bad::Uri), "{uri} for {ruri}");
        }
    }

    #[test]
    fn remembered_counts_are_bounded() {
        let mut d = Digest::new("pbx", "secret");
        let a: SocketAddr = "192.168.1.10:5060".parse().unwrap();
        let first = d.nonce(a);
        let c = answer("101", "pw", "REGISTER", "sip:pbx", &first, 1);
        assert_eq!(
            d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), a, REQ),
            Verdict::Ok
        );
        crate::util::test_clock::step_wall(d.nonce_ttl as i64 + 1);
        for _ in 0..MAX_USED + 10 {
            let n = d.nonce(a);
            let c = answer("101", "pw", "REGISTER", "sip:pbx", &n, 1);
            assert_eq!(
                d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), a, REQ),
                Verdict::Ok
            );
        }
        assert!(d.used.len() <= MAX_USED);
        assert!(
            !d.used.keys().any(|k| k.starts_with(&first)),
            "expired nonces go first"
        );
    }

    #[test]
    fn correct_password_works_after_repeated_bad_guesses() {
        let mut d = Digest::new("pbx", "secret");
        let a: SocketAddr = "192.168.1.10:5060".parse().unwrap();
        let nonce = d.nonce(a);
        for i in 0..20 {
            let c = answer("101", &format!("guess{i}"), "REGISTER", "sip:pbx", &nonce, 1);
            assert_eq!(
                d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), a, REQ),
                Verdict::Bad(Bad::Password)
            );
        }
        let c = answer("101", "pw", "REGISTER", "sip:pbx", &nonce, 1);
        assert_eq!(
            d.verify(&c, "REGISTER", "sip:pbx", Some("pw"), a, REQ),
            Verdict::Ok
        );
    }
}
