//! Location service: extension -> registered contacts, persisted to a small
//! text file so a restart doesn't make phones unreachable until they
//! re-register.
//!
//! Expiry runs on the monotonic clock, so setting the wall clock (NTP after
//! booting a Raspberry Pi without RTC) neither expires every phone at once
//! nor keeps them forever. Only the state file uses wall-clock times, and
//! what is loaded from it is limited to max_expires.

use crate::sip::{find_param, parse_params, Uri};
use crate::util::{clip, ip_addr, mono_now, now_unix, INFO, WARN};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Binding {
    /// Contact URI as sent by the phone.
    pub contact: String,
    /// Contact header params (without expires), echoed back in 200 OK.
    pub params: String,
    /// Where the REGISTER came from; requests are sent here (NAT friendly).
    pub source: SocketAddr,
    /// When the binding expires (monotonic clock, see `mono_now`).
    pub expires: Instant,
    /// When this device first registered (kept across refreshes).
    pub registered: Instant,
    pub call_id: String,
    pub cseq: u32,
    pub user_agent: String,
    /// Our address the phone registered to (None: unknown). Requests to the
    /// phone are sent from it, as a phone may accept SIP only from the
    /// server it registered with.
    pub local: Option<IpAddr>,
}

impl Binding {
    /// Seconds until expiry, rounded up: a binding that was just registered
    /// for 3600 s still has 3600 s, and one that is live has at least 1.
    pub fn expires_in(&self, now: Instant) -> u64 {
        let d = self.expires.saturating_duration_since(now);
        d.as_secs() + u64::from(d.subsec_nanos() > 0)
    }

    /// Does `uri` point at this binding's contact (same host and port)?
    pub fn matches_hostport(&self, uri: &Uri) -> bool {
        match Uri::parse(&self.contact) {
            Some(c) => c.host.eq_ignore_ascii_case(&uri.host) && c.port_or_default() == uri.port_or_default(),
            None => false,
        }
    }
}

fn instance(params: &str) -> Option<String> {
    let p = parse_params(params);
    find_param(&p, "+sip.instance")
        .flatten()
        .map(|v| v.to_ascii_lowercase())
}

/// Normalize escaped unreserved characters, but do not turn escaped reserved
/// characters (e.g. %2F) into URI delimiters. RFC 3261 section 19.1.4.
fn uri_unescape(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16).map(|n| n as u8);
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                let c = hi * 16 + lo;
                if c.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&c) {
                    out.push(c);
                } else {
                    out.extend([
                        b'%',
                        bytes[i + 1].to_ascii_uppercase(),
                        bytes[i + 2].to_ascii_uppercase(),
                    ]);
                }
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Only ASCII escapes were decoded, so UTF-8 remains valid.
    String::from_utf8(out).unwrap()
}

/// Binding identity, not routing equivalence: explicit default ports and
/// transports are NOT interchangeable with omitted ones. Keep the original
/// Contact string in Binding for forwarding and responses.
fn same_contact(a: &str, b: &str) -> bool {
    // Uri::parse intentionally discards passwords. Compare complete userinfo
    // separately, and parse the host part so '?' in userinfo is not a header.
    let parse = |s: &str| {
        let (scheme, rest) = s.trim().split_once(':')?;
        let (userinfo, hostpart) = match rest.split_once('@') {
            Some((u, h)) => (Some(uri_unescape(u)), h),
            None => (None, rest),
        };
        Some((userinfo, Uri::parse(&format!("{}:{}", scheme, hostpart))?))
    };
    let (Some((au, a)), Some((bu, b))) = (parse(a), parse(b)) else {
        return false;
    };
    if a.scheme != b.scheme || au != bu || !a.host.eq_ignore_ascii_case(&b.host) || a.port != b.port {
        return false;
    }
    let params = |s: &str| {
        parse_params(s)
            .into_iter()
            .map(|(k, v)| {
                let k = uri_unescape(&k).to_ascii_lowercase();
                let v = v.map(|v| {
                    let mut v = uri_unescape(&v);
                    // SIP method names, unlike other standard URI parameter
                    // values, are case-sensitive (RFC 3261 section 7.1).
                    if k != "method" {
                        v.make_ascii_lowercase();
                    }
                    v
                });
                (k, v)
            })
            .collect::<Vec<_>>()
    };
    let mut ap = params(&a.params);
    let mut bp = params(&b.params);
    ap.sort();
    bp.sort();
    // (sorted by name, so this is a binary search: O(n log n) in all)
    let significant = |k: &str, other: &[(String, Option<String>)]| {
        matches!(k, "transport" | "user" | "ttl" | "method" | "maddr")
            || other.binary_search_by(|(name, _)| name.as_str().cmp(k)).is_ok()
    };
    // Extension parameters present on only one side are ignored. This is
    // deliberately a pairwise comparison, not a canonical map key.
    let ac = ap.iter().filter(|(k, _)| significant(k, &bp));
    let bc = bp.iter().filter(|(k, _)| significant(k, &ap));
    if !ac.eq(bc) {
        return false;
    }
    let headers = |s: &str| {
        let mut h: Vec<_> = s
            .strip_prefix('?')
            .unwrap_or(s)
            .split('&')
            .filter(|h| !h.is_empty())
            .map(|h| {
                let (name, value) = h.split_once('=').unwrap_or((h, ""));
                let name = crate::sip::canonical_name(&uri_unescape(name)).to_ascii_lowercase();
                let mut value = uri_unescape(value);
                // Simple standard text/token headers are case-insensitive.
                // Keep other values opaque: Call-ID, body, and userinfo/tags
                // in address headers must not be indiscriminately folded.
                if matches!(
                    name.as_str(),
                    "subject"
                        | "organization"
                        | "priority"
                        | "supported"
                        | "require"
                        | "proxy-require"
                        | "unsupported"
                        | "content-encoding"
                        | "content-language"
                ) {
                    value.make_ascii_lowercase();
                }
                (name, value)
            })
            .collect();
        h.sort();
        h
    };
    headers(&a.headers) == headers(&b.headers)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegisterError {
    StaleCSeq,
    TooManyContacts,
}

pub const MAX_BINDINGS_PER_EXT: usize = 5;
/// Limits for one REGISTER: number of updates, bytes per Contact, and URI /
/// header parameters per Contact. A request whose own Contacts exceed
/// MAX_BINDINGS_PER_EXT is refused as a whole; otherwise older bindings of
/// the extension make room for it (see `update_many`).
pub const MAX_CONTACTS: usize = 16;
pub const MAX_CONTACT_LEN: usize = 2048;
pub const MAX_CONTACT_PARAMS: usize = 32;
/// User-Agent strings are stored, logged and shown by `status`; this is
/// plenty for e.g. "Yealink SIP-T46U 108.86.0.20".
pub const MAX_USER_AGENT: usize = 128;

pub fn truncate_user_agent(ua: &str) -> String {
    ua.chars().take(MAX_USER_AGENT).collect()
}

#[derive(Debug, PartialEq)]
pub enum Change {
    New,
    Refreshed,
    Moved,
    Removed,
    Ignored,
}

pub struct Registrar {
    bindings: BTreeMap<String, Vec<Binding>>,
    path: Option<PathBuf>,
    warned: bool,
}

impl Registrar {
    /// Load the bindings saved in `path`. Their remaining lifetime is
    /// limited to `max_expires`: the file holds wall-clock times, and the
    /// clock may have been wrong when it was written, or be wrong now.
    pub fn new(path: Option<PathBuf>, max_expires: u32) -> Registrar {
        let mut r = Registrar {
            bindings: BTreeMap::new(),
            path,
            warned: false,
        };
        r.load(max_expires);
        r
    }

    fn purge(&mut self) {
        let now = mono_now();
        for list in self.bindings.values_mut() {
            list.retain(|b| b.expires > now);
        }
        self.bindings.retain(|_, l| !l.is_empty());
    }

    /// Current (unexpired) bindings of an extension, newest first.
    pub fn get(&self, ext: &str) -> Vec<Binding> {
        let now = mono_now();
        let mut v: Vec<(usize, &Binding)> = self
            .bindings
            .get(ext)
            .map(|l| l.iter().enumerate().filter(|(_, b)| b.expires > now).collect())
            .unwrap_or_default();
        // newest first; at the same time, the one added later wins
        v.sort_by_key(|(i, b)| std::cmp::Reverse((b.registered, *i)));
        v.into_iter().map(|(_, b)| b.clone()).collect()
    }

    /// The contact to send calls to: the most recently registered one.
    pub fn lookup(&self, ext: &str) -> Option<Binding> {
        self.get(ext).into_iter().next()
    }

    /// Is there a live binding from this address — for extension `ext`, or
    /// for any extension if `ext` is None? (A phone with several lines
    /// registers several extensions from the same address.)
    pub fn registered_from(&self, src: SocketAddr, ext: Option<&str>) -> bool {
        let now = mono_now();
        self.bindings
            .iter()
            .filter(|(e, _)| ext.is_none_or(|x| x == e.as_str()))
            .any(|(_, l)| l.iter().any(|b| b.expires > now && b.source == src))
    }

    /// Find a binding (of any extension) whose contact host:port is `uri`:
    /// one registered from that very address if there is one (it is
    /// provably there), else the newest.
    pub fn find_by_contact(&self, uri: &Uri) -> Option<Binding> {
        let now = mono_now();
        let at = ip_addr(&uri.host, uri.port_or_default());
        self.bindings
            .values()
            .flatten()
            .filter(|b| b.expires > now && b.matches_hostport(uri))
            .max_by_key(|b| (Some(b.source) == at, b.registered))
            .cloned()
    }

    /// Is `uri` (a Contact that `ext` wants to register from `source`)
    /// already the Contact address of another extension, registered from
    /// another host? Then `find_by_contact` would let `ext` receive that
    /// extension's in-dialog requests. Not if `uri` is `source` itself:
    /// the phone is provably there (it answered a challenge sent there),
    /// and `find_by_contact` prefers it. The same host may register
    /// several extensions (a phone with several lines, also behind NAT).
    pub fn contact_taken(&self, ext: &str, uri: &Uri, source: SocketAddr) -> Option<(String, Binding)> {
        if ip_addr(&uri.host, uri.port_or_default()) == Some(source) {
            return None;
        }
        let now = mono_now();
        self.bindings
            .iter()
            .filter(|(e, _)| e.as_str() != ext)
            .flat_map(|(e, l)| l.iter().map(move |b| (e, b)))
            .find(|(_, b)| b.expires > now && b.source.ip() != source.ip() && b.matches_hostport(uri))
            .map(|(e, b)| (e.clone(), b.clone()))
    }

    pub fn all(&self) -> Vec<(String, Binding)> {
        let now = mono_now();
        self.bindings
            .iter()
            .flat_map(|(e, l)| {
                l.iter()
                    .filter(|b| b.expires > now)
                    .map(move |b| (e.clone(), b.clone()))
            })
            .collect()
    }

    /// Single-contact convenience API for test setup. Production REGISTERs
    /// use update_many and report errors to the phone.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        &mut self,
        ext: &str,
        contact: &str,
        params: &str,
        source: SocketAddr,
        expires_in: u32,
        call_id: &str,
        cseq: u32,
        user_agent: &str,
    ) -> Change {
        self.update_many(
            ext,
            &[(contact.to_string(), params.to_string(), expires_in)],
            (source, None),
            call_id,
            cseq,
            user_agent,
        )
        .map(|mut changes| changes.remove(0))
        .unwrap_or(Change::Ignored)
    }

    /// Apply all Contacts of one REGISTER atomically. Check every affected
    /// binding against the pre-request state, including device replacements,
    /// before changing anything. Contacts in this request share one CSeq and
    /// must not be mistaken for retransmissions of each other.
    pub fn update_many(
        &mut self,
        ext: &str,
        updates: &[(String, String, u32)],
        (source, local): (SocketAddr, Option<IpAddr>),
        call_id: &str,
        cseq: u32,
        user_agent: &str,
    ) -> Result<Vec<Change>, RegisterError> {
        self.purge();
        let now = mono_now();
        let list = self.bindings.get(ext).map(Vec::as_slice).unwrap_or(&[]);
        let mut retransmission = false;
        for (contact, _, exp) in updates {
            // Sequence numbers are comparable only within this Call-ID.
            // A positive update may replace a device's old Contact; a
            // removal applies only to the named Contact.
            for b in list
                .iter()
                .filter(|b| b.call_id == call_id && (*exp != 0 || same_contact(&b.contact, contact)))
            {
                if cseq < b.cseq || (cseq == b.cseq && source != b.source) {
                    return Err(RegisterError::StaleCSeq);
                }
                if cseq == b.cseq {
                    retransmission = true;
                }
            }
        }
        if retransmission {
            // A duplicate REGISTER is a successful transaction, not a new
            // binding update. Reply with current Contacts, including for a
            // request listing several Contacts from this same endpoint.
            return Ok((0..updates.len()).map(|_| Change::Ignored).collect());
        }
        // Contacts of this request are applied in order. Each may replace
        // an older binding of the same device (same source or instance),
        // but never another Contact of this same request: a phone may
        // register several (RFC 3261 section 10.3), e.g. IPv4 and IPv6.
        let listed = |b: &Binding| updates.iter().any(|(c, _, _)| same_contact(&b.contact, c));
        let user_agent = truncate_user_agent(user_agent);
        let mut work = list.to_vec();
        let mut changes = Vec::with_capacity(updates.len());
        for (contact, params, exp) in updates {
            let exact = |b: &Binding| same_contact(&b.contact, contact);
            let pos = work.iter().position(exact);
            if *exp == 0 {
                work.retain(|b| !exact(b));
                changes.push(if pos.is_some() {
                    Change::Removed
                } else {
                    Change::Ignored
                });
                continue;
            }
            // Refreshing a known Contact does not replace the device's
            // other Contacts at this source. Still retire bindings at an
            // old source when the device moves.
            let inst = instance(params);
            let matches = |b: &Binding| {
                if exact(b) {
                    return true;
                }
                if (pos.is_some() && b.source == source) || listed(b) {
                    return false;
                }
                b.source == source || b.call_id == call_id || (inst.is_some() && instance(&b.params) == inst)
            };
            let moved = work.iter().any(|b| matches(b) && b.source != source);
            let change = match pos {
                _ if moved => Change::Moved,
                Some(_) => Change::Refreshed,
                None => Change::New,
            };
            let new = Binding {
                contact: contact.clone(),
                params: params.clone(),
                source,
                expires: now + Duration::from_secs((*exp).into()),
                // A refresh keeps its place in the "newest device" order.
                registered: pos.map_or(now, |i| work[i].registered),
                call_id: call_id.to_string(),
                cseq,
                user_agent: user_agent.clone(),
                local,
            };
            let insert_at = pos.map(|i| work[..i].iter().filter(|w| !matches(w)).count());
            work.retain(|w| !matches(w));
            let at = insert_at.unwrap_or(work.len());
            work.insert(at, new);
            changes.push(change);
        }
        // Only the final result counts: a request may add a Contact before
        // removing another. A phone that registers always gets in; an older
        // binding makes room. First what the registering host left behind
        // itself (a softphone that restarted on a new port without
        // unregistering would otherwise lock its extension until those
        // expire), then whatever expires soonest, i.e. (for equal intervals)
        // was heard from longest ago. Never a Contact of this request: one
        // that lists more than the limit by itself is refused, and nothing
        // is changed.
        let mut dropped = Vec::new();
        while work.len() > MAX_BINDINGS_PER_EXT {
            let stalest = work
                .iter()
                .enumerate()
                .filter(|(_, b)| !listed(b))
                .min_by_key(|(i, b)| (b.source.ip() != source.ip(), b.expires, b.registered, *i))
                .map(|(i, _)| i);
            let Some(i) = stalest else {
                return Err(RegisterError::TooManyContacts);
            };
            dropped.push(work.remove(i));
        }
        for b in &dropped {
            crate::log!(
                INFO,
                "{} has more than {} devices: dropped {} from {} (would have expired in {}s)",
                ext,
                MAX_BINDINGS_PER_EXT,
                clip(&b.contact),
                b.source,
                b.expires_in(now)
            );
        }
        if work.is_empty() {
            self.bindings.remove(ext);
        } else {
            self.bindings.insert(ext.to_string(), work);
        }
        Ok(changes)
    }

    /// Our address that the phone at `source` registered to (as the newest
    /// of its live bindings that knows it says, of any extension).
    pub fn local_for(&self, source: SocketAddr) -> Option<IpAddr> {
        let now = mono_now();
        self.bindings
            .values()
            .flatten()
            .filter(|b| b.expires > now && b.source == source && b.local.is_some())
            .max_by_key(|b| b.registered)
            .and_then(|b| b.local)
    }

    /// Ordered wildcard REGISTER removal (RFC 3261 section 10.3, step 6).
    /// Different Call-IDs have independent sequence spaces. One stale binding
    /// rejects the entire request, including removals of other devices.
    pub fn unregister_all(&mut self, ext: &str, call_id: &str, cseq: u32) -> Result<bool, RegisterError> {
        self.purge();
        if self
            .bindings
            .get(ext)
            .is_some_and(|list| list.iter().any(|b| b.call_id == call_id && cseq <= b.cseq))
        {
            return Err(RegisterError::StaleCSeq);
        }
        Ok(self.remove_all(ext))
    }

    /// Administrative removal, without REGISTER ordering checks.
    pub fn remove_all(&mut self, ext: &str) -> bool {
        self.bindings.remove(ext).is_some()
    }

    /// Drop extensions that are no longer configured.
    pub fn retain_exts(&mut self, keep: impl Fn(&str) -> bool) {
        self.bindings.retain(|e, _| keep(e));
    }

    // ------------------------------------------------------------ persistence

    /// Registrations are a cache: skip invalid or excess rows, keeping the
    /// other phones reachable. Loading never modifies the file (also used by
    /// `status`); the next save atomically replaces it with valid bindings.
    fn load(&mut self, max_expires: u32) {
        let Some(path) = &self.path else { return };
        let data = match std::fs::read(path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                crate::log!(WARN, "cannot read registrations from {}: {}", path.display(), e);
                return;
            }
        };
        let (wall, now) = (now_unix(), mono_now());
        let mut skipped = false;
        let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&data);
        for raw in data.split(|&c| c == b'\n') {
            let Ok(line) = std::str::from_utf8(raw) else {
                skipped = true;
                continue;
            };
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((ext, binding)) = parse_line(line, wall, now, max_expires) else {
                skipped = true;
                continue;
            };
            if binding.expires <= now {
                continue;
            }
            let list = self.bindings.entry(ext).or_default();
            if list.len() < MAX_BINDINGS_PER_EXT {
                list.push(binding);
            } else {
                skipped = true;
            }
        }
        if skipped {
            crate::log!(
                WARN,
                "{}: skipped invalid or excess registrations",
                path.display()
            );
        }
    }

    /// Replace `path` atomically and durably: write and fsync a temporary
    /// file, rename it over `path`, then fsync the directory so the rename
    /// survives a power cut (a Pi pulled from the wall). On failure (e.g. a
    /// full disk) the temporary file is removed and `path` is untouched.
    fn write_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let tmp = sibling(path, ".tmp");
        let written = std::fs::File::create(&tmp).and_then(|mut f| {
            f.write_all(data)?;
            f.sync_all()
        });
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        let dir = path.parent().filter(|d| !d.as_os_str().is_empty());
        if let Ok(d) = std::fs::File::open(dir.unwrap_or(std::path::Path::new("."))) {
            let _ = d.sync_all(); // best effort: not every filesystem supports it
        }
        Ok(())
    }

    pub fn save(&mut self) {
        let Some(path) = self.path.clone() else { return };
        let clean = |s: &str| s.replace(['\t', '\r', '\n'], " ");
        // Monotonic times in memory -> wall-clock times in the file.
        let (wall, now) = (now_unix(), mono_now());
        let mut out = String::from(
            "# ext\tcontact\tparams\tsource\texpires\tregistered\tcall-id\tcseq\tuser-agent\tlocal\n",
        );
        for (ext, b) in self.all() {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                clean(&ext),
                clean(&b.contact),
                clean(&b.params),
                b.source,
                wall + b.expires_in(now),
                wall.saturating_sub(now.saturating_duration_since(b.registered).as_secs()),
                clean(&b.call_id),
                b.cseq,
                clean(&b.user_agent),
                b.local.map(|ip| ip.to_string()).unwrap_or_default()
            ));
        }
        let res = Self::write_file(&path, out.as_bytes());
        if let Err(e) = res {
            if !self.warned {
                crate::log!(WARN, "cannot save registrations to {}: {}", path.display(), e);
                self.warned = true;
            }
        } else {
            self.warned = false;
        }
    }
}

/// Parse a cache row, converting wall-clock times to bounded monotonic ones.
/// Expired rows are valid but are discarded by the loader.
fn parse_line(line: &str, wall: u64, now: Instant, max_expires: u32) -> Option<(String, Binding)> {
    let f: Vec<&str> = line.split('\t').collect();
    // The tenth field (local) came later and may be missing; more fields
    // are ignored, for a newer version's additions.
    if f.len() < 9
        || f[0].is_empty()
        || Uri::parse(f[1]).is_none()
        || f[1].len() + f[2].len() > MAX_CONTACT_LEN
    {
        return None;
    }
    let (expires, registered): (u64, u64) = (f[4].parse().ok()?, f[5].parse().ok()?);
    let (source, cseq) = (f[3].parse().ok()?, f[7].parse().ok()?);
    let left = expires.saturating_sub(wall);
    let age = Duration::from_secs(wall.saturating_sub(registered));
    let binding = Binding {
        contact: f[1].to_string(),
        params: f[2].to_string(),
        source,
        expires: now + Duration::from_secs(left.min(max_expires.into())),
        // "registered" in the future (the clock was ahead): now
        registered: now.checked_sub(age).unwrap_or(now),
        call_id: f[6].to_string(),
        cseq,
        user_agent: truncate_user_agent(f[8]),
        local: f.get(9).and_then(|l| l.parse().ok()),
    };
    Some((f[0].to_string(), binding))
}

/// Append a suffix without replacing the filename's extension.
fn sibling(path: &std::path::Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lifecycle() {
        let dir = crate::util::TestDir::create();
        let path = dir.join("b.txt");
        let mut r = Registrar::new(Some(path.clone()), 3600);
        let a = addr("192.168.1.10:5060");
        assert_eq!(
            r.update("101", "sip:101@192.168.1.10", "", a, 60, "c1", 1, "ua"),
            Change::New
        );
        assert_eq!(
            r.update("101", "sip:101@192.168.1.10", "", a, 60, "c1", 1, "ua"),
            Change::Ignored
        );
        assert_eq!(
            r.update("101", "sip:101@192.168.1.10", "", a, 60, "c1", 2, "ua"),
            Change::Refreshed
        );
        assert_eq!(
            r.update(
                "101",
                "sip:101@192.168.1.10",
                "",
                addr("1.2.3.4:999"),
                60,
                "c2",
                1,
                "ua"
            ),
            Change::Moved
        );
        assert!(r.registered_from(addr("1.2.3.4:999"), Some("101")));
        assert!(r.registered_from(addr("1.2.3.4:999"), None));
        assert!(!r.registered_from(a, None));
        // a second line on the same phone
        assert_eq!(
            r.update(
                "102",
                "sip:102@192.168.1.10",
                "",
                addr("1.2.3.4:999"),
                60,
                "c3",
                1,
                "ua"
            ),
            Change::New
        );
        assert!(r.registered_from(addr("1.2.3.4:999"), Some("101")));
        assert!(r.registered_from(addr("1.2.3.4:999"), Some("102")));
        assert!(!r.registered_from(addr("1.2.3.4:999"), Some("103")));
        assert!(r.remove_all("102"));
        // same device, new contact (e.g. new port): replaces the old binding
        let b = addr("192.168.1.20:5060");
        assert_eq!(
            r.update("103", "sip:103@192.168.1.20", "", b, 60, "d1", 1, "ua"),
            Change::New
        );
        assert_eq!(
            r.update("103", "sip:103@192.168.1.20:5070", "", b, 60, "d2", 1, "ua"),
            Change::New
        );
        assert_eq!(r.get("103").len(), 1);
        let inst = ";+sip.instance=\"<urn:uuid:AB>\"";
        assert_eq!(
            r.update(
                "103",
                "sip:103@192.168.1.21",
                inst,
                addr("192.168.1.21:5060"),
                60,
                "d3",
                1,
                "ua"
            ),
            Change::New
        );
        // the same device (+sip.instance) from a new address
        assert_eq!(
            r.update(
                "103",
                "sip:103@192.168.1.22",
                inst,
                addr("192.168.1.22:5060"),
                60,
                "d4",
                1,
                "ua"
            ),
            Change::Moved
        );
        let l = r.get("103");
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].contact, "sip:103@192.168.1.22");
        // a refresh doesn't make a device "newer" than one that registered later
        crate::util::test_clock::advance(1);
        assert_eq!(
            r.update("103", "sip:103@192.168.1.20:5070", "", b, 60, "d2", 2, "ua"),
            Change::Refreshed
        );
        assert_eq!(r.lookup("103").unwrap().contact, "sip:103@192.168.1.22");
        let u = Uri::parse("sip:whoever@192.168.1.10:5060;transport=udp").unwrap();
        assert_eq!(r.find_by_contact(&u).unwrap().source, addr("1.2.3.4:999"));
        r.save();
        let r2 = Registrar::new(Some(path.clone()), 3600);
        // The file has whole seconds, so times are only equal to within 1 s.
        let (old, new) = (r.lookup("101").unwrap(), r2.lookup("101").unwrap());
        let now = mono_now();
        assert!(new.expires_in(now).abs_diff(old.expires_in(now)) <= 1);
        assert!(
            now.duration_since(new.registered)
                .abs_diff(now.duration_since(old.registered))
                <= Duration::from_secs(1)
        );
        assert_eq!(
            Binding {
                expires: old.expires,
                registered: old.registered,
                ..new
            },
            old
        );
        assert_eq!(
            r.update("101", "sip:101@192.168.1.10", "", a, 0, "c2", 2, "ua"),
            Change::Removed
        );
        assert!(r.lookup("101").is_none());
    }

    /// The address a phone registered to survives a restart; state files
    /// from before it was saved (nine fields) still load.
    #[test]
    fn local_address_is_kept_and_saved() {
        let dir = crate::util::TestDir::create();
        let path = dir.join("b.txt");
        let mut r = Registrar::new(Some(path.clone()), 3600);
        let (a, b) = (addr("192.168.1.10:5060"), addr("[fd00::10]:5060"));
        let (la, lb): (IpAddr, IpAddr) = ("192.168.1.2".parse().unwrap(), "fd00::2".parse().unwrap());
        r.update("102", "sip:102@192.168.1.10", "", a, 60, "c2", 1, "ua");
        assert_eq!(r.local_for(a), None);
        for (ext, uri, src, local) in [
            ("101", "sip:101@192.168.1.10", a, la),
            ("103", "sip:103@[fd00::10]", b, lb),
        ] {
            r.update_many(
                ext,
                &[(uri.into(), String::new(), 60)],
                (src, Some(local)),
                ext,
                1,
                "ua",
            )
            .unwrap();
        }
        assert_eq!(r.lookup("102").unwrap().local, None, "per extension");
        assert_eq!(r.local_for(a), Some(la));
        assert_eq!(r.local_for(b), Some(lb));
        r.save();
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved
            .lines()
            .any(|l| l.starts_with("103\t") && l.ends_with("\tfd00::2")));
        let r2 = Registrar::new(Some(path.clone()), 3600);
        assert_eq!(r2.lookup("101").unwrap().local, Some(la));
        assert_eq!(r2.lookup("102").unwrap().local, None);
        assert_eq!(r2.lookup("103").unwrap().local, Some(lb));
        // an older version's file: nine fields; and a damaged local
        let wall = now_unix();
        let old = format!(
            "101\tsip:101@192.168.1.10\t\t{a}\t{e}\t{wall}\tc1\t1\tua\n\
             102\tsip:102@192.168.1.10\t\t{a}\t{e}\t{wall}\tc2\t1\tua\tnot-an-ip\textra\n",
            e = wall + 60
        );
        std::fs::write(&path, old).unwrap();
        let r3 = Registrar::new(Some(path), 3600);
        assert_eq!(r3.all().len(), 2);
        assert!(r3.all().iter().all(|(_, b)| b.local.is_none()));
    }
}

#[cfg(test)]
#[path = "registration_tests.rs"]
mod registration_tests;
