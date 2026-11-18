//! The PBX: a SIP registrar and forwarding proxy.
//!
//! Phones register their extension; an INVITE (or MESSAGE, ...) to an
//! extension number is forwarded to the phone that registered it. Media
//! (RTP) flows directly between the phones. For a single target, the phones
//! handle retransmissions; the proxy remembers the INVITE's route. Only
//! multi-target calls need fork timers, so an idle PBX blocks in `recvmsg()`.
//!
//! On a host with several addresses, each phone is sent everything from the
//! address it uses for the PBX (see `udp`): replies from where the request
//! arrived, requests from where the phone registered to.

use crate::config::Config;
use crate::digest::{parse_credentials, Digest, Verdict};
use crate::fork::{self, Fork, Out, Target};
use crate::log;
use crate::registrar::{
    Binding, Change, RegisterError, Registrar, MAX_CONTACTS, MAX_CONTACT_LEN, MAX_CONTACT_PARAMS,
};
use crate::routing;
use crate::sip::{parse_params, Header, Message, NameAddr, StartLine, Uri};
use crate::udp;
use crate::util::*;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// At most this many group calls ringing at once (in total / per calling
/// phone, by source IP: unlike a Via port the sender can't pick it, and a
/// phone never needs more), and this many kept in memory including finished
/// ones that are still absorbing retransmissions, of which one source IP
/// may hold only a quarter (so it can't lock everybody else out). A call
/// beyond any of these limits gets 503.
const MAX_RINGING: usize = 64;
const MAX_RINGING_PER_CALLER: usize = 4;
const MAX_FORKS: usize = 256;
const MAX_FORKS_PER_SOURCE: usize = MAX_FORKS / 4;
/// How long we remember where a one-phone INVITE went (for its CANCEL,
/// ACK and retransmissions), and how many such entries at most.
const RECENT_TTL: Duration = Duration::from_secs(600);
const RECENT_MAX: usize = 1024;

/// Every branch we generate starts with this, so we can recognise our Via.
pub const BRANCH_PREFIX: &str = "z9hG4bK-pbx-";
/// Via parameter with our address a forwarded request arrived on, when its
/// responses come back to another one of ours: they are passed on from it.
const VIA_IN: &str = "pbx-in";
const ALLOW: &str =
    "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER, MESSAGE, REFER, NOTIFY, INFO, UPDATE, PRACK";
pub const SERVER: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

pub struct Pbx {
    pub cfg: Config,
    sock: UdpSocket,
    port: u16,
    v6: bool,
    /// The socket is bound to the wildcard address, and we choose the
    /// source address of what we send.
    choose_src: bool,
    /// The packet being handled.
    inbound: Inbound,
    /// The socket's receive timeout (None: block).
    read_timeout: Option<Duration>,
    secret: String,
    digest: Digest,
    pub reg: Registrar,
    /// Completed authenticated REGISTERs, independent of live bindings.
    registers: std::collections::BTreeMap<String, Vec<CompletedRegister>>,
    /// This host's interface addresses, refreshed at most every few seconds
    /// (and only when packets arrive).
    local_ips: Vec<IpAddr>,
    local_ips_at: u64,
    /// Calls currently ringing several phones (empty when idle).
    forks: Vec<Fork>,
    /// Where recent authorized one-phone INVITEs were sent, so that their
    /// CANCEL, ACK and retransmissions go to the same phone even if
    /// registrations change meanwhile. Pruned lazily (no timers).
    recent: std::collections::HashMap<String, Sent>,
}

/// Outcome of checking a request's digest credentials (`Pbx::credentials`).
enum Auth {
    /// Authenticated as this extension.
    User(String),
    /// No usable credentials: challenge (stale: some were for an old nonce).
    Challenge { stale: bool },
    /// Rejected (and logged): 403.
    Refused,
}

/// Non-INVITE UDP transaction lifetime (Timer J = 64*T1, T1 = 500ms).
/// Limit records per *configured, authenticated extension*: one busy phone
/// cannot consume another extension's slots. Never evict a live record;
/// refuse new work for that extension with 503 until a slot expires.
const REGISTER_WINDOW: Duration = Duration::from_secs(32);
pub(crate) const REGISTER_LIMIT: usize = 64;

type RegisterOutcome = Result<(), (u16, &'static str)>;

struct CompletedRegister {
    until: Instant,
    /// Hash of the entire parsed request, including the source-bound Digest
    /// credentials. A new authenticated attempt is not the same transaction.
    request: [u8; 16],
    outcome: RegisterOutcome,
}

/// How an authorized INVITE was forwarded (see `Pbx::recent`).
struct Sent {
    at: Instant,
    dst: SocketAddr,
    /// Our address it was sent from (and that is in its Via).
    local: Option<IpAddr>,
    uri: String,
    /// Preloaded Routes left after removing our own (normally empty).
    routes: Vec<String>,
    record_route: bool,
}

/// About the packet being handled (reset for each one).
#[derive(Clone, Copy, Default)]
struct Inbound {
    /// Our address it was sent to (None: unknown).
    local: Option<IpAddr>,
    /// In an in-dialog request, the address in the last of our Record-Route
    /// entries in its Route: the one we record-routed towards where it goes.
    route: Option<IpAddr>,
}

/// "486 Busy Here", for logs.
pub fn status_line(resp: &Message) -> String {
    match &resp.start {
        StartLine::Response { code, reason } => format!("{} {}", code, clip(reason)),
        StartLine::Request { method, .. } => clip(method).to_string(),
    }
}

/// Turn "::ffff:1.2.3.4" (as seen on a dual-stack socket) into 1.2.3.4.
fn canonical(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        _ => a,
    }
}

impl Pbx {
    pub fn new(cfg: Config, sock: UdpSocket) -> Pbx {
        let local = sock.local_addr().expect("socket has no local address");
        let secret = routing::load_key(cfg.state_file.as_deref());
        let mut reg = Registrar::new(cfg.state_file.clone(), cfg.max_expires);
        reg.retain_exts(|e| cfg.extensions.contains_key(e));
        // Bound to one address, everything comes from that one anyway.
        let choose_src = local.ip().is_unspecified() && udp::enable_pktinfo(&sock);
        Pbx {
            digest: Digest::new(&cfg.realm, &random_hex()),
            port: local.port(),
            v6: local.is_ipv6(),
            choose_src,
            inbound: Inbound::default(),
            read_timeout: None,
            cfg,
            sock,
            secret,
            reg,
            registers: Default::default(),
            local_ips: interface_ips(),
            local_ips_at: now_unix(),
            forks: Vec::new(),
            recent: Default::default(),
        }
    }

    /// Serve forever. Blocks in recvmsg() without a timeout unless a group
    /// call is ringing.
    pub fn run(&mut self) -> ! {
        let mut buf = vec![0u8; 65536];
        loop {
            self.turn(&mut buf);
        }
    }

    /// Wait for a datagram, or until the next timer is due, and handle it.
    pub fn turn(&mut self, buf: &mut [u8]) {
        let now = Instant::now();
        let want = self
            .next_deadline(now)
            .map(|d| d.saturating_duration_since(now).max(Duration::from_millis(1)));
        if want != self.read_timeout {
            if let Err(e) = self.sock.set_read_timeout(want) {
                log!(WARN, "set_read_timeout: {}", e);
            }
            self.read_timeout = want;
        }
        let packet = match udp::recv(&self.sock, buf) {
            Ok((n, src, local)) => Some((n, canonical(src), local)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(e) => {
                log!(WARN, "recv: {}", e);
                None
            }
        };
        self.step(
            packet.map(|(n, src, local)| (&buf[..n], src, local)),
            Instant::now(),
        );
    }

    /// One turn of the main loop: handle the datagram that arrived (if
    /// any: data, sender, our address it was sent to), then run timers that
    /// are due — whatever arrived, so that a stream of keep-alives can't
    /// starve the timers.
    pub fn step(&mut self, packet: Option<(&[u8], SocketAddr, Option<IpAddr>)>, now: Instant) {
        if let Some((data, src, local)) = packet {
            // CRLF keep-alives need no answer
            if !data.iter().all(u8::is_ascii_whitespace) {
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.handle_at(data, src, local)
                }));
                if res.is_err() {
                    log!(ERROR, "internal error while handling a packet from {}", src);
                }
            }
        }
        if !self.forks.is_empty() {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.tick(now)));
            if res.is_err() {
                log!(ERROR, "internal error in timers; dropping ringing group calls");
                self.forks.clear();
            }
        }
    }

    /// When timers next need to run (None: nothing pending, sleep forever).
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        self.forks.iter().map(|f| f.next_deadline(now)).min()
    }

    /// Run due timers of ringing group calls.
    pub fn tick(&mut self, now: Instant) {
        let mut out = Vec::new();
        for f in &mut self.forks {
            out.extend(f.tick(now));
        }
        self.forks.retain(|f| !f.finished(now));
        self.send_all(out);
    }

    fn send_all(&self, out: Vec<Out>) {
        for o in out {
            self.send(&o.msg, o.dst, o.src);
        }
    }

    /// A packet whose local address is unknown (tests).
    #[cfg(test)]
    pub fn handle(&mut self, data: &[u8], src: SocketAddr) {
        self.handle_at(data, src, None)
    }

    /// Handle a packet from `src` that was sent to our address `local`.
    fn handle_at(&mut self, data: &[u8], src: SocketAddr, local: Option<IpAddr>) {
        self.inbound = Inbound {
            local: local.map(|ip| canonical(SocketAddr::new(ip, 0)).ip()),
            route: None,
        };
        self.dispatch(data, src);
        self.inbound = Inbound::default();
    }

    fn dispatch(&mut self, data: &[u8], src: SocketAddr) {
        if !self.cfg.allowed(src.ip()) {
            log!(
                DEBUG,
                "ignoring {} bytes from {} (not in `allow`)",
                data.len(),
                src
            );
            return;
        }
        let now = now_unix();
        if now.abs_diff(self.local_ips_at) >= 5 {
            self.local_ips = interface_ips();
            self.local_ips_at = now;
        }
        if log_enabled(DEBUG) {
            log!(
                DEBUG,
                "<<< {} bytes from {}{}\n{}",
                data.len(),
                src,
                self.inbound
                    .local
                    .map(|l| format!(" to {}", l))
                    .unwrap_or_default(),
                String::from_utf8_lossy(data)
            );
        }
        match Message::parse(data) {
            Ok(m) if m.is_request() => self.on_request(m, src),
            Ok(m) => self.on_response(m, src),
            Err(e) => log!(DEBUG, "ignoring unparseable packet from {}: {:?}", src, e),
        }
    }

    /// Send `msg` to `dst` from our address `src` (None: the kernel's
    /// choice; also if sending from `src` fails, e.g. because that address
    /// has just gone away).
    fn send(&self, msg: &Message, dst: SocketAddr, src: Option<IpAddr>) {
        let bytes = msg.to_bytes();
        let src = src.filter(|ip| self.choose_src && ip.is_ipv4() == dst.is_ipv4());
        if log_enabled(DEBUG) {
            log!(
                DEBUG,
                ">>> {} bytes to {}{}\n{}",
                bytes.len(),
                dst,
                src.map(|l| format!(" from {}", l)).unwrap_or_default(),
                String::from_utf8_lossy(&bytes)
            );
        }
        let to = match (self.v6, dst.ip()) {
            (true, IpAddr::V4(v4)) => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), dst.port()),
            _ => dst,
        };
        let sent = match src {
            Some(ip) => udp::send(&self.sock, &bytes, to, ip).or_else(|e| {
                log!(
                    DEBUG,
                    "send to {} from {}: {}; sending from any address",
                    dst,
                    ip,
                    e
                );
                self.sock.send_to(&bytes, to)
            }),
            None => self.sock.send_to(&bytes, to),
        };
        if let Err(e) = sent {
            log!(WARN, "send to {}: {}", dst, e);
        }
    }

    /// Answer a request ourselves (always back to where it came from, from
    /// where it arrived).
    fn reply(&self, req: &Message, src: SocketAddr, code: u16, reason: &str, extra: Vec<(&str, String)>) {
        if req.method() == "ACK" {
            return; // ACKs are never answered
        }
        let tag = self.local_tag(req);
        let mut resp = req.make_response(code, reason, Some(&tag));
        for (name, value) in extra {
            resp.headers.push(Header {
                name: name.to_string(),
                value,
            });
        }
        resp.headers.push(Header {
            name: "Server".into(),
            value: SERVER.into(),
        });
        self.send(&resp, src, self.inbound.local);
    }

    /// To-tag for responses we generate; stable across retransmissions so we
    /// can recognise (and swallow) the ACK for our own 4xx responses.
    fn local_tag(&self, req: &Message) -> String {
        let h = md5_hex(&format!(
            "{}|{}|{}",
            self.secret,
            req.call_id().unwrap_or(""),
            req.from_tag().unwrap_or_default()
        ));
        h[..12].to_string()
    }

    /// RFC 3261 16.11: stateless proxies derive the branch from the incoming
    /// one, so an INVITE and its CANCEL / non-2xx ACK get the same branch.
    /// It also covers where responses will be sent, so a forged response
    /// can't make us send to an address of the forger's choosing: on the way
    /// back the branch is recomputed from the next Via and must match.
    /// (`msg` is the request, or a response with our Via already removed.)
    fn branch_for(&self, msg: &Message) -> String {
        let via = msg.top_via();
        let key = match via.as_ref().and_then(|v| v.branch()) {
            Some(b) if b.starts_with("z9hG4bK") => b.to_string(),
            _ => format!(
                "{}|{}|{}",
                msg.call_id().unwrap_or(""),
                msg.cseq().map(|c| c.0).unwrap_or(0),
                msg.from_tag().unwrap_or_default(),
            ),
        };
        let target = via
            .as_ref()
            .and_then(reply_addr)
            .map(|a| a.to_string())
            .unwrap_or_default();
        let h = md5_hex(&format!("{}|{}|{}", self.secret, key, target));
        format!("{}{}", BRANCH_PREFIX, &h[..20])
    }

    fn is_our_ip(&self, ip: IpAddr) -> bool {
        if Some(ip) == self.cfg.advertise {
            return true;
        }
        let l = canonical(self.cfg.listen).ip();
        if !l.is_unspecified() {
            return ip == l;
        }
        ip.is_loopback() || ip.is_unspecified() || self.local_ips.contains(&ip)
    }

    /// Does this URI address the PBX itself (rather than a phone)?
    /// Host names always do: we never look names up (phones use IPs in
    /// their Contact), so a name can only be the "SIP server" the phone was
    /// configured with, i.e. us.
    fn is_us(&self, uri: &Uri) -> bool {
        match parse_ip_host(&uri.host) {
            Some(ip) => uri.port_or_default() == self.port && self.is_our_ip(ip),
            None => true,
        }
    }

    /// A phone's Contact must not take precedence over our own dial plan,
    /// including when the binding was restored from disk.
    fn phone_contact(&self, uri: &Uri) -> Option<Binding> {
        if self.is_us(uri) {
            return None;
        }
        self.reg.find_by_contact(uri)
    }

    /// Is `ip` (still) one of this host's addresses?
    fn is_local(&self, ip: IpAddr) -> bool {
        ip.is_loopback() || self.local_ips.contains(&ip)
    }

    /// Our address to send to `dst` from, and to name in Via / Record-Route:
    /// the one the phone there registered to or, for an in-dialog request
    /// to a phone without a live registration, the one we record-routed
    /// towards it -- if still ours. None: the kernel's choice.
    fn local_towards(&self, dst: SocketAddr) -> Option<IpAddr> {
        let usable = |ip: &IpAddr| ip.is_ipv4() == dst.is_ipv4() && self.is_local(*ip);
        self.reg
            .local_for(dst)
            .filter(usable)
            .or(self.inbound.route.filter(usable))
    }

    /// The address we write into Via / Record-Route for our address `local`
    /// (None: whichever the kernel uses towards `peer`).
    fn via_ip(&self, local: Option<IpAddr>, peer: IpAddr) -> IpAddr {
        if let Some(a) = self.cfg.advertise {
            return a;
        }
        let l = canonical(self.cfg.listen).ip();
        if !l.is_unspecified() {
            return l;
        }
        local.or_else(|| local_ip_for(peer)).unwrap_or(l)
    }

    // ------------------------------------------------------------ requests

    fn on_request(&mut self, mut req: Message, src: SocketAddr) {
        if !fix_top_via(&mut req, src) {
            log!(DEBUG, "dropping request without a usable Via from {}", src);
            return;
        }
        strip_identity(&mut req);
        let method = req.method().to_string();
        // RFC 3261 8.1.1.5: CSeq numbers are below 2^31 (so ours, +1, can't overflow)
        let cseq_ok = req.cseq().is_some_and(|(n, m)| m == method && n < 1 << 31);
        if req.call_id().is_none() || !cseq_ok || req.hdr("From").is_none() || req.hdr("To").is_none() {
            return self.reply(&req, src, 400, "Bad Request", vec![]);
        }
        let to_tag = req.to_tag();
        if matches!(method.as_str(), "INVITE" | "CANCEL" | "ACK") {
            // retransmission / CANCEL / ACK of a group call that is ringing?
            // (Not the ACK for a 2xx, even if a phone reuses the branch:
            // that one goes end to end.)
            let key = fork::key_of(&req);
            let caller = req.top_via().as_ref().and_then(reply_addr).unwrap_or(src);
            if let Some(f) = self.forks.iter_mut().find(|f| {
                Some(&f.key) == key.as_ref() && f.caller() == caller && !(method == "ACK" && f.answered())
            }) {
                let out = f.on_caller(&req, caller, Instant::now());
                return self.send_all(out);
            }
        }
        if method == "ACK" && to_tag.as_deref() == Some(self.local_tag(&req).as_str()) {
            return; // ACK for a negative response we sent ourselves
        }
        let mf = match req.hdr("Max-Forwards") {
            Some(v) => match v.trim().parse::<u32>() {
                Ok(n) => n,
                Err(_) => return self.reply(&req, src, 400, "Bad Max-Forwards", vec![]),
            },
            None => 70,
        };
        if method != "ACK" && method != "CANCEL" {
            if let Some(pr) = req.hdr("Proxy-Require").filter(|v| !v.trim().is_empty()) {
                let pr = pr.to_string();
                return self.reply(&req, src, 420, "Bad Extension", vec![("Unsupported", pr)]);
            }
        }

        // Loose routing: remove the Route entries that point at us (we put
        // them there via Record-Route, or the phone preloaded us). Keep our
        // dialog token if it is valid for this call and sender, and note our
        // address in the last of our Record-Routes (see `local_towards`).
        let mut dialog_token = None;
        while let Some(r) = req.hdr("Route") {
            match NameAddr::parse(r).and_then(|n| Uri::parse(&n.uri)) {
                Some(u) if self.is_us(&u) => {
                    if to_tag.is_some() && dialog_token.is_none() {
                        dialog_token = u
                            .param("pbx-dialog")
                            .flatten()
                            .filter(|t| routing::valid(&self.secret, req.call_id().unwrap_or(""), src, t));
                    }
                    if to_tag.is_some() && u.param("pbx-dialog").is_some() {
                        self.inbound.route = parse_ip_host(&u.host).filter(|ip| self.is_local(*ip));
                    }
                    req.remove_first("Route");
                }
                _ => break,
            }
        }
        // For a matching transaction the original next hop wins, including
        // when a preloaded Route or Contact no longer has a live binding.
        // recall checks both the source and the remaining Route set.
        if matches!(method.as_str(), "INVITE" | "CANCEL" | "ACK") {
            if let Some(sent) = self.recall(&req, src) {
                req.set_uri(sent.uri.clone());
                let add_rr = sent.record_route && method == "INVITE" && to_tag.is_none();
                let local = sent.local.filter(|ip| self.is_local(*ip));
                return self.forward_from(req, src, sent.dst, local, mf, add_rr);
            }
        }
        if let Some(r) = req.hdr("Route") {
            // Someone else's Route: we only ever forward to our own phones,
            // and only what we would forward without the Route. Never a
            // REGISTER: we are the registrar, and a phone is not one.
            let next = NameAddr::parse(r).and_then(|n| Uri::parse(&n.uri));
            let phone = next.and_then(|u| self.phone_contact(&u));
            let Some(b) = phone.filter(|_| method != "REGISTER") else {
                log!(
                    DEBUG,
                    "{} from {}: refusing to relay to Route {}",
                    method,
                    src,
                    clip(r)
                );
                return self.reply(&req, src, 403, "Relaying Denied", vec![]);
            };
            if to_tag.is_some() {
                if !self.dialog_trusted(src, dialog_token.is_some()) {
                    return self.reply(&req, src, 481, "Call/Transaction Does Not Exist", vec![]);
                }
                return self.forward(req, src, b.source, mf, false);
            }
            if !self.authorize_new(&req, src) {
                return;
            }
            return self.forward_new(req, src, b.source, mf, false);
        }
        let Some(ruri) = Uri::parse(req.uri()) else {
            return self.reply(&req, src, 416, "Unsupported URI Scheme", vec![]);
        };
        if method == "REGISTER" {
            return self.register(req, src);
        }
        if to_tag.is_some() {
            self.in_dialog(req, src, ruri, mf, dialog_token)
        } else {
            self.out_of_dialog(req, src, ruri, mf)
        }
    }

    fn ext_of(&self, user: Option<String>) -> Option<String> {
        user.filter(|u| self.cfg.extensions.contains_key(u))
    }

    /// Mid-call requests (BYE, re-INVITE, ACK for 2xx, ...) and the ACK for a
    /// phone's negative final response. `token`: our dialog token from the
    /// Route, if valid for this call and sender.
    fn in_dialog(&mut self, mut req: Message, src: SocketAddr, ruri: Uri, mf: u32, token: Option<String>) {
        let trusted = self.dialog_trusted(src, token.is_some());
        if req.method() == "BYE" {
            // (anybody can send a BYE; only log those we may pass on)
            log!(
                if trusted { INFO } else { DEBUG },
                "hangup {} -> {}",
                clip(&req.from_user().unwrap_or_default()),
                clip(&req.to_user().unwrap_or_default())
            );
        }
        if trusted {
            if let Some(b) = self.phone_contact(&ruri) {
                return self.forward(req, src, b.source, mf, false);
            }
        }
        if self.is_us(&ruri) {
            let number = ruri
                .user
                .clone()
                .filter(|u| self.cfg.extensions.contains_key(u) || self.cfg.groups.contains_key(u));
            if let Some(number) = number {
                if req.method() == "ACK" {
                    // R-URI is still the dialled number: the ACK for a
                    // phone's 4xx-6xx. Route it exactly like the INVITE
                    // (and, like any non-2xx ACK, without authorization:
                    // see `authorize_new`). (ACKs of group calls that rang
                    // several phones were taken care of by their Fork
                    // already.)
                    let mut t = self.targets(&number, src, self.ext_of(req.from_user()).as_deref());
                    if t.len() == 1 {
                        let (_, b) = t.remove(0);
                        req.set_uri(b.contact.clone());
                        return self.forward(req, src, b.source, mf, false);
                    }
                    return;
                }
                if trusted && self.cfg.extensions.contains_key(&number) {
                    return self.route_to_extension(req, src, &number, mf, false);
                }
            }
        } else if let (true, Some(dst)) = (trusted, ip_addr(&ruri.host, ruri.port_or_default())) {
            // A Contact without a live registration. Relay only to where a
            // phone registered from, or between the two endpoints our dialog
            // token was minted for (e.g. after a registration expired) --
            // never to an arbitrary host, nor to services on our own host.
            let dst = canonical(dst);
            let call_id = req.call_id().unwrap_or("");
            let peer = token
                .as_deref()
                .is_some_and(|t| routing::connects(&self.secret, call_id, src, dst, t));
            if peer || self.reg.registered_from(dst, None) {
                return self.forward(req, src, dst, mf, false);
            }
            log!(
                DEBUG,
                "{} from {}: refusing to relay to {}",
                req.method(),
                src,
                dst
            );
        }
        self.reply(&req, src, 481, "Call/Transaction Does Not Exist", vec![])
    }

    /// New requests: calls, messages, pings (REGISTER: see `register`).
    fn out_of_dialog(&mut self, mut req: Message, src: SocketAddr, ruri: Uri, mf: u32) {
        let method = req.method().to_string();
        let from_user = req.from_user();
        if method == "OPTIONS" && (ruri.user.is_none() || ruri.user == from_user) {
            // keep-alive / "are you there" aimed at the PBX
            return self.reply(
                &req,
                src,
                200,
                "OK",
                vec![("Allow", ALLOW.into()), ("Accept", "application/sdp".into())],
            );
        }
        if method == "SUBSCRIBE" || method == "PUBLISH" {
            // no voicemail (MWI), presence or BLF here, whatever the number
            return self.reply(&req, src, 489, "Bad Event", vec![]);
        }
        // Authorize before revealing which numbers exist (404 / 405),
        // including when a registered phone claims another extension's From.
        if !self.authorize_new(&req, src) {
            return;
        }
        // Usually the R-URI is a dialled extension; but e.g. after a transfer
        // a phone may address another phone's Contact directly.
        let contact = self.phone_contact(&ruri);
        let ext = self.ext_of(ruri.user.clone());
        let group = ruri
            .user
            .as_ref()
            .filter(|u| self.cfg.groups.contains_key(*u))
            .cloned();
        if contact.is_none() && ext.is_none() && group.is_none() {
            if method == "INVITE" {
                log!(
                    INFO,
                    "call {} -> {}: no such extension",
                    clip(&from_user.unwrap_or_default()),
                    clip(ruri.user.as_deref().unwrap_or(""))
                );
            }
            if method == "CANCEL" {
                // nothing was forwarded there, so nothing to cancel
                return self.reply(&req, src, 481, "Call/Transaction Does Not Exist", vec![]);
            }
            return self.reply(&req, src, 404, "Not Found", vec![]);
        }
        if contact.is_none() && group.is_some() && method != "INVITE" && method != "CANCEL" {
            let allow = "INVITE, ACK, CANCEL".to_string();
            return self.reply(&req, src, 405, "Method Not Allowed", vec![("Allow", allow)]);
        }
        let callee = ext
            .clone()
            .or(group)
            .or_else(|| ruri.user.clone())
            .unwrap_or_default();
        let label = format!("{} -> {}", clip(&from_user.unwrap_or_default()), clip(&callee));
        if method == "INVITE" {
            log!(INFO, "call {}", label);
        }
        let add_rr = self.cfg.record_route && (method == "INVITE" || method == "REFER");
        if let Some(b) = contact {
            return self.forward_new(req, src, b.source, mf, add_rr);
        }
        if method != "INVITE" && method != "CANCEL" {
            return self.route_to_extension(req, src, &callee, mf, add_rr);
        }
        // INVITE: ring every device of the extension / every member of the
        // group.
        let mut targets = self.targets(&callee, src, self.ext_of(req.from_user()).as_deref());
        match targets.len() {
            0 => {
                if method == "INVITE" {
                    log!(INFO, "call {}: not registered", label);
                }
                self.reply(&req, src, 480, "Temporarily Unavailable", vec![])
            }
            1 => {
                let (_, b) = targets.remove(0);
                req.set_uri(b.contact.clone());
                self.forward_new(req, src, b.source, mf, add_rr)
            }
            _ if method == "INVITE" => self.start_fork(req, src, targets, mf, add_rr, label),
            _ => self.reply(&req, src, 481, "Call/Transaction Does Not Exist", vec![]),
        }
    }

    /// Bind cached transaction routing to both the reply address and the
    /// actual sender; a client-supplied Via port is not authorization.
    fn recent_key(req: &Message, src: SocketAddr) -> Option<String> {
        let caller = req.top_via().as_ref().and_then(reply_addr).unwrap_or(src);
        fork::key_of(req).map(|k| format!("{}|{}|{}", k, caller, src))
    }

    /// Note where an authorized INVITE goes, and from which of our
    /// addresses (only `forward_new` calls this).
    fn remember(
        &mut self,
        req: &Message,
        src: SocketAddr,
        dst: SocketAddr,
        local: Option<IpAddr>,
        record_route: bool,
    ) {
        let Some(key) = Self::recent_key(req, src) else {
            return;
        };
        let now = Instant::now();
        if self.recent.len() >= RECENT_MAX {
            self.recent.retain(|_, s| now.duration_since(s.at) < RECENT_TTL);
            if self.recent.len() >= RECENT_MAX {
                self.recent.clear();
            }
        }
        let sent = Sent {
            at: now,
            dst,
            local,
            uri: req.uri().to_string(),
            routes: req.hdrs("Route").map(str::to_string).collect(),
            record_route,
        };
        self.recent.insert(key, sent);
    }

    fn recall(&self, req: &Message, src: SocketAddr) -> Option<&Sent> {
        let s = self.recent.get(&Self::recent_key(req, src)?)?;
        (s.at.elapsed() < RECENT_TTL && req.hdrs("Route").eq(s.routes.iter().map(String::as_str)))
            .then_some(s)
    }

    /// The phones a call to `number` rings: newest registration first.
    /// Each extension rings once per device, also when several share one
    /// address: the handsets of a DECT base register their extensions from
    /// the base's IP:port (and a desk phone with two accounts in a group
    /// rings on both lines). The calling extension (`caller`, from its From)
    /// is not rung back on the device that is calling; other extensions on
    /// that device are. If the caller is no extension, nothing at its
    /// address rings.
    fn targets(&self, number: &str, src: SocketAddr, caller: Option<&str>) -> Vec<(String, Binding)> {
        let group = self.cfg.groups.get(number);
        let members = group.cloned().unwrap_or_else(|| vec![number.to_string()]);
        let mut out: Vec<(String, Binding)> = Vec::new();
        for m in members {
            for b in self.reg.get(&m) {
                let is_caller = b.source == src && caller.is_none_or(|ext| ext == m);
                if !is_caller && !out.iter().any(|(e, o)| *e == m && o.source == b.source) {
                    out.push((m.clone(), b));
                }
            }
        }
        out
    }

    fn start_fork(
        &mut self,
        req: Message,
        src: SocketAddr,
        targets: Vec<(String, Binding)>,
        mf: u32,
        add_rr: bool,
        label: String,
    ) {
        if mf == 0 {
            return self.reply(&req, src, 483, "Too Many Hops", vec![]);
        }
        let caller = req.top_via().as_ref().and_then(reply_addr).unwrap_or(src);
        let now = Instant::now();
        self.forks.retain(|f| !f.finished(now));
        let (mut all, mut mine, mut held) = (0, 0, 0);
        for f in &self.forks {
            let same = f.source() == src.ip();
            held += same as usize;
            if f.ringing() {
                all += 1;
                mine += same as usize;
            }
        }
        if self.forks.len() >= MAX_FORKS
            || held >= MAX_FORKS_PER_SOURCE
            || all >= MAX_RINGING
            || mine >= MAX_RINGING_PER_CALLER
        {
            log!(WARN, "call {}: too many group calls ringing", label);
            return self.reply(&req, src, 503, "Service Unavailable", vec![]);
        }
        let Some(key) = fork::key_of(&req) else {
            return self.reply(&req, src, 400, "Missing Branch", vec![]);
        };
        let mut ts = Vec::new();
        let mut base = req.clone();
        base.set("Max-Forwards", (mf - 1).to_string());
        for (ext, b) in targets {
            if b.source.port() == self.port && self.is_our_ip(b.source.ip()) {
                continue;
            }
            let mut m = base.clone();
            m.set_uri(b.contact.clone());
            let branch = fork::branch_id();
            let local = b
                .local
                .filter(|ip| ip.is_ipv4() == b.source.is_ipv4() && self.is_local(*ip));
            self.stamp(&mut m, src, b.source, local, add_rr, &branch);
            ts.push(Target {
                branch,
                invite: m,
                dst: b.source,
                local,
                who: format!("{} at {}", ext, b.source),
                ext,
            });
        }
        log!(INFO, "call {}: ringing {} phones", label, ts.len());
        let tag = self.local_tag(&req);
        let local = self.inbound.local;
        let (f, out) = Fork::new(key, req, caller, src.ip(), local, tag, label, ts, now);
        self.forks.push(f);
        self.send_all(out);
    }

    /// New requests need a registered source or a digest response. ACK and
    /// CANCEL cannot be challenged; the phone matches them to the INVITE.
    fn authorize_new(&mut self, req: &Message, src: SocketAddr) -> bool {
        if !self.cfg.auth_calls || matches!(req.method(), "ACK" | "CANCEL") {
            return true;
        }
        let from_ext = self.ext_of(req.from_user());
        if self.reg.registered_from(src, from_ext.as_deref()) {
            return true;
        }
        match self.credentials(req, "Proxy-Authorization", src) {
            Auth::User(u) if from_ext.is_none() || from_ext.as_deref() == Some(u.as_str()) => true,
            Auth::User(u) => {
                log!(
                    WARN,
                    "{} from {}: authenticated as {} but From says {:?}",
                    req.method(),
                    src,
                    u,
                    from_ext
                );
                self.reply(req, src, 403, "Forbidden", vec![]);
                false
            }
            Auth::Refused => {
                self.reply(req, src, 403, "Forbidden", vec![]);
                false
            }
            Auth::Challenge { stale } => {
                let ch = self.digest.challenge(stale, src);
                let extra = vec![("Proxy-Authenticate", ch)];
                self.reply(req, src, 407, "Proxy Authentication Required", extra);
                false
            }
        }
    }

    /// Check the request's credentials for our realm (in `header`).
    fn credentials(&mut self, req: &Message, header: &str, src: SocketAddr) -> Auth {
        let mut stale = false;
        let request = || md5_bytes(&req.to_bytes());
        for v in req.hdrs(header) {
            let Some(c) = parse_credentials(v) else { continue };
            if c.realm != self.digest.realm {
                continue;
            }
            let pw = self.cfg.extensions.get(&c.username).map(String::as_str);
            match self.digest.verify(&c, req.method(), req.uri(), pw, src, &request) {
                Verdict::Ok => return Auth::User(c.username),
                Verdict::Stale => stale = true,
                Verdict::Bad(why) => {
                    log!(
                        WARN,
                        "{} from {}: {} \"{}\"",
                        req.method(),
                        src,
                        why,
                        clip(&c.username)
                    );
                    return Auth::Refused;
                }
            }
        }
        Auth::Challenge { stale }
    }

    // The authorization policy. Every path that forwards a request applies
    // one of these two checks, whatever told us where to send it (dialled
    // number, Contact in the Request-URI, a Route naming a phone's Contact):
    // - in-dialog requests (To-tag): `dialog_trusted`;
    // - new requests: `authorize_new`.
    // Retransmissions, CANCEL and ACK of an authorized INVITE follow it via
    // the `recent` cache, which only `forward_new` fills.

    /// May `src` send in-dialog requests through us? Registered phones may;
    /// anybody else only with our Record-Route token for this Call-ID and
    /// source (`has_token`): an original endpoint of a dialog we authorized,
    /// e.g. a caller that answered a 407 challenge, or a phone whose
    /// registration expired mid-call. Either way, in-dialog requests only go
    /// to registered phones or to the token's other endpoint (`in_dialog`).
    fn dialog_trusted(&self, src: SocketAddr, has_token: bool) -> bool {
        has_token || self.reg.registered_from(src, None)
    }

    fn route_to_extension(&mut self, mut req: Message, src: SocketAddr, ext: &str, mf: u32, add_rr: bool) {
        match self.reg.lookup(ext) {
            Some(b) => {
                req.set_uri(b.contact.clone());
                self.forward(req, src, b.source, mf, add_rr)
            }
            None => {
                if req.method() == "INVITE" {
                    log!(INFO, "call to {}: not registered", ext);
                }
                self.reply(&req, src, 480, "Temporarily Unavailable", vec![])
            }
        }
    }

    /// Forward a new request that passed `authorize_new`. INVITEs are
    /// remembered, so that their retransmissions, CANCEL and ACK follow them.
    fn forward_new(&mut self, req: Message, src: SocketAddr, dst: SocketAddr, mf: u32, add_rr: bool) {
        let local = self.local_towards(dst);
        if req.method() == "INVITE" && req.to_tag().is_none() {
            self.remember(&req, src, dst, local, add_rr);
        }
        self.forward_from(req, src, dst, local, mf, add_rr)
    }

    fn forward(&mut self, req: Message, src: SocketAddr, dst: SocketAddr, mf: u32, add_rr: bool) {
        let local = self.local_towards(dst);
        self.forward_from(req, src, dst, local, mf, add_rr)
    }

    /// Forward to `dst`, from our address `local` (None: the kernel's choice).
    fn forward_from(
        &mut self,
        mut req: Message,
        src: SocketAddr,
        dst: SocketAddr,
        local: Option<IpAddr>,
        mf: u32,
        add_rr: bool,
    ) {
        if mf == 0 {
            return self.reply(&req, src, 483, "Too Many Hops", vec![]);
        }
        if dst.port() == self.port && self.is_our_ip(dst.ip()) {
            log!(
                WARN,
                "{} {}: would loop back to ourselves",
                req.method(),
                clip(req.uri())
            );
            return self.reply(&req, src, 482, "Loop Detected", vec![]);
        }
        let branch = self.branch_for(&req);
        req.set("Max-Forwards", (mf - 1).to_string());
        self.stamp(&mut req, src, dst, local, add_rr, &branch);
        self.send(&req, dst, local);
    }

    /// Prepare a request from `src` for sending to `dst` from our address
    /// `local`: Record-Route, our Via.
    fn stamp(
        &self,
        req: &mut Message,
        src: SocketAddr,
        dst: SocketAddr,
        local: Option<IpAddr>,
        add_rr: bool,
        branch: &str,
    ) {
        // Strip our credentials on every forwarding path, including retries
        // routed from the transaction cache without a new authorization check.
        req.headers.retain(|h| {
            h.name != "Proxy-Authorization"
                || parse_credentials(&h.value).is_none_or(|c| c.realm != self.digest.realm)
        });
        let out_ip = self.via_ip(local, dst.ip());
        if add_rr {
            // Double Record-Route if the two phones reach us on different
            // addresses, so each side gets the one it uses.
            let in_ip = self.via_ip(self.inbound.local, src.ip());
            let token = routing::token(&self.secret, req.call_id().unwrap_or(""), src, dst);
            if in_ip != out_ip {
                req.insert_top(
                    "Record-Route",
                    format!("<sip:{}:{};lr;pbx-dialog={}>", fmt_host(in_ip), self.port, token),
                    false,
                );
            }
            req.insert_top(
                "Record-Route",
                format!("<sip:{}:{};lr;pbx-dialog={}>", fmt_host(out_ip), self.port, token),
                false,
            );
        }
        let mut via = format!("SIP/2.0/UDP {}:{};branch={}", fmt_host(out_ip), self.port, branch);
        if let Some(in_local) = self.inbound.local.filter(|ip| Some(*ip) != local) {
            // the responses may arrive on another address; see `on_response`
            via.push_str(&format!(";{}={}", VIA_IN, fmt_host(in_local)));
        }
        req.insert_top("Via", via, true);
    }

    // ------------------------------------------------------------ registrar

    fn register(&mut self, req: Message, src: SocketAddr) {
        let user = match self.credentials(&req, "Authorization", src) {
            Auth::User(u) => u,
            Auth::Refused => return self.reply(&req, src, 403, "Forbidden", vec![]),
            Auth::Challenge { stale } => {
                let ch = self.digest.challenge(stale, src);
                return self.reply(&req, src, 401, "Unauthorized", vec![("WWW-Authenticate", ch)]);
            }
        };
        if req.to_user().as_deref() != Some(user.as_str()) {
            log!(
                WARN,
                "REGISTER from {}: {} tried to register \"{}\"",
                src,
                user,
                clip(&req.to_user().unwrap_or_default())
            );
            return self.reply(&req, src, 403, "Forbidden", vec![]);
        }
        // Digest accepts an exact retransmission (the response may have
        // been lost). Its binding may no longer exist, or may now belong
        // to a later REGISTER. Re-answer without re-applying anything,
        // even if this copy arrived on another IP.
        let request = md5_bytes(&req.to_bytes());
        let recent = self.registers.entry(user.clone()).or_default();
        let now = mono_now();
        recent.retain(|r| r.until > now);
        let outcome = if let Some(r) = recent.iter().find(|r| r.request == request) {
            r.outcome
        } else if recent.len() >= REGISTER_LIMIT {
            let extra = vec![("Retry-After", REGISTER_WINDOW.as_secs().to_string())];
            return self.reply(&req, src, 503, "Service Unavailable", extra);
        } else {
            let outcome = self.apply_register(&req, src, &user);
            self.registers.get_mut(&user).unwrap().push(CompletedRegister {
                until: mono_now() + REGISTER_WINDOW,
                request,
                outcome,
            });
            outcome
        };
        if let Err((code, reason)) = outcome {
            let mut extra = Vec::new();
            if code == 423 {
                extra.push(("Min-Expires", self.cfg.min_expires.to_string()));
            }
            return self.reply(&req, src, code, reason, extra);
        }
        // As for a binding-level duplicate, list the *current* Contacts.
        let (now, mono) = (now_unix(), mono_now());
        let mut extra: Vec<(&str, String)> = self
            .reg
            .get(&user)
            .into_iter()
            .map(|b| {
                (
                    "Contact",
                    format!("<{}>{};expires={}", b.contact, b.params, b.expires_in(mono)),
                )
            })
            .collect();
        extra.push(("Date", http_date(now)));
        self.reply(&req, src, 200, "OK", extra);
    }

    fn apply_register(&mut self, req: &Message, src: SocketAddr, user: &str) -> RegisterOutcome {
        let contacts: Vec<String> = req.hdrs("Contact").map(str::to_string).collect();
        if contacts.is_empty() {
            return Ok(()); // Query only: list the current bindings without updating them.
        }
        let expires_hdr: Option<u32> = req.hdr("Expires").and_then(|v| v.trim().parse().ok());
        let call_id = req.call_id().unwrap_or("").to_string();
        let cseq = req.cseq().map(|c| c.0).unwrap_or(0);
        let ua = crate::registrar::truncate_user_agent(req.hdr("User-Agent").unwrap_or(""));
        let mut changed = false;

        if contacts.iter().any(|c| c.trim() == "*") {
            if contacts.len() != 1 || expires_hdr != Some(0) {
                return Err((400, "Bad Request"));
            }
            match self.reg.unregister_all(user, &call_id, cseq) {
                Ok(true) => {
                    log!(INFO, "{} unregistered from {}", user, src);
                    changed = true;
                }
                Ok(false) => {}
                Err(_) => return self.register_out_of_order(req, src, user),
            }
        } else {
            // Generous limits for real phones (whose Contacts are mostly
            // well under 200 bytes; Linphone's with push parameters ~600),
            // so that one REGISTER can't make every later one slow, or
            // every 200 OK for the extension too big for a datagram.
            if contacts.len() > MAX_CONTACTS {
                log!(
                    WARN,
                    "REGISTER from {}: {} has {} Contacts; refused",
                    src,
                    user,
                    contacts.len()
                );
                return Err((400, "Too Many Contacts"));
            }
            let mut updates = Vec::new();
            for c in &contacts {
                let Some((na, uri)) =
                    NameAddr::parse(c).and_then(|na| Uri::parse(&na.uri).map(|uri| (na, uri)))
                else {
                    return Err((400, "Bad Contact"));
                };
                let uri_params = parse_params(&uri.params).len();
                let header_params = parse_params(&na.params).len();
                if c.len() > MAX_CONTACT_LEN || uri_params.max(header_params) > MAX_CONTACT_PARAMS {
                    log!(
                        WARN,
                        "REGISTER from {}: {} has a Contact of {} bytes, {} URI parameters, {} parameters; refused",
                        src,
                        user,
                        c.len(),
                        uri_params,
                        header_params
                    );
                    return Err((400, "Contact Too Long"));
                }
                let exp = na
                    .param("expires")
                    .flatten()
                    .and_then(|e| e.trim().parse::<u32>().ok())
                    .or(expires_hdr)
                    .unwrap_or(self.cfg.default_expires);
                if exp != 0 && exp < self.cfg.min_expires {
                    return Err((423, "Interval Too Brief"));
                }
                if let Some((other, b)) = self.reg.contact_taken(user, &uri, src).filter(|_| exp != 0) {
                    log!(
                        WARN,
                        "REGISTER from {}: {} wants Contact {}, which is {}'s (registered from {}); refused",
                        src,
                        user,
                        clip(&na.uri),
                        other,
                        b.source
                    );
                    return Err((403, "Contact In Use"));
                }
                updates.push((
                    na.uri.clone(),
                    na.params_without("expires"),
                    exp.min(self.cfg.max_expires),
                ));
            }
            let received = (src, self.inbound.local);
            let changes = match self
                .reg
                .update_many(user, &updates, received, &call_id, cseq, &ua)
            {
                Ok(changes) => changes,
                Err(RegisterError::StaleCSeq) => return self.register_out_of_order(req, src, user),
                Err(RegisterError::TooManyContacts) => {
                    log!(
                        WARN,
                        "REGISTER from {}: {} exceeds the binding limit; refused",
                        src,
                        user
                    );
                    return Err((403, "Too Many Contacts"));
                }
            };
            let done: Vec<_> = updates
                .into_iter()
                .zip(changes)
                .filter(|(_, c)| *c != Change::Ignored)
                .map(|((uri, _, exp), c)| (uri, exp, c))
                .collect();
            changed = !done.is_empty();
            log_register(user, src, &ua, &done);
        }
        if changed {
            self.reg.save();
        }
        Ok(())
    }

    /// A REGISTER older than (or replaying) what a binding already has.
    fn register_out_of_order(&self, req: &Message, src: SocketAddr, user: &str) -> RegisterOutcome {
        log!(
            WARN,
            "REGISTER from {}: {} sent CSeq {} for Call-ID \"{}\", not newer than its registration; \
             rejected (replay, or a phone that reuses its Call-ID after a reboot?)",
            src,
            user,
            req.cseq().map(|c| c.0).unwrap_or(0),
            clip(req.call_id().unwrap_or(""))
        );
        Err((500, "CSeq Out of Order"))
    }

    // ------------------------------------------------------------ responses

    fn on_response(&mut self, mut resp: Message, src: SocketAddr) {
        strip_identity(&mut resp);
        let Some(top) = resp.top_via() else { return };
        let ours = top.branch().is_some_and(|b| b.starts_with(BRANCH_PREFIX))
            && top.port.unwrap_or(5060) == self.port;
        if !ours {
            log!(DEBUG, "dropping response from {} that isn't for us", src);
            return;
        }
        let branch = top.branch().unwrap_or_default();
        for f in &mut self.forks {
            if let Some(i) = f.branch_index(branch) {
                let out = f.on_response(i, resp, Instant::now());
                return self.send_all(out);
            }
            if let Some(i) = f.hangup_branch_index(branch) {
                let out = f.on_hangup_response(i, &resp, Instant::now());
                return self.send_all(out);
            }
        }
        // Unmatched fork responses cannot be recovered without state. Their
        // branches (including late-answer BYEs) cannot match branch_for below,
        // so they are dropped rather than relayed or given fabricated requests.
        resp.remove_first("Via");
        // Passed on from our address the request arrived on: the one in our
        // Via if it said so (see `stamp`), else where the response arrived.
        let local = top
            .param(VIA_IN)
            .flatten()
            .and_then(parse_ip_host)
            .filter(|ip| self.is_local(*ip))
            .or(self.inbound.local);
        if top.branch() != Some(self.branch_for(&resp).as_str()) {
            log!(
                DEBUG,
                "dropping response from {}: branch doesn't match the next Via",
                src
            );
            return;
        }
        let Some(dst) = resp.top_via().as_ref().and_then(reply_addr) else {
            log!(DEBUG, "dropping response from {} without a usable next Via", src);
            return;
        };
        if let Some((_, m)) = resp.cseq() {
            if m == "INVITE" && resp.code() >= 200 {
                log!(
                    INFO,
                    "call {} -> {}: {}",
                    clip(&resp.from_user().unwrap_or_default()),
                    clip(&resp.to_user().unwrap_or_default()),
                    status_line(&resp)
                );
            }
        }
        self.send(&resp, dst, local);
    }
}

/// Caller (and connected party) identity headers that phones prefer to
/// From / To for display, but that any phone can set to anything: RFC 3325
/// trusts them only within a trust domain, and the phones on a LAN are not
/// one. So they are removed from everything we pass on, and phones show
/// the From of a request (whose extension `authorize_new` checks).
const IDENTITY_HEADERS: &[&str] = &["P-Asserted-Identity", "P-Preferred-Identity", "Remote-Party-ID"];

fn strip_identity(m: &mut Message) {
    m.headers
        .retain(|h| !IDENTITY_HEADERS.iter().any(|n| h.name.eq_ignore_ascii_case(n)));
}

/// One line per REGISTER that changed something (however many Contacts it
/// has): what was registered, moved and unregistered.
fn log_register(user: &str, src: SocketAddr, ua: &str, done: &[(String, u32, Change)]) {
    match done {
        [] => {}
        [(_, exp, Change::Refreshed), ..] if done.iter().all(|d| d.2 == Change::Refreshed) => {
            log!(DEBUG, "{} refreshed from {} ({}s)", user, src, exp)
        }
        [(uri, exp, Change::New)] => log!(
            INFO,
            "{} registered from {} ({}) for {}s [{}]",
            user,
            src,
            clip(uri),
            exp,
            clip(ua)
        ),
        [(uri, exp, Change::Moved)] => log!(
            INFO,
            "{} re-registered from new address {} ({}) for {}s [{}]",
            user,
            src,
            clip(uri),
            exp,
            clip(ua)
        ),
        [(uri, _, Change::Removed)] => log!(INFO, "{} unregistered {} from {}", user, clip(uri), src),
        _ => {
            let what = |c: &Change| match c {
                Change::New => "registered",
                Change::Moved => "moved here",
                Change::Refreshed => "refreshed",
                Change::Removed => "unregistered",
                Change::Ignored => "ignored",
            };
            let mut list: Vec<String> = done
                .iter()
                .take(3)
                .map(|(uri, exp, c)| match c {
                    Change::Removed => format!("{} {}", what(c), clip(uri)),
                    _ => format!("{} {} for {}s", what(c), clip(uri), exp),
                })
                .collect();
            if done.len() > 3 {
                list.push(format!("{} more", done.len() - 3));
            }
            log!(INFO, "{} from {} [{}]: {}", user, src, clip(ua), list.join("; "));
        }
    }
}

/// Where responses for a request with this (top) Via go: `received` or the
/// sent-by host, and `rport` or the sent-by port (RFC 3261 18.2.2, RFC 3581).
fn reply_addr(via: &crate::sip::Via) -> Option<SocketAddr> {
    let host = via.param("received").flatten().unwrap_or(&via.host);
    let port = match via.param("rport").flatten().and_then(|p| p.parse().ok()) {
        Some(p) => p,
        None => via.port.unwrap_or(5060),
    };
    ip_addr(host, port).map(canonical)
}

/// RFC 3261 18.2.1 + RFC 3581: note where the request really came from in
/// the top Via so responses find their way back (also through NAT).
fn fix_top_via(req: &mut Message, src: SocketAddr) -> bool {
    let Some(i) = req.headers.iter().position(|h| h.name == "Via") else {
        return false;
    };
    let Some(mut via) = crate::sip::Via::parse(&req.headers[i].value) else {
        return false;
    };
    let ip = src.ip();
    if via.param("rport").is_some() {
        via.set_param("rport", Some(src.port().to_string()));
        via.set_param("received", Some(ip.to_string()));
    } else if parse_ip_host(&via.host) != Some(ip) || via.param("received").is_some() {
        // (also overwrite a `received` the client put there itself)
        via.set_param("received", Some(ip.to_string()));
    } else {
        return true;
    }
    req.headers[i].value = via.to_string();
    true
}
