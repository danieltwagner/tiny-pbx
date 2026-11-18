//! Ringing several phones at once ("forking", RFC 3261 16.6-16.10).
//!
//! Used when an INVITE has more than one target: a ring group, or an
//! extension registered from several devices. A `Fork` tracks each outgoing
//! INVITE until shortly after the call is answered or has failed. Its timers
//! run only during the call and its bounded cleanup; an idle PBX never wakes up.
//!
//! What it does:
//! - answers the caller with 100 Trying and sends the INVITE to every phone,
//!   retransmitting to each until it responds (UDP, Timer A/B);
//! - passes ringing (and early media) on to the caller;
//! - the first phone to answer wins: its 200 goes to the caller and every
//!   other phone gets a CANCEL ("call completed elsewhere", so phones don't
//!   log a missed call);
//! - a phone that is busy or rejects doesn't end the call while others still
//!   ring; when all have failed the caller gets the most useful response
//!   (redirect > authentication challenge > busy > decline > unavailable ...);
//! - declining (6xx) on one device of an extension stops its other devices;
//!   if the call is for that extension only, the decline is the caller's
//!   answer (RFC 3261 16.7), in a ring group the other members ring on;
//! - phones that never respond at all (stale registration) are given up on
//!   after a few seconds instead of holding the caller for 32 s, once
//!   another phone has responded (if none does, Timer B decides);
//! - a CANCEL from the caller cancels every phone; the caller gets its 487
//!   once they have stopped, so a 200 racing the CANCEL still reaches the
//!   caller (which then hangs that call up properly). A silent branch keeps
//!   retrying the INVITE until a response permits CANCEL or Timer B expires,
//!   so a phone can briefly start ringing after the caller hangs up;
//! - a phone that answers after the caller already got a final response (it
//!   was presumed dead) gets ACK + BYE instead of sitting in a dead call,
//!   with bounded retransmissions if the BYE is lost;
//! - after `RING_TIMEOUT` of ringing without an answer, everything is
//!   cancelled and the caller gets 480.
//!
//! Cleanup and response forwarding require the fork state. Once it expires
//! (or the PBX restarts), responses to its branches are silently dropped.
//!
//! The logic is pure: methods return the messages to send, so it can be
//! tested without sockets or real time.

use crate::log;
use crate::proxy::BRANCH_PREFIX;
use crate::sip::{Header, Message, NameAddr, StartLine, Via};
use crate::util::{random_hex, DEBUG, INFO};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub const T1: Duration = Duration::from_millis(500);
pub const T2: Duration = Duration::from_secs(4);
/// 64*T1: transaction timeout (Timer B/F/H).
pub const TIMER_B: Duration = Duration::from_secs(32);
/// How long phones may ring before we give up (Timer C).
pub const RING_TIMEOUT: Duration = Duration::from_secs(180);
/// A phone that hasn't sent anything by now (not even 100 Trying) is
/// presumed dead once all the others are done.
pub const DEAD_AFTER: Duration = Duration::from_secs(4);
/// Keep a finished fork around this long to absorb retransmissions.
pub const LINGER: Duration = Duration::from_secs(32);
/// Hard limit on a fork's life, whatever happens.
pub const MAX_AGE: Duration = Duration::from_secs(600);

/// Reason for CANCELs sent because another phone answered (RFC 3326).
const ELSEWHERE: &str = "SIP;cause=200;text=\"Call completed elsewhere\"";

/// A message to send.
#[derive(Clone)]
pub struct Out {
    pub msg: Message,
    pub dst: SocketAddr,
    /// Our address to send it from (None: the kernel's choice).
    pub src: Option<IpAddr>,
}

/// One target of the fork.
pub struct Target {
    /// Our Via branch for this target (unique, starts with our prefix).
    pub branch: String,
    /// The INVITE as sent to this phone (with our Via on top).
    pub invite: Message,
    pub dst: SocketAddr,
    /// Our address everything to this phone is sent from (the one in the
    /// INVITE's Via; None: the kernel's choice).
    pub local: Option<IpAddr>,
    /// The extension this device belongs to: a 6xx (decline) from one
    /// device stops the extension's other devices.
    pub ext: String,
    /// For logs, e.g. "102 at 192.168.130.52:5060".
    pub who: String,
}

impl Target {
    fn out(&self, msg: Message) -> Out {
        Out {
            msg,
            dst: self.dst,
            src: self.local,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    /// INVITE sent, nothing heard yet.
    Calling,
    /// Got a provisional response (it's ringing).
    Proceeding,
    Answered,
    Failed(u16),
    /// Gave up on it (no response, or no final response after CANCEL).
    TimedOut,
}

enum Cancel {
    No,
    /// Wanted, but we have to wait for a provisional response first.
    Wanted,
    Sent(ClientTransaction),
    Done,
}

/// Bounded UDP non-INVITE client transaction (Timers E/F). Keep the exact
/// request, including branch and CSeq, for retries; a 1xx is not completion.
struct ClientTransaction {
    req: Out,
    next: Instant,
    iv: Duration,
    give_up: Instant,
}

impl ClientTransaction {
    fn start(req: Out, now: Instant, out: &mut Vec<Out>) -> Self {
        out.push(req.clone());
        Self {
            req,
            next: now + T1,
            iv: T1,
            give_up: now + TIMER_B,
        }
    }

    /// True once a matching final response completes this transaction.
    fn on_response(&mut self, resp: &Message) -> bool {
        if resp.cseq() != self.req.msg.cseq() || resp.call_id() != self.req.msg.call_id() {
            return false;
        }
        if (100..200).contains(&resp.code()) {
            // Timer E runs at T2 in Proceeding. Duplicates must not postpone
            // either the next retry or the fixed Timer F deadline.
            self.iv = T2;
        }
        resp.code() >= 200
    }

    /// True on timeout. Expiry takes precedence over a due retransmission.
    fn tick(&mut self, now: Instant, out: &mut Vec<Out>) -> bool {
        if now >= self.give_up {
            return true;
        }
        if now >= self.next {
            out.push(self.req.clone());
            self.iv = (self.iv * 2).min(T2);
            self.next = now + self.iv;
        }
        false
    }

    fn next_deadline(&self) -> Instant {
        self.next.min(self.give_up)
    }
}

struct Branch {
    t: Target,
    state: State,
    /// Next INVITE retransmission (only while Calling).
    retx: Option<(Instant, Duration)>,
    /// Timer B (Calling), Timer C (Proceeding), or the wait for the final
    /// response after our CANCEL.
    deadline: Instant,
    cancel: Cancel,
    /// Reason for cancelling this one in particular (another device of the
    /// same extension declined).
    reason: Option<String>,
    /// Our ACK for this phone's negative final response (resent if the
    /// response is retransmitted).
    ack: Option<Message>,
    /// Hangup was started for a late answer; never start a second BYE transaction.
    hung_up: bool,
    /// BYE transaction for that late answer; hung_up stays true after it ends.
    bye: Option<ClientTransaction>,
}

impl Branch {
    fn terminal(&self) -> bool {
        matches!(self.state, State::Answered | State::Failed(_) | State::TimedOut)
    }

    fn busy(&self) -> bool {
        !self.terminal() || matches!(self.cancel, Cancel::Sent(_)) || self.bye.is_some()
    }

    fn send_cancel(&mut self, reason: Option<&str>, now: Instant, out: &mut Vec<Out>) {
        self.cancel = Cancel::Sent(ClientTransaction::start(
            self.t.out(build_cancel(&self.t.invite, reason)),
            now,
            out,
        ));
        self.deadline = now + TIMER_B;
    }
}

enum Server {
    /// Nothing final sent to the caller yet.
    Proceeding,
    /// We sent the caller a negative final response and wait for its ACK
    /// (retransmitting, Timer G/H).
    Completed {
        resp: Message,
        next: Instant,
        iv: Duration,
        give_up: Instant,
    },
    /// Answered (2xx passed on), or the negative final was ACKed.
    Done,
}

pub struct Fork {
    /// Caller's branch + Call-ID: identifies retransmissions, CANCEL, ACK.
    pub key: String,
    caller: SocketAddr,
    /// The IP address the INVITE came from (for per-phone limits: unlike
    /// the Via, the sender can't pick it freely).
    source: IpAddr,
    /// Our address the INVITE arrived on: everything to the caller is sent
    /// from it (None: the kernel's choice).
    local: Option<IpAddr>,
    invite: Message,
    local_tag: String,
    label: String,
    branches: Vec<Branch>,
    server: Server,
    last_provisional: Message,
    best: Option<Message>,
    /// WWW-/Proxy-Authenticate of every 401/407, all passed on with the one
    /// chosen (RFC 3261 16.7 step 7).
    challenges: Vec<Header>,
    /// A 6xx from a device when all targets belong to one extension: that
    /// is the caller's answer (RFC 3261 16.7), once the others have stopped.
    declined: Option<Message>,
    /// A phone answered and its 2xx went to the caller.
    answered: bool,
    /// The caller sent CANCEL.
    canceled: bool,
    /// Its Reason header(s), passed on to the phones (RFC 3326).
    cancel_reason: Option<String>,
    /// We sent the caller a negative final response.
    failed: bool,
    created: Instant,
    /// Some phone has responded: only then are silent ones presumed dead.
    heard: bool,
    quiet_since: Option<Instant>,
}

/// How useful a final response is to the caller when nobody answered;
/// lower is better. A redirect (call forwarding) beats every failure, as
/// the lowest class wins (RFC 3261 16.7). Next prefer a challenge: the
/// caller may succeed with credentials. Then busy > declined > unavailable.
/// A 482 says nothing either: a phone with several accounts
/// in the call (a DECT base, a two-line desk phone) takes the first INVITE
/// and may refuse the others as merged requests (RFC 3261 8.2.2.2).
fn rank(code: u16) -> u8 {
    match code {
        300..=399 => 0, // redirect: the caller can follow it
        401 | 407 => 1, // challenge: the caller can retry
        486 | 600 => 2, // busy
        603 => 3,       // declined
        480 | 404 | 410 => 4,
        487 | 408 | 482 => 9, // we cancelled it / it timed out / see above
        400..=499 => 5,
        500..=599 => 6,
        _ => 7,
    }
}

/// The caller's branch and Call-ID, which match an INVITE to its
/// retransmissions, CANCEL and non-2xx ACK.
pub fn key_of(msg: &Message) -> Option<String> {
    let via = msg.top_via()?;
    match via.branch().filter(|b| b.starts_with("z9hG4bK")) {
        Some(b) => Some(format!("{}|{}", b, msg.call_id()?)),
        // RFC 2543 phones: no usable branch
        None => Some(format!(
            "{}|{}|{}|{}:{}",
            msg.call_id()?,
            msg.cseq()?.0,
            msg.from_tag().unwrap_or_default(),
            via.host,
            via.port.unwrap_or(5060)
        )),
    }
}

fn request(method: &str, uri: &str) -> StartLine {
    StartLine::Request {
        method: method.into(),
        uri: uri.to_string(),
    }
}

/// Build a follow-up from the INVITE as sent on this branch. RFC 3261 22.1:
/// ACK repeats every credential sent on that INVITE, not the caller's original.
fn branch_request(invite: &Message, method: &str, uri: &str, cseq: u32) -> Message {
    let headers = invite
        .headers
        .iter()
        .filter(|h| match h.name.as_str() {
            "From" | "To" | "Call-ID" | "Route" | "Max-Forwards" => true,
            "Authorization" | "Proxy-Authorization" => method == "ACK",
            _ => false,
        })
        .cloned()
        .collect();
    let mut m = Message {
        start: request(method, uri),
        headers,
        body: Vec::new(),
    };
    m.insert_top("Via", invite.hdr("Via").unwrap_or("").to_string(), true);
    m.set("CSeq", format!("{} {}", cseq, method));
    m
}

/// RFC 3261 9.1: CANCEL for a request we sent.
fn build_cancel(invite: &Message, reason: Option<&str>) -> Message {
    let cseq = invite.cseq().map(|c| c.0).unwrap_or(1);
    let mut c = branch_request(invite, "CANCEL", invite.uri(), cseq);
    if let Some(r) = reason {
        c.set("Reason", r.to_string());
    }
    c
}

/// A unique Via branch for an active fork target. Retransmissions, CANCEL
/// and non-2xx ACK reuse the branch kept in `Target`; no recovery is needed.
/// The format is distinct from the proxy's stateless branches.
pub fn branch_id() -> String {
    format!("{}fork-{}", BRANCH_PREFIX, random_hex())
}

/// RFC 3261 17.1.1.3: ACK for a negative final response to our INVITE.
fn build_ack(invite: &Message, resp: &Message) -> Message {
    let cseq = invite.cseq().map(|c| c.0).unwrap_or(1);
    let mut a = branch_request(invite, "ACK", invite.uri(), cseq);
    if let Some(to) = resp.hdr("To") {
        a.set("To", to.to_string());
    }
    a
}

/// ACK + BYE for a 2xx that arrived after the caller was already given a
/// final response: hang up that phone ourselves. The 2xx's Contact is only
/// the Request-URI; both go to the address the INVITE went to, never to a
/// host the Contact names (a phone must not be able to aim PBX traffic at
/// anybody else). The only other hop in the phone's route set is us. Each
/// has a new branch, as ACK-for-2xx and BYE are new transactions.
fn hang_up(t: &Target, resp: &Message) -> [Out; 2] {
    let invite = &t.invite;
    let target = resp
        .hdr("Contact")
        .and_then(NameAddr::parse)
        .map(|n| n.uri)
        .unwrap_or_else(|| invite.uri().to_string());
    // Best effort: a fork does not track CSeqs of PRACK or UPDATE. A phone
    // whose early dialog advanced beyond this BYE's CSeq can reject cleanup.
    let cseq = invite.cseq().map(|c| c.0).unwrap_or(1);
    [("ACK", cseq, "a"), ("BYE", cseq.saturating_add(1), "b")].map(|(method, n, suffix)| {
        let mut m = branch_request(invite, method, &target, n);
        m.headers.retain(|h| h.name != "Route");
        if let Some(mut v) = m.hdr("Via").and_then(Via::parse) {
            v.set_param("branch", Some(format!("{}{}", t.branch, suffix)));
            m.set("Via", v.to_string());
        }
        if let Some(to) = resp.hdr("To") {
            m.set("To", to.to_string());
        }
        m.set("Max-Forwards", "70".into());
        if method == "ACK" && invite.body.is_empty() && is_sdp(resp) {
            // The INVITE had no offer, so the 2xx carries one and the ACK
            // must answer it (RFC 3261 13.2.2.4): decline every stream.
            m.body = reject_offer(&resp.body);
            m.set("Content-Type", "application/sdp".into());
        }
        t.out(m)
    })
}

fn is_sdp(m: &Message) -> bool {
    !m.body.is_empty()
        && m.hdr("Content-Type")
            .is_some_and(|t| t.trim().to_ascii_lowercase().starts_with("application/sdp"))
}

/// An SDP answer rejecting every stream of `offer` (port 0, RFC 3264 6).
fn reject_offer(offer: &[u8]) -> Vec<u8> {
    let mut sdp = String::from("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=-\r\nc=IN IP4 0.0.0.0\r\nt=0 0\r\n");
    for line in String::from_utf8_lossy(offer).lines() {
        let f: Vec<&str> = line
            .trim()
            .strip_prefix("m=")
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if let [media, _port, proto, fmt, ..] = f[..] {
            sdp.push_str(&format!("m={} 0 {} {}\r\n", media, proto, fmt));
        }
    }
    sdp.into_bytes()
}

impl Fork {
    /// Start ringing `targets`. `invite` is the caller's INVITE as received
    /// (top Via already has received/rport), `caller` where responses go,
    /// `source` the IP it came from, `local` our address it arrived on.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: String,
        invite: Message,
        caller: SocketAddr,
        source: IpAddr,
        local: Option<IpAddr>,
        local_tag: String,
        label: String,
        targets: Vec<Target>,
        now: Instant,
    ) -> (Fork, Vec<Out>) {
        let trying = invite.make_response(100, "Trying", None);
        let mut out = vec![Out {
            msg: trying.clone(),
            dst: caller,
            src: local,
        }];
        let branches = targets
            .into_iter()
            .map(|t| {
                out.push(t.out(t.invite.clone()));
                Branch {
                    t,
                    state: State::Calling,
                    retx: Some((now + T1, T1)),
                    deadline: now + TIMER_B,
                    cancel: Cancel::No,
                    reason: None,
                    ack: None,
                    hung_up: false,
                    bye: None,
                }
            })
            .collect();
        let fork = Fork {
            key,
            caller,
            source,
            local,
            invite,
            local_tag,
            label,
            branches,
            server: Server::Proceeding,
            last_provisional: trying,
            best: None,
            challenges: Vec::new(),
            declined: None,
            answered: false,
            canceled: false,
            cancel_reason: None,
            failed: false,
            created: now,
            heard: false,
            quiet_since: None,
        };
        (fork, out)
    }

    /// Where the caller's responses go.
    pub fn caller(&self) -> SocketAddr {
        self.caller
    }

    fn to_caller(&self, msg: Message) -> Out {
        Out {
            msg,
            dst: self.caller,
            src: self.local,
        }
    }

    /// Where the INVITE came from.
    pub fn source(&self) -> IpAddr {
        self.source
    }

    /// Still ringing: nothing final has been sent to the caller yet, and
    /// the caller hasn't cancelled (a cancelled call only waits for the
    /// phones to confirm, e.g. a mute one for up to 32 s).
    pub fn ringing(&self) -> bool {
        matches!(self.server, Server::Proceeding) && !self.answered && !self.canceled
    }

    /// Has a phone answered (2xx passed to the caller)?
    pub fn answered(&self) -> bool {
        self.answered
    }

    /// Find the branch whose late-answer BYE this response belongs to.
    pub fn hangup_branch_index(&self, branch: &str) -> Option<usize> {
        branch.strip_suffix('b').and_then(|b| self.branch_index(b))
    }

    pub fn on_hangup_response(&mut self, i: usize, resp: &Message, now: Instant) -> Vec<Out> {
        if let Some(tx) = &mut self.branches[i].bye {
            if tx.on_response(resp) {
                self.branches[i].bye = None;
            }
        }
        self.settle(Vec::new(), now)
    }

    /// Index of our branch with this Via branch parameter.
    pub fn branch_index(&self, branch: &str) -> Option<usize> {
        self.branches.iter().position(|b| b.t.branch == branch)
    }

    /// Reason for cancelling branch `i`: answered elsewhere, declined on
    /// another device of the extension, or whatever the caller said in its
    /// CANCEL.
    fn reason(&self, i: usize) -> Option<String> {
        match self.answered {
            true => Some(ELSEWHERE.into()),
            false => self.branches[i]
                .reason
                .clone()
                .or_else(|| self.cancel_reason.clone()),
        }
    }

    /// Device `i` declined (6xx): stop the extension's other devices. If
    /// the call is only for that extension, the decline is final for the
    /// whole call (RFC 3261 16.7); in a ring group the other members keep
    /// ringing.
    fn decline(&mut self, i: usize, resp: &Message, now: Instant, out: &mut Vec<Out>) {
        let ext = self.branches[i].t.ext.clone();
        let text = match &resp.start {
            StartLine::Response { reason, .. } => reason.replace(['"', '\\'], ""),
            StartLine::Request { .. } => String::new(),
        };
        let reason = format!("SIP;cause={};text=\"{}\"", resp.code(), text);
        for j in 0..self.branches.len() {
            if j != i && self.branches[j].t.ext == ext {
                self.branches[j].reason.get_or_insert_with(|| reason.clone());
                self.cancel_branch(j, now, out);
            }
        }
        if self.declined.is_none() && self.branches.iter().all(|b| b.t.ext == ext) {
            self.declined = Some(resp.clone());
        }
    }

    /// A response from one of the phones (our Via still on top).
    pub fn on_response(&mut self, i: usize, mut resp: Message, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        let code = resp.code();
        let method = resp.cseq().map(|c| c.1).unwrap_or_default();
        if method == "CANCEL" {
            if let Cancel::Sent(tx) = &mut self.branches[i].cancel {
                if tx.on_response(&resp) {
                    self.branches[i].cancel = Cancel::Done;
                }
            }
            return self.settle(out, now);
        }
        if method != "INVITE" {
            return out;
        }
        self.heard = true;
        resp.remove_first("Via");
        let (caller, local) = (self.caller, self.local);
        let to_caller = move |msg| Out {
            msg,
            dst: caller,
            src: local,
        };
        let reason = self.reason(i);
        let ringing = matches!(self.server, Server::Proceeding)
            && !self.answered
            && !self.canceled
            && self.declined.is_none();
        let failed = self.failed;
        let b = &mut self.branches[i];
        match code {
            100..=199 => {
                if b.state == State::TimedOut && matches!(b.cancel, Cancel::Wanted) {
                    // Timer B expired while silent. Even a late 100 now
                    // permits the CANCEL we could not send earlier. Remain
                    // terminal, but track this cleanup transaction separately.
                    b.send_cancel(reason.as_deref(), now, &mut out);
                }
                if b.state == State::Calling {
                    b.state = State::Proceeding;
                    b.retx = None;
                    if matches!(b.cancel, Cancel::Wanted) {
                        b.send_cancel(reason.as_deref(), now, &mut out);
                    } else {
                        b.deadline = now + RING_TIMEOUT;
                    }
                }
                if code > 100 && ringing && b.state == State::Proceeding {
                    self.last_provisional = resp.clone();
                    out.push(to_caller(resp));
                }
            }
            200..=299 if failed && b.state != State::Answered => {
                // too late: the caller was already told busy/unavailable.
                // ACK every (re)transmission of the 2xx; start just one BYE
                // transaction, whose retries are driven by its own timer.
                let first = !b.hung_up;
                if first {
                    log!(
                        INFO,
                        "call {}: {} answered too late, hanging it up",
                        self.label,
                        b.t.who
                    );
                }
                b.hung_up = true;
                b.state = State::TimedOut;
                b.retx = None;
                b.cancel = Cancel::Done;
                let [ack, bye] = hang_up(&b.t, &resp);
                out.push(ack);
                if first {
                    b.bye = Some(ClientTransaction::start(bye, now, &mut out));
                }
            }
            200..=299 => {
                // forward every 2xx, including retransmissions and a second
                // phone answering at the same time (the caller hangs that up)
                let first = b.state != State::Answered;
                b.state = State::Answered;
                b.retx = None;
                b.cancel = Cancel::Done;
                out.push(to_caller(resp));
                if first {
                    // linger long enough to pass on this phone's 2xx
                    // retransmissions too (it may answer during the linger)
                    self.quiet_since = None;
                }
                if first && !self.answered {
                    self.answered = true;
                    self.server = Server::Done;
                    log!(
                        INFO,
                        "call {}: answered by {}",
                        self.label,
                        self.branches[i].t.who
                    );
                }
            }
            _ => match b.state {
                // (also from one we had given up on: its user may just have
                // declined the call, which must still stop the others)
                State::Calling | State::Proceeding | State::TimedOut => {
                    b.state = State::Failed(code);
                    b.retx = None;
                    b.cancel = Cancel::Done;
                    let ack = build_ack(&b.t.invite, &resp);
                    out.push(b.t.out(ack.clone()));
                    b.ack = Some(ack);
                    log!(DEBUG, "call {}: {} says {}", self.label, b.t.who, code);
                    if code >= 600 {
                        self.decline(i, &resp, now, &mut out);
                    }
                    if code == 401 || code == 407 {
                        let auth = |h: &&Header| {
                            h.name.eq_ignore_ascii_case("WWW-Authenticate")
                                || h.name.eq_ignore_ascii_case("Proxy-Authenticate")
                        };
                        self.challenges.extend(resp.headers.iter().filter(auth).cloned());
                    }
                    if self.best.as_ref().is_none_or(|x| rank(code) < rank(x.code())) {
                        self.best = Some(resp);
                    }
                }
                State::Failed(_) => {
                    if let Some(a) = &b.ack {
                        out.push(b.t.out(a.clone()));
                    }
                }
                State::Answered => {}
            },
        }
        self.settle(out, now)
    }

    /// The caller retransmitted its INVITE, or sent CANCEL or ACK.
    /// `src` is where to answer.
    pub fn on_caller(&mut self, req: &Message, src: SocketAddr, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        match req.method() {
            "INVITE" => match &self.server {
                Server::Proceeding => out.push(Out {
                    msg: self.last_provisional.clone(),
                    dst: src,
                    src: self.local,
                }),
                Server::Completed { resp, .. } => out.push(Out {
                    msg: resp.clone(),
                    dst: src,
                    src: self.local,
                }),
                Server::Done => {}
            },
            "ACK" => {
                if matches!(self.server, Server::Completed { .. }) {
                    self.server = Server::Done;
                }
            }
            "CANCEL" => {
                out.push(Out {
                    msg: req.make_response(200, "OK", Some(&self.local_tag)),
                    dst: src,
                    src: self.local,
                });
                if matches!(self.server, Server::Proceeding) && !self.answered && !self.canceled {
                    // the 487 follows once the phones have stopped (settle)
                    self.canceled = true;
                    let reason: Vec<&str> = req.hdrs("Reason").collect();
                    self.cancel_reason = (!reason.is_empty()).then(|| reason.join(", "));
                    log!(INFO, "call {}: caller hung up", self.label);
                }
            }
            _ => {}
        }
        self.settle(out, now)
    }

    fn send_final(&mut self, resp: Message, now: Instant, out: &mut Vec<Out>) {
        self.failed = true;
        out.push(self.to_caller(resp.clone()));
        self.server = Server::Completed {
            resp,
            next: now + T1,
            iv: T1,
            give_up: now + TIMER_B,
        };
    }

    fn cancel_branch(&mut self, i: usize, now: Instant, out: &mut Vec<Out>) {
        let reason = self.reason(i);
        let b = &mut self.branches[i];
        match (b.state, &b.cancel) {
            (State::Calling, Cancel::No) => b.cancel = Cancel::Wanted,
            (State::Proceeding, Cancel::No | Cancel::Wanted) => {
                b.send_cancel(reason.as_deref(), now, out);
            }
            _ => {}
        }
    }

    /// Decide what follows from the current state of all branches.
    fn settle(&mut self, mut out: Vec<Out>, now: Instant) -> Vec<Out> {
        if self.answered || self.canceled || self.declined.is_some() {
            for i in 0..self.branches.len() {
                self.cancel_branch(i, now, &mut out);
            }
        }
        if matches!(self.server, Server::Proceeding) && !self.answered {
            // Phones silent for DEAD_AFTER are presumed dead (stale
            // registration), but only if another one has proved the call
            // gets through; if none responds, wait for Timer B.
            let dead = self.heard && now >= self.created + DEAD_AFTER;
            let over = self
                .branches
                .iter()
                .all(|b| b.terminal() || (dead && b.state == State::Calling));
            if over {
                for i in 0..self.branches.len() {
                    self.cancel_branch(i, now, &mut out);
                }
                let tag = Some(self.local_tag.as_str());
                let resp = match (&self.declined, &self.best) {
                    _ if self.canceled => self.invite.make_response(487, "Request Terminated", tag),
                    (Some(d), _) => d.clone(),
                    (None, Some(r)) if r.code() == 503 => self.invite.make_response(500, "Server Error", tag),
                    (None, Some(r)) if rank(r.code()) < 9 => {
                        let mut r = r.clone();
                        if matches!(r.code(), 401 | 407) {
                            for h in &self.challenges {
                                if !r.headers.contains(h) {
                                    r.headers.push(h.clone());
                                }
                            }
                        }
                        r
                    }
                    _ => self.invite.make_response(480, "Temporarily Unavailable", tag),
                };
                log!(INFO, "call {}: {}", self.label, crate::proxy::status_line(&resp));
                self.send_final(resp, now, &mut out);
            }
        }
        if matches!(self.server, Server::Done) && !self.branches.iter().any(Branch::busy) {
            self.quiet_since.get_or_insert(now);
        } else {
            // Cleanup can start during linger (a late provisional or 2xx).
            // Never reap a newly active transaction at the old quiet deadline.
            self.quiet_since = None;
        }
        out
    }

    /// Run timers that are due. Cheap to call at any time.
    pub fn tick(&mut self, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        for i in 0..self.branches.len() {
            let reason = self.reason(i);
            let b = &mut self.branches[i];
            if b.deadline <= now && !b.terminal() {
                // Calling: Timer B. Cancelled (CANCEL sent, maybe even
                // answered with 200) but no final response: give up too.
                if b.state == State::Calling || !matches!(b.cancel, Cancel::No) {
                    log!(DEBUG, "call {}: giving up on {}", self.label, b.t.who);
                    // A silent branch still needs cancellation if it finally
                    // responds during linger; a CANCEL already tried is done.
                    b.cancel = if b.state == State::Calling {
                        Cancel::Wanted
                    } else {
                        Cancel::Done
                    };
                    b.state = State::TimedOut;
                    b.retx = None;
                } else {
                    // rang for RING_TIMEOUT without an answer
                    log!(DEBUG, "call {}: {} rang too long", self.label, b.t.who);
                    b.send_cancel(reason.as_deref(), now, &mut out);
                }
            }
            if let (State::Calling, Some((at, iv))) = (b.state, b.retx) {
                if at <= now {
                    out.push(b.t.out(b.t.invite.clone()));
                    b.retx = Some((now + iv * 2, iv * 2));
                }
            }
            if let Cancel::Sent(tx) = &mut b.cancel {
                if tx.tick(now, &mut out) {
                    b.cancel = Cancel::Done;
                }
            }
            if let Some(tx) = &mut b.bye {
                if tx.tick(now, &mut out) {
                    b.bye = None;
                }
            }
        }
        if let Server::Completed {
            resp,
            next,
            iv,
            give_up,
        } = &mut self.server
        {
            if *give_up <= now {
                self.server = Server::Done;
            } else if *next <= now {
                out.push(Out {
                    msg: resp.clone(),
                    dst: self.caller,
                    src: self.local,
                });
                *iv = (*iv * 2).min(T2);
                *next = now + *iv;
            }
        }
        self.settle(out, now)
    }

    /// When `tick` next has something to do. Never in the past for things
    /// that `tick` has already handled, so the main loop can't spin.
    pub fn next_deadline(&self, now: Instant) -> Instant {
        let mut d = self.created + MAX_AGE;
        let mut consider = |t: Instant| d = d.min(t);
        if let Some(q) = self.quiet_since {
            consider(q + LINGER);
        }
        let mut calling = false;
        for b in &self.branches {
            if let (State::Calling, Some((at, _))) = (b.state, b.retx) {
                consider(at);
                calling = true;
            }
            if let Cancel::Sent(tx) = &b.cancel {
                consider(tx.next_deadline());
            }
            if let Some(tx) = &b.bye {
                consider(tx.next_deadline());
            }
            if !b.terminal() {
                consider(b.deadline);
            }
        }
        if calling
            && self.heard
            && matches!(self.server, Server::Proceeding)
            && self.created + DEAD_AFTER > now
        {
            consider(self.created + DEAD_AFTER);
        }
        if let Server::Completed { next, give_up, .. } = self.server {
            consider(next.min(give_up));
        }
        d
    }

    pub fn finished(&self, now: Instant) -> bool {
        self.quiet_since.is_some_and(|q| now >= q + LINGER) || now >= self.created + MAX_AGE
    }
}

#[cfg(test)]
#[path = "fork_tests.rs"]
mod tests;
