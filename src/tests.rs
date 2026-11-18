//! End-to-end tests of the proxy logic: a real `Pbx` on a loopback UDP
//! socket, "phones" are plain UDP sockets, messages are hand-written.
//! (Many of these started life as repros from a security review.)

#[path = "tests_auth.rs"]
mod auth_regressions;
#[path = "tests_hardening.rs"]
mod hardening;
#[cfg(target_os = "linux")]
#[path = "tests_multihome.rs"]
mod multihome;
#[path = "tests_routing.rs"]
mod routing_regressions;

use crate::config::Config;
use crate::proxy::Pbx;
use crate::sip::*;
use crate::util::*;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

struct Env {
    pbx: Pbx,
    port: u16,
    p101: UdpSocket,
    p102: UdpSocket,
    victim: UdpSocket,
    attacker: UdpSocket,
}

fn sock() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
    s
}

fn addr(s: &UdpSocket) -> SocketAddr {
    s.local_addr().unwrap()
}

/// PBX with 101 and 102 registered (101..103 configured); attacker and
/// victim are unregistered sockets.
fn env() -> Env {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    let mut cfg = Config::parse("[extensions]\n101 = pw101\n102 = pw102\n103 = pw103\n").unwrap();
    cfg.listen = format!("0.0.0.0:{}", port).parse().unwrap();
    cfg.state_file = None;
    cfg.log_level = ERROR;
    set_log_level(ERROR);
    let mut pbx = Pbx::new(cfg, s);
    let (p101, p102, victim, attacker) = (sock(), sock(), sock(), sock());
    for (ext, p) in [("101", &p101), ("102", &p102)] {
        let a = addr(p);
        let contact = format!("sip:{}@127.0.0.1:{}", ext, a.port());
        pbx.reg.update(ext, &contact, "", a, 3600, ext, 1, "ua");
    }
    Env {
        pbx,
        port,
        p101,
        p102,
        victim,
        attacker,
    }
}

fn recv(s: &UdpSocket) -> Option<Message> {
    let mut buf = [0u8; 65536];
    s.recv_from(&mut buf)
        .ok()
        .map(|(n, _)| Message::parse(&buf[..n]).expect("we sent garbage"))
}

fn status(m: &Option<Message>) -> u16 {
    m.as_ref().map(|m| m.code()).unwrap_or(0)
}

fn get_nonce(m: &Message, hdr: &str) -> String {
    let v = m.hdr(hdr).unwrap();
    let i = v.find("nonce=\"").unwrap() + 7;
    v[i..i + 32].to_string()
}

fn auth_hdr(hdr: &str, user: &str, pw: &str, method: &str, uri: &str, nonce: &str) -> String {
    auth_hdr_nc(hdr, user, pw, method, uri, nonce, 1)
}

/// Like `auth_hdr`, with nonce count `nc` (a response is accepted once:
/// the next request with the same nonce needs a higher count).
fn auth_hdr_nc(hdr: &str, user: &str, pw: &str, method: &str, uri: &str, nonce: &str, nc: u32) -> String {
    let ha1 = md5_hex(&format!("{}:pbx:{}", user, pw));
    let ha2 = md5_hex(&format!("{}:{}", method, uri));
    let resp = md5_hex(&format!("{}:{}:{:08x}:abc:auth:{}", ha1, nonce, nc, ha2));
    format!(
        "{hdr}: Digest username=\"{user}\", realm=\"pbx\", nonce=\"{nonce}\", uri=\"{uri}\", \
         response=\"{resp}\", algorithm=MD5, qop=auth, nc={nc:08x}, cnonce=\"abc\"\r\n"
    )
}

/// A request from `from` (the socket it'll be sent from). `extra` are raw
/// header lines ending in CRLF.
fn request(
    method: &str,
    ruri: &str,
    from_ext: &str,
    from: &UdpSocket,
    branch: &str,
    call: &str,
    extra: &str,
) -> String {
    let p = addr(from).port();
    let cseq = if method == "ACK" || method == "CANCEL" {
        1
    } else {
        1 + branch.len() as u32
    };
    format!(
        "{method} {ruri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{p};branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\nFrom: <sip:{from_ext}@pbx>;tag=f{from_ext}\r\nTo: <{ruri}>\r\n\
         Call-ID: {call}\r\nCSeq: {cseq} {method}\r\nContact: <sip:{from_ext}@127.0.0.1:{p}>\r\n{extra}\
         Content-Length: 0\r\n\r\n"
    )
}

fn send(e: &mut Env, from: &UdpSocket, msg: &str) {
    let a = addr(from);
    e.pbx.handle(msg.as_bytes(), a);
}

fn respond(e: &mut Env, phone: &UdpSocket, req: &Message, code: u16, tag: &str, contact: bool) {
    let mut r = req.make_response(code, "X", Some(tag));
    for rr in req.hdrs("Record-Route") {
        r.headers.push(Header {
            name: "Record-Route".into(),
            value: rr.to_string(),
        });
    }
    if contact {
        let c = format!("<sip:102@127.0.0.1:{}>", addr(phone).port());
        r.headers.push(Header {
            name: "Contact".into(),
            value: c,
        });
    }
    let a = addr(phone);
    e.pbx.handle(&r.to_bytes(), a);
}

// ------------------------------------------------------------------ registrar

#[test]
fn register_challenge_and_auth() {
    let mut e = env();
    let phone = sock();
    let p = addr(&phone).port();
    let reg = |cseq: u32, extra: &str| {
        format!(
            "REGISTER sip:127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{p};branch=z9hG4bKr{cseq};rport\r\n\
             From: <sip:103@pbx>;tag=x\r\nTo: <sip:103@pbx>\r\nCall-ID: reg103\r\nCSeq: {cseq} REGISTER\r\n\
             Contact: <sip:103@127.0.0.1:{p};line=abc>;+sip.instance=\"<urn:uuid:1>\"\r\n{extra}\
             Expires: 3600\r\nContent-Length: 0\r\n\r\n"
        )
    };
    send(&mut e, &phone, &reg(1, ""));
    let r = recv(&phone).unwrap();
    assert_eq!(r.code(), 401);
    let nonce = get_nonce(&r, "WWW-Authenticate");
    // wrong password -> 403, nothing registered
    send(
        &mut e,
        &phone,
        &reg(
            2,
            &auth_hdr(
                "Authorization",
                "103",
                "nope",
                "REGISTER",
                "sip:127.0.0.1",
                &nonce,
            ),
        ),
    );
    assert_eq!(status(&recv(&phone)), 403);
    assert!(e.pbx.reg.lookup("103").is_none());
    // right password
    let good = auth_hdr(
        "Authorization",
        "103",
        "pw103",
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
    );
    send(&mut e, &phone, &reg(3, &good));
    let r = recv(&phone).unwrap();
    assert_eq!(r.code(), 200);
    let c = r.hdr("Contact").unwrap();
    assert!(
        c.contains(";line=abc>") && c.contains("+sip.instance") && c.contains(";expires=3600"),
        "{}",
        c
    );
    assert!(r.hdr("Date").is_some());
    assert_eq!(e.pbx.reg.lookup("103").unwrap().source, addr(&phone));
    // the same credentials replayed from another address: stale, not accepted
    let evil = sock();
    send(
        &mut e,
        &evil,
        &reg(4, &good)
            .replace(
                &format!("127.0.0.1:{p};branch"),
                &format!("127.0.0.1:{};branch", addr(&evil).port()),
            )
            .replace("Call-ID: reg103", "Call-ID: evil"),
    );
    let r = recv(&evil).unwrap();
    assert_eq!(r.code(), 401);
    assert!(r.hdr("WWW-Authenticate").unwrap().contains("stale=true"));
    assert_eq!(e.pbx.reg.lookup("103").unwrap().source, addr(&phone));
    // authenticating as 103 but registering 102 -> 403 (each request with
    // the next nonce count, as phones do)
    let good = |nc| {
        auth_hdr_nc(
            "Authorization",
            "103",
            "pw103",
            "REGISTER",
            "sip:127.0.0.1",
            &nonce,
            nc,
        )
    };
    let other = reg(5, &good(2)).replace("To: <sip:103@pbx>", "To: <sip:102@pbx>");
    send(&mut e, &phone, &other);
    assert_eq!(status(&recv(&phone)), 403);
    // too short -> 423
    send(
        &mut e,
        &phone,
        &reg(6, &good(3)).replace("Expires: 3600", "Expires: 10"),
    );
    let r = recv(&phone).unwrap();
    assert_eq!(r.code(), 423);
    assert_eq!(r.hdr("Min-Expires"), Some("60"));
    // REGISTER with a To-tag (some phones do that on refresh) still works
    send(
        &mut e,
        &phone,
        &reg(7, &good(4)).replace("To: <sip:103@pbx>", "To: <sip:103@pbx>;tag=zz"),
    );
    assert_eq!(status(&recv(&phone)), 200);
    // unregister
    send(
        &mut e,
        &phone,
        &reg(8, &good(5)).replace("Expires: 3600", "Expires: 0"),
    );
    assert_eq!(status(&recv(&phone)), 200);
    assert!(e.pbx.reg.lookup("103").is_none());
}

#[test]
fn options_keepalive() {
    let mut e = env();
    let p101 = e.p101.try_clone().unwrap();
    send(
        &mut e,
        &p101,
        &request("OPTIONS", "sip:127.0.0.1", "101", &p101, "o1", "o1", ""),
    );
    let r = recv(&p101).unwrap();
    assert_eq!(r.code(), 200);
    assert!(r.hdr("Allow").is_some());
}

// ------------------------------------------------------------------ calls

#[test]
fn call_answer_hangup() {
    let mut e = env();
    let (p101, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let pbx = format!("sip:102@127.0.0.1:{}", e.port);
    send(
        &mut e,
        &p101,
        &request("INVITE", &pbx, "101", &p101, "inv1", "call1", ""),
    );
    let inv = recv(&p102).expect("INVITE forwarded to 102");
    assert_eq!(inv.uri(), format!("sip:102@127.0.0.1:{}", addr(&p102).port()));
    assert_eq!(inv.hdrs("Via").count(), 2);
    assert!(inv
        .top_via()
        .unwrap()
        .branch()
        .unwrap()
        .starts_with("z9hG4bK-pbx-"));
    assert_eq!(inv.hdr("Max-Forwards"), Some("69"));
    let rr: Vec<_> = inv.hdrs("Record-Route").collect();
    assert_eq!(rr.len(), 1);
    assert!(rr[0].starts_with(&format!("<sip:127.0.0.1:{};lr;pbx-dialog=", e.port)));
    // 180 + 200 go back to the caller without our Via
    respond(&mut e, &p102, &inv, 180, "t102", true);
    let r = recv(&p101).unwrap();
    assert_eq!(r.code(), 180);
    assert_eq!(r.hdrs("Via").count(), 1);
    respond(&mut e, &p102, &inv, 200, "t102", true);
    let ok = recv(&p101).unwrap();
    assert_eq!(ok.code(), 200);
    assert_eq!(ok.hdr("Record-Route"), Some(rr[0]));
    // ACK and BYE follow the route set to the callee's Contact
    let target = format!("sip:102@127.0.0.1:{}", addr(&p102).port());
    let route = format!("Route: {}\r\n", rr[0]);
    let ack = request("ACK", &target, "101", &p101, "ack1", "call1", &route).replace(
        &format!("To: <{}>", target),
        &format!("To: <{}>;tag=t102", target),
    );
    send(&mut e, &p101, &ack);
    let a = recv(&p102).expect("ACK delivered");
    assert_eq!(a.method(), "ACK");
    assert!(a.hdr("Route").is_none());
    // callee hangs up: BYE to the caller's Contact via the route set
    let caller = format!("sip:101@127.0.0.1:{}", addr(&p101).port());
    let bye = request("BYE", &caller, "102", &p102, "bye1", "call1", &route).replace(
        &format!("To: <{}>", caller),
        &format!("To: <{}>;tag=f101", caller),
    );
    send(&mut e, &p102, &bye);
    let b = recv(&p101).expect("BYE delivered");
    assert_eq!(b.method(), "BYE");
    assert_eq!(b.uri(), caller);
    let ok = b.make_response(200, "OK", None);
    let a = addr(&p101);
    e.pbx.handle(&ok.to_bytes(), a);
    assert_eq!(status(&recv(&p102)), 200);
}

#[test]
fn cancel_and_negative_ack_follow_the_invite() {
    let mut e = env();
    let (p101, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let pbx = format!("sip:102@127.0.0.1:{}", e.port);
    let invite = request("INVITE", &pbx, "101", &p101, "inv2", "call2", "");
    send(&mut e, &p101, &invite);
    let inv = recv(&p102).unwrap();
    let branch = inv.top_via().unwrap().branch().unwrap().to_string();
    let cancel = request("CANCEL", &pbx, "101", &p101, "inv2", "call2", "");
    send(&mut e, &p101, &cancel);
    let c = recv(&p102).expect("CANCEL forwarded");
    assert_eq!(c.method(), "CANCEL");
    assert_eq!(c.top_via().unwrap().branch(), Some(branch.as_str()));
    assert_eq!(c.uri(), inv.uri());
    respond(&mut e, &p102, &inv, 487, "t102", false);
    assert_eq!(status(&recv(&p101)), 487);
    let ack = request("ACK", &pbx, "101", &p101, "inv2", "call2", "")
        .replace(&format!("To: <{}>", pbx), &format!("To: <{}>;tag=t102", pbx));
    send(&mut e, &p101, &ack);
    let a = recv(&p102).expect("ACK for 487 forwarded");
    assert_eq!(a.top_via().unwrap().branch(), Some(branch.as_str()));
    assert_eq!(a.uri(), inv.uri());
}

#[test]
fn unknown_and_unregistered() {
    let mut e = env();
    let p101 = e.p101.try_clone().unwrap();
    send(
        &mut e,
        &p101,
        &request("INVITE", "sip:999@pbx", "101", &p101, "u1", "u1", ""),
    );
    assert_eq!(status(&recv(&p101)), 404);
    send(
        &mut e,
        &p101,
        &request("INVITE", "sip:103@pbx", "101", &p101, "u2", "u2", ""),
    );
    assert_eq!(status(&recv(&p101)), 480);
    // ACK for our own 480 is swallowed (and certainly not sent anywhere)
    let to_tag = recv_tag_after(&mut e, &p101, "u3");
    let ack = request("ACK", "sip:103@pbx", "101", &p101, "u3", "u3", "")
        .replace("To: <sip:103@pbx>", &format!("To: <sip:103@pbx>;tag={}", to_tag));
    send(&mut e, &p101, &ack);
    assert!(recv(&p101).is_none() && recv(&e.p102).is_none());
}

fn recv_tag_after(e: &mut Env, p101: &UdpSocket, call: &str) -> String {
    send(
        e,
        p101,
        &request("INVITE", "sip:103@pbx", "101", p101, call, call, ""),
    );
    let r = recv(p101).unwrap();
    r.to_tag().unwrap()
}

#[test]
fn strangers_must_authenticate() {
    let mut e = env();
    let (att, p102) = (e.attacker.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let inv = request("INVITE", "sip:102@pbx", "101", &att, "s1", "s1", "");
    send(&mut e, &att, &inv);
    let r = recv(&att).unwrap();
    assert_eq!(r.code(), 407);
    assert!(recv(&p102).is_none());
    let nonce = get_nonce(&r, "Proxy-Authenticate");
    // wrong password
    let bad = auth_hdr("Proxy-Authorization", "101", "x", "INVITE", "sip:102@pbx", &nonce);
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:102@pbx", "101", &att, "s2", "s1", &bad),
    );
    assert_eq!(status(&recv(&att)), 403);
    // right password for 101, but claiming to be 102 in From
    let good = auth_hdr(
        "Proxy-Authorization",
        "101",
        "pw101",
        "INVITE",
        "sip:102@pbx",
        &nonce,
    );
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:102@pbx", "102", &att, "s3", "s1", &good),
    );
    assert_eq!(status(&recv(&att)), 403);
    // correct: forwarded, without our credentials (the next nonce count:
    // the response above was used up)
    let good = auth_hdr_nc(
        "Proxy-Authorization",
        "101",
        "pw101",
        "INVITE",
        "sip:102@pbx",
        &nonce,
        2,
    );
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:102@pbx", "101", &att, "s4", "s1", &good),
    );
    let f = recv(&p102).expect("authenticated INVITE forwarded");
    assert!(f.hdr("Proxy-Authorization").is_none());
}

#[test]
fn auth_calls_and_record_route_can_be_turned_off() {
    let mut e = env();
    let (att, p102) = (e.attacker.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let invite = |call: &str| request("INVITE", "sip:102@pbx", "101", &att, call, call, "");
    send(&mut e, &att, &invite("on"));
    assert_eq!(status(&recv(&att)), 407, "by default a stranger is challenged");
    e.pbx.cfg.auth_calls = false;
    send(&mut e, &att, &invite("noauth"));
    let f = recv(&p102).expect("auth_calls = no: forwarded unchallenged");
    assert!(
        f.hdr("Record-Route").is_some(),
        "by default we stay in the dialog"
    );
    e.pbx.cfg.record_route = false;
    send(&mut e, &att, &invite("norr"));
    let f = recv(&p102).expect("forwarded");
    assert!(f.hdr("Record-Route").is_none(), "record_route = no");
}

#[test]
fn multi_line_phone_is_trusted_for_each_line() {
    let mut e = env();
    let (p101, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let a = addr(&p101);
    e.pbx.reg.update(
        "103",
        &format!("sip:103@127.0.0.1:{};line=2", a.port()),
        "",
        a,
        3600,
        "l2",
        1,
        "ua",
    );
    send(
        &mut e,
        &p101,
        &request("INVITE", "sip:102@pbx", "103", &p101, "ml", "ml", ""),
    );
    assert_eq!(recv(&p102).expect("forwarded without 407").method(), "INVITE");
}

#[test]
fn request_to_a_contact_uri() {
    // e.g. a transfer target addressed by its Contact, user part not the extension
    let mut e = env();
    let (p101, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let b = addr(&p102);
    let contact = format!("sip:k3j4h5@127.0.0.1:{}", b.port());
    e.pbx.reg.update("102", &contact, "", b, 3600, "c102x", 1, "ua");
    send(
        &mut e,
        &p101,
        &request(
            "INVITE",
            &contact,
            "101",
            &p101,
            "tr",
            "tr",
            "Replaces: abc;to-tag=1;from-tag=2\r\n",
        ),
    );
    let f = recv(&p102).expect("delivered to the contact");
    assert_eq!(f.uri(), contact);
}

#[test]
fn subscribe_is_refused() {
    let mut e = env();
    let p101 = e.p101.try_clone().unwrap();
    send(
        &mut e,
        &p101,
        &request(
            "SUBSCRIBE",
            "sip:101@pbx",
            "101",
            &p101,
            "sub",
            "sub",
            "Event: message-summary\r\n",
        ),
    );
    assert_eq!(status(&recv(&p101)), 489);
}

// ------------------------------------------------------------------ abuse

#[test]
fn no_relay_via_foreign_route() {
    let mut e = env();
    let att = e.attacker.try_clone().unwrap();
    let route = format!("Route: <sip:127.0.0.1:{};lr>\r\n", addr(&e.victim).port());
    send(
        &mut e,
        &att,
        &request("MESSAGE", "sip:x@example.com", "evil", &att, "r1", "r1", &route),
    );
    assert!(recv(&e.victim).is_none());
    assert_eq!(status(&recv(&att)), 403);
}

#[test]
fn register_is_never_relayed_via_a_route() {
    let mut e = env();
    let (p101, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let att = e.attacker.try_clone().unwrap();
    // A Route to 102's Contact: what a registered phone may send there...
    let route = format!("Route: <sip:102@{};lr>\r\n", addr(&p102));
    let via_route =
        |method: &str, from: &UdpSocket| request(method, "sip:pbx", "101", from, method, method, &route);
    send(&mut e, &p101, &via_route("MESSAGE", &p101));
    assert_eq!(recv(&p102).expect("relayed").method(), "MESSAGE");
    // ...but never a REGISTER, whoever sends it: we are the registrar.
    for from in [&p101, &att] {
        send(&mut e, from, &via_route("REGISTER", from));
        assert_eq!(status(&recv(from)), 403);
        assert!(recv(&p102).is_none());
    }
}

#[test]
fn no_relay_via_in_dialog_request() {
    let mut e = env();
    let att = e.attacker.try_clone().unwrap();
    let ruri = format!("sip:x@127.0.0.1:{}", addr(&e.victim).port());
    let m = request("MESSAGE", &ruri, "evil", &att, "r2", "r2", "")
        .replace(&format!("To: <{}>", ruri), &format!("To: <{}>;tag=1", ruri));
    send(&mut e, &att, &m);
    assert!(recv(&e.victim).is_none());
    assert_eq!(status(&recv(&att)), 481);
    // and an in-dialog-looking INVITE to an extension doesn't bypass the 407
    let m = request("INVITE", "sip:102@pbx", "101", &att, "r3", "r3", "")
        .replace("To: <sip:102@pbx>", "To: <sip:102@pbx>;tag=fake");
    send(&mut e, &att, &m);
    assert!(recv(&e.p102).is_none());
    assert_eq!(status(&recv(&att)), 481);
}

#[test]
fn no_relay_via_forged_response() {
    let mut e = env();
    let att = e.attacker.try_clone().unwrap();
    let (p, v) = (e.port, addr(&e.victim).port());
    let msg = format!(
        "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 127.0.0.1:{p};branch=z9hG4bK-pbx-0123456789abcdef0123\r\n\
         Via: SIP/2.0/UDP 127.0.0.1:{v};branch=z9hG4bKc\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>;tag=2\r\n\
         Call-ID: r4\r\nCSeq: 1 INVITE\r\nContent-Length: 7\r\n\r\nPAYLOAD"
    );
    send(&mut e, &att, &msg);
    assert!(recv(&e.victim).is_none());
}

#[test]
fn ignores_sources_outside_allow() {
    let mut e = env();
    let p101 = e.p101.try_clone().unwrap();
    let msg = request("OPTIONS", "sip:127.0.0.1", "101", &p101, "al", "al", "");
    send(&mut e, &p101, &msg);
    assert_eq!(status(&recv(&p101)), 200);
    e.pbx.cfg.allow = vec![Cidr::parse("10.0.0.0/8").unwrap()];
    send(&mut e, &p101, &msg);
    assert!(recv(&p101).is_none());
}

#[test]
fn huge_route_header_is_cheap() {
    let mut e = env();
    let att = e.attacker.try_clone().unwrap();
    let mut routes = String::new();
    while routes.len() < 60000 {
        routes.push_str(&format!("<sip:127.0.0.1:{};lr>,", e.port));
    }
    let m = request(
        "OPTIONS",
        "sip:101@x",
        "e",
        &att,
        "fl",
        "fl",
        &format!("Route: {}\r\n", routes),
    );
    let t = Instant::now();
    send(&mut e, &att, &m);
    assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
}

// ------------------------------------------------------------------ fuzzing

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
}

const WEIRD: &[&str] = &[
    "Via: SIP/2.0/UDP [::1]:5060;rport;branch=z9hG4bKx",
    "Via: SIP/2.0/UDP [",
    "Via: SIP/2.0/UDP []:",
    "Via: SIP/2.0/UDP host:99999",
    "Via: SIP/2.0/UDP ;;;==;",
    "Via: SIP / 2.0 / UDP x ;rport= ;received=",
    "Via: SIP/2.0/UDP 127.0.0.1:PBXPORT;branch=z9hG4bK-pbx-xx",
    "Via: ,,,,,",
    "Via: SIP/2.0/UDP é:1;branch=ü",
    "Via: SIP/2.0/UDP 1.2.3.4;received=::ffff:1.2.3.4;rport=0",
    "Route: <sip:127.0.0.1:PBXPORT;lr>, <sip:[::1]:PBXPORT;lr>",
    "Route: <",
    "Route: <sip:>",
    "Route: <sip:127.0.0.1:P101;lr>",
    "Contact: *",
    "Contact: \"unterminated <sip:a@b>",
    "Contact: <sip:101@[::1]:5060;transport=udp>;expires=99999999999",
    "Contact: <sip:101@127.0.0.1:P101>;expires=-5",
    "m: <sip:101@1.2.3.4>;+sip.instance=\"<urn:uuid:a,b>\";reg-id=1",
    "Content-Length: -1",
    "Content-Length: 99999999999999999999999",
    "l: 3",
    "CSeq: 4294967296 INVITE",
    "CSeq: 1",
    "Max-Forwards: 0",
    "Max-Forwards: 4294967295",
    "Expires: 18446744073709551616",
    "Authorization: Digest ,,,=,\"",
    "Authorization: Digest username=\"101\", realm=\"pbx\", nonce=\"ééééééééééé\", response=\"x\", uri=\"sip:pbx\"",
    "Proxy-Authorization: Digest username=\"\\\"\", realm=\"pbx\", nonce=\"0\", response=\"0\"",
    "Proxy-Require: foo",
    "From: <tel:+123>;tag=1",
    "To: <sip:102@pbx>;tag=",
    "To: sip:101@pbx;tag=y",
    "i: x",
    " folded continuation",
    "NoColonHeader",
    ": empty name",
];

const SEEDS: &[&str] = &[
    "INVITE sip:102@127.0.0.1:PBXPORT SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:P101;branch=z9hG4bK1;rport\r\nMax-Forwards: 70\r\nFrom: \"A\" <sip:101@pbx>;tag=a\r\nTo: <sip:102@pbx>\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\nContact: <sip:101@127.0.0.1:P101>\r\nContent-Type: application/sdp\r\nContent-Length: 4\r\n\r\nv=0\n",
    "REGISTER sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:P101;branch=z9hG4bK2;rport\r\nFrom: <sip:101@pbx>;tag=a\r\nTo: <sip:101@pbx>\r\nCall-ID: c2\r\nCSeq: 2 REGISTER\r\nContact: <sip:101@127.0.0.1:P101;line=x>;+sip.instance=\"<urn:uuid:1>\";reg-id=1\r\nExpires: 3600\r\nContent-Length: 0\r\n\r\n",
    "BYE sip:101@127.0.0.1:P101 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:P102;branch=z9hG4bK3;rport\r\nRoute: <sip:127.0.0.1:PBXPORT;lr>\r\nFrom: <sip:102@pbx>;tag=b\r\nTo: <sip:101@pbx>;tag=a\r\nCall-ID: c1\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n",
    "ACK sip:102@127.0.0.1:PBXPORT SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:P101;branch=z9hG4bK1;rport\r\nFrom: <sip:101@pbx>;tag=a\r\nTo: <sip:102@pbx>;tag=zz\r\nCall-ID: c1\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n",
    "CANCEL sip:102@127.0.0.1:PBXPORT SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:P101;branch=z9hG4bK1;rport\r\nFrom: <sip:101@pbx>;tag=a\r\nTo: <sip:102@pbx>\r\nCall-ID: c1\r\nCSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n",
    "SIP/2.0 180 Ringing\r\nVia: SIP/2.0/UDP 127.0.0.1:PBXPORT;branch=z9hG4bK-pbx-0123456789abcdef0123\r\nVia: SIP/2.0/UDP 127.0.0.1:P101;branch=z9hG4bK1;rport=P101;received=127.0.0.1\r\nFrom: <sip:101@pbx>;tag=a\r\nTo: <sip:102@pbx>;tag=b\r\nCall-ID: c1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
    "OPTIONS sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:P101;branch=z9hG4bK9\r\nFrom: <sip:101@pbx>;tag=a\r\nTo: <sip:pbx>\r\nCall-ID: c9\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    "MESSAGE sip:102@pbx SIP/2.0\r\nv: SIP/2.0/UDP [::1]:5060;branch=z9hG4bK8\r\nf: <sip:101@pbx>;tag=a\r\nt: <sip:102@pbx>\r\ni: c8\r\nCSeq: 1 MESSAGE\r\nc: text/plain\r\nl: 2\r\n\r\nhi",
];

fn mutate(r: &mut Rng, s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    let after_first_line = |v: &Vec<u8>| {
        v.windows(2)
            .position(|x| x == b"\r\n")
            .map(|p| p + 2)
            .unwrap_or(0)
    };
    for _ in 0..1 + r.below(4) {
        match r.below(9) {
            0 if !v.is_empty() => {
                let i = r.below(v.len());
                v[i] = r.next() as u8;
            }
            1 => {
                let i = r.below(v.len() + 1);
                for _ in 0..1 + r.below(8) {
                    let b = *r.pick(&[
                        0u8, 0xff, 0xc3, b'\r', b'\n', b' ', b';', b',', b'<', b'>', b'"', b'[', b']', b':',
                        b'@', b'=', b'\\',
                    ]);
                    v.insert(i, b);
                }
            }
            2 if !v.is_empty() => {
                let i = r.below(v.len());
                let n = r.below(v.len() - i + 1);
                v.drain(i..i + n);
            }
            3 => {
                let n = r.below(v.len() + 1);
                v.truncate(n);
            }
            4..=6 => {
                let w = format!("{}\r\n", r.pick(WEIRD));
                let i = after_first_line(&v);
                v.splice(i..i, w.into_bytes());
            }
            7 => {
                let n = 1000 + r.below(30000);
                let fill = *r.pick(&[
                    "a",
                    ",",
                    "<",
                    "\"",
                    ";x=",
                    "SIP/2.0/UDP a,",
                    "<sip:127.0.0.1;lr>,",
                ]);
                let name = *r.pick(&["X-Big", "Via", "Route", "Contact", "Record-Route"]);
                let mut h = format!("{}: ", name);
                while h.len() < n {
                    h.push_str(fill);
                }
                h.push_str("\r\n");
                let i = after_first_line(&v);
                v.splice(i..i, h.into_bytes());
            }
            _ => {
                let sl = *r.pick(&[
                    "SIP/2.0 200 OK",
                    "SIP/2.0 99 X",
                    "SIP/2.0 ",
                    "INVITE sip:[::1] SIP/2.0",
                    "INVITE tel:123 SIP/2.0",
                    "INVITE sip:@ SIP/2.0",
                    "INVITE sip:101@127.0.0.1:P101;lr SIP/2.0",
                    "REGISTER sip:pbx SIP/2.0",
                    "BYE sip:x@127.0.0.1:1 SIP/2.0",
                    "",
                ]);
                let end = v.windows(2).position(|x| x == b"\r\n").unwrap_or(v.len());
                v.splice(0..end, sl.bytes());
            }
        }
    }
    v
}

/// No panics on mangled input. Quick by default; FUZZ_ITERS=500000 (and
/// --release) for a thorough run.
#[test]
fn fuzz() {
    let mut e = env();
    let p = e.port.to_string();
    let p1 = addr(&e.p101).port().to_string();
    let p2 = addr(&e.p102).port().to_string();
    let fix = |s: &str| s.replace("PBXPORT", &p).replace("P101", &p1).replace("P102", &p2);
    let seeds: Vec<String> = SEEDS.iter().map(|s| fix(s)).collect();
    let iters: usize = std::env::var("FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let srcs: Vec<SocketAddr> = vec![addr(&e.p101), addr(&e.attacker), "[::1]:5060".parse().unwrap()];
    let all = [
        e.p101.try_clone().unwrap(),
        e.p102.try_clone().unwrap(),
        e.victim.try_clone().unwrap(),
        e.attacker.try_clone().unwrap(),
    ];
    for i in 0..iters {
        let seed = r.pick(&seeds).clone();
        let data = fix(&String::from_utf8_lossy(&mutate(&mut r, seed.as_bytes()))).into_bytes();
        let src = *r.pick(&srcs);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Ok(m) = Message::parse(&data) {
                let _ = (m.top_via(), m.from_tag(), m.to_tag(), m.from_user(), m.cseq());
                let _ = Message::parse(&m.to_bytes());
            }
            e.pbx.handle(&data, src);
        }));
        assert!(
            res.is_ok(),
            "panic at iteration {} on {:?}",
            i,
            String::from_utf8_lossy(&data)
        );
        if i % 64 == 0 {
            for s in &all {
                s.set_nonblocking(true).unwrap();
                let mut buf = [0u8; 65536];
                while s.recv_from(&mut buf).is_ok() {}
                s.set_nonblocking(false).unwrap();
            }
        }
    }
}

// ------------------------------------------------------------------ ring groups / forking

struct Group {
    pbx: Pbx,
    port: u16,
    caller: UdpSocket, // 101
    a: UdpSocket,      // 102
    b: UdpSocket,      // 103
}

/// 101 calls group 100 = 102 + 103 (all registered).
fn group_env() -> Group {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    let mut cfg = Config::parse(
        "[extensions]\n101 = pw101\n102 = pw102\n103 = pw103\n104 = pw104\n[groups]\n100 = 102 103\n200 = *\n",
    )
    .unwrap();
    cfg.listen = format!("0.0.0.0:{}", port).parse().unwrap();
    cfg.state_file = None;
    set_log_level(ERROR);
    let mut pbx = Pbx::new(cfg, s);
    let (caller, a, b) = (sock(), sock(), sock());
    for (ext, p) in [("101", &caller), ("102", &a), ("103", &b)] {
        let ad = addr(p);
        pbx.reg.update(
            ext,
            &format!("sip:{}@127.0.0.1:{}", ext, ad.port()),
            "",
            ad,
            3600,
            ext,
            1,
            "ua",
        );
    }
    Group {
        pbx,
        port,
        caller,
        a,
        b,
    }
}

fn gsend(g: &mut Group, from: &UdpSocket, msg: &str) {
    let a = addr(from);
    g.pbx.handle(msg.as_bytes(), a);
}

fn gresp(g: &mut Group, phone: &UdpSocket, req: &Message, code: u16, tag: &str) {
    let mut r = req.make_response(code, "X", Some(tag));
    for rr in req.hdrs("Record-Route") {
        r.headers.push(Header {
            name: "Record-Route".into(),
            value: rr.to_string(),
        });
    }
    if req.method() == "INVITE" {
        let c = format!("<sip:x@127.0.0.1:{}>", addr(phone).port());
        r.headers.push(Header {
            name: "Contact".into(),
            value: c,
        });
    }
    let a = addr(phone);
    g.pbx.handle(&r.to_bytes(), a);
}

fn later(secs: f64) -> Instant {
    Instant::now() + Duration::from_secs_f64(secs)
}

fn group_invite(g: &mut Group) -> (String, Message, Message) {
    let caller = g.caller.try_clone().unwrap();
    let inv = request("INVITE", "sip:100@pbx", "101", &caller, "g1", "gcall", "");
    gsend(g, &caller, &inv);
    assert_eq!(status(&recv(&caller)), 100, "caller gets 100 Trying");
    let ia = recv(&g.a).expect("102 rings");
    let ib = recv(&g.b).expect("103 rings");
    assert_eq!(ia.uri(), format!("sip:102@127.0.0.1:{}", addr(&g.a).port()));
    assert_eq!(ib.uri(), format!("sip:103@127.0.0.1:{}", addr(&g.b).port()));
    assert_ne!(ia.top_via().unwrap().branch(), ib.top_via().unwrap().branch());
    assert!(ia
        .hdr("Record-Route")
        .unwrap()
        .starts_with(&format!("<sip:127.0.0.1:{};lr;pbx-dialog=", g.port)));
    (inv, ia, ib)
}

#[test]
fn group_first_answer_wins() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (inv, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 180, "ta");
    let r = recv(&caller).unwrap();
    assert_eq!((r.code(), r.hdrs("Via").count()), (180, 1));
    gresp(&mut g, &b, &ib, 180, "tb");
    assert_eq!(status(&recv(&caller)), 180);
    // caller retransmits its INVITE: answered from the fork, phones not bothered
    gsend(&mut g, &caller, &inv);
    assert_eq!(status(&recv(&caller)), 180);
    assert!(recv(&a).is_none() && recv(&b).is_none());
    // 103 answers
    gresp(&mut g, &b, &ib, 200, "tb");
    let ok = recv(&caller).unwrap();
    assert_eq!(ok.code(), 200);
    assert_eq!(ok.to_tag().as_deref(), Some("tb"));
    // 102 is cancelled with the branch of its INVITE
    let c = recv(&a).expect("CANCEL to 102");
    assert_eq!(c.method(), "CANCEL");
    assert_eq!(c.top_via().unwrap().branch(), ia.top_via().unwrap().branch());
    assert_eq!(c.hdrs("Via").count(), 1);
    assert_eq!(c.uri(), ia.uri());
    gresp(&mut g, &a, &c, 200, "ta");
    gresp(&mut g, &a, &ia, 487, "ta");
    let ack = recv(&a).expect("we ACK 102's 487");
    assert_eq!((ack.method(), ack.to_tag().as_deref()), ("ACK", Some("ta")));
    assert!(recv(&caller).is_none(), "the 487 isn't passed on");
    // 2xx retransmission is still passed on
    gresp(&mut g, &b, &ib, 200, "tb");
    assert_eq!(status(&recv(&caller)), 200);
    // the caller's ACK goes end to end along the route set
    let target = format!("sip:x@127.0.0.1:{}", addr(&b).port());
    let route = format!("Route: <sip:127.0.0.1:{};lr>\r\n", g.port);
    let ack = request("ACK", &target, "101", &caller, "gack", "gcall", &route)
        .replace(&format!("To: <{}>", target), &format!("To: <{}>;tag=tb", target));
    gsend(&mut g, &caller, &ack);
    assert_eq!(recv(&b).expect("ACK to 103").method(), "ACK");
    // and afterwards no timers are left once the fork has lingered
    g.pbx.tick(later(1.0));
    assert!(recv(&a).is_none() && recv(&b).is_none() && recv(&caller).is_none());
    g.pbx.tick(later(40.0));
    assert_eq!(g.pbx.next_deadline(Instant::now()), None);
}

#[test]
fn group_busy_phone_doesnt_end_the_call() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (inv, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 486, "ta");
    assert_eq!(recv(&a).expect("ACK for 486").method(), "ACK");
    assert!(recv(&caller).is_none(), "103 still ringing");
    gresp(&mut g, &b, &ib, 180, "tb");
    assert_eq!(status(&recv(&caller)), 180);
    gresp(&mut g, &b, &ib, 603, "tb");
    assert_eq!(recv(&b).expect("ACK for 603").method(), "ACK");
    let fin = recv(&caller).unwrap();
    assert_eq!(fin.code(), 486, "busy is the most useful answer");
    // retransmitted until the caller ACKs
    g.pbx.tick(later(0.6));
    assert_eq!(status(&recv(&caller)), 486);
    let tag = fin.to_tag().unwrap();
    let ack = inv
        .replace("INVITE sip:100@pbx", "ACK sip:100@pbx")
        .replace(" INVITE\r\n", " ACK\r\n")
        .replace("To: <sip:100@pbx>", &format!("To: <sip:100@pbx>;tag={}", tag));
    gsend(&mut g, &caller, &ack);
    g.pbx.tick(later(5.0));
    assert!(recv(&caller).is_none() && recv(&a).is_none() && recv(&b).is_none());
}

#[test]
fn group_caller_cancels() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 180, "ta");
    assert_eq!(status(&recv(&caller)), 180);
    // 103 hasn't said anything yet: it can only be cancelled once it does
    let cancel = request("CANCEL", "sip:100@pbx", "101", &caller, "g1", "gcall", "");
    gsend(&mut g, &caller, &cancel);
    assert_eq!(status(&recv(&caller)), 200, "200 for the CANCEL");
    let c = recv(&a).expect("CANCEL to 102");
    assert_eq!(c.method(), "CANCEL");
    assert!(c.hdr("Reason").is_none(), "not 'completed elsewhere'");
    assert!(recv(&b).is_none());
    gresp(&mut g, &b, &ib, 180, "tb");
    assert_eq!(recv(&b).expect("CANCEL to 103 once it rings").method(), "CANCEL");
    assert!(recv(&caller).is_none(), "late 180 not passed on");
    gresp(&mut g, &a, &ia, 487, "ta");
    assert_eq!(recv(&a).unwrap().method(), "ACK");
    assert!(recv(&caller).is_none(), "103 hasn't stopped yet");
    gresp(&mut g, &b, &ib, 487, "tb");
    assert_eq!(recv(&b).unwrap().method(), "ACK");
    assert_eq!(status(&recv(&caller)), 487, "487 once all phones stopped");
}

#[test]
fn group_answer_racing_cancel_reaches_caller() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 180, "ta");
    gresp(&mut g, &b, &ib, 180, "tb");
    while recv(&caller).is_some() {}
    gsend(
        &mut g,
        &caller,
        &request("CANCEL", "sip:100@pbx", "101", &caller, "g1", "gcall", ""),
    );
    assert_eq!(status(&recv(&caller)), 200);
    while recv(&a).is_some() {}
    while recv(&b).is_some() {}
    // 103 had already picked up: its 200 still goes to the caller (which
    // then ACKs and BYEs it), instead of a 487 first
    gresp(&mut g, &b, &ib, 200, "tb");
    assert_eq!(status(&recv(&caller)), 200);
    gresp(&mut g, &a, &ia, 487, "ta");
    assert!(recv(&caller).is_none(), "no 487 after the 200");
}

#[test]
fn group_cancelled_phone_that_never_sends_487() {
    // review finding: used to spin the main loop and never answer the caller
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 180, "ta");
    gresp(&mut g, &b, &ib, 180, "tb");
    gsend(
        &mut g,
        &caller,
        &request("CANCEL", "sip:100@pbx", "101", &caller, "g1", "gcall", ""),
    );
    let ca = recv(&a).unwrap();
    let cb = recv(&b).unwrap();
    gresp(&mut g, &a, &ca, 200, "ta");
    gresp(&mut g, &b, &cb, 200, "tb");
    gresp(&mut g, &b, &ib, 487, "tb");
    // 102 never sends its 487
    while recv(&caller).is_some() {}
    let t = later(33.0);
    g.pbx.tick(t);
    let mut codes = Vec::new();
    while let Some(m) = recv(&caller) {
        codes.push(m.code());
    }
    assert_eq!(codes, vec![487]);
    assert!(
        g.pbx.next_deadline(t).is_none_or(|d| d > t),
        "deadline in the past = busy loop"
    );
}

#[test]
fn group_dead_phone_deadline_is_scheduled() {
    // the "presumed dead after 4 s" decision must have its own wake-up
    let mut g = group_env();
    let a = g.a.try_clone().unwrap();
    let (_, ia, _) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 486, "ta");
    for t in [0.6, 1.6, 3.6] {
        g.pbx.tick(later(t));
    }
    let d = g.pbx.next_deadline(later(3.6)).unwrap();
    assert!(d <= later(4.2), "next wake-up should be the 4 s dead-phone check");
    let caller = g.caller.try_clone().unwrap();
    while recv(&caller).is_some() {}
    g.pbx.tick(later(4.1));
    assert_eq!(status(&recv(&caller)), 486, "and that wake-up does decide");
}

#[test]
fn group_ack_for_our_final_stops_retransmissions() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (inv, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 480, "ta");
    gresp(&mut g, &b, &ib, 480, "tb");
    let fin = recv(&caller).unwrap();
    assert_eq!(fin.code(), 480);
    let ack = inv
        .replace("INVITE sip:100@pbx", "ACK sip:100@pbx")
        .replace(" INVITE\r\n", " ACK\r\n")
        .replace(
            "To: <sip:100@pbx>",
            &format!("To: <sip:100@pbx>;tag={}", fin.to_tag().unwrap()),
        );
    gsend(&mut g, &caller, &ack);
    g.pbx.tick(later(1.0));
    g.pbx.tick(later(3.0));
    assert!(recv(&caller).is_none(), "final not retransmitted after the ACK");
}

#[test]
fn group_late_answer_is_hung_up() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 486, "ta");
    g.pbx.tick(later(4.5)); // 103 presumed dead -> caller gets 486
    let mut last = 0;
    while let Some(m) = recv(&caller) {
        last = m.code();
    }
    assert_eq!(last, 486);
    while recv(&b).is_some() {}
    while recv(&a).is_some() {}
    // ... but 103 was just slow and picks up
    gresp(&mut g, &b, &ib, 200, "tb");
    assert!(recv(&caller).is_none(), "not passed to the caller");
    let ack = recv(&b).expect("ACK");
    let bye = recv(&b).expect("BYE");
    assert_eq!((ack.method(), bye.method()), ("ACK", "BYE"));
    assert_eq!(bye.uri(), format!("sip:x@127.0.0.1:{}", addr(&b).port()));
    assert_eq!(bye.to_tag().as_deref(), Some("tb"));
    assert_eq!(bye.cseq().unwrap().0, ia.cseq().unwrap().0 + 1);
}

#[test]
fn group_cancel_after_answer_says_elsewhere() {
    let mut g = group_env();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 180, "ta");
    gresp(&mut g, &b, &ib, 200, "tb");
    let c = recv(&a).unwrap();
    assert_eq!(c.method(), "CANCEL");
    assert!(c.hdr("Reason").unwrap().contains("cause=200"));
}

#[test]
fn one_phone_cancel_follows_the_invite() {
    // review finding: a second device registering while 102 rings used to
    // make the CANCEL fail (two targets now) and leave 102 ringing
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let a = g.a.try_clone().unwrap();
    let pbx = "sip:102@pbx";
    gsend(
        &mut g,
        &caller,
        &request("INVITE", pbx, "101", &caller, "one2", "one2", ""),
    );
    let ia = recv(&a).expect("102 rings (one device: no fork)");
    let a2 = sock();
    let ad = addr(&a2);
    g.pbx.reg.update(
        "102",
        &format!("sip:102@127.0.0.1:{}", ad.port()),
        "",
        ad,
        3600,
        "late",
        1,
        "ua",
    );
    gsend(
        &mut g,
        &caller,
        &request("CANCEL", pbx, "101", &caller, "one2", "one2", ""),
    );
    let c = recv(&a).expect("CANCEL reaches the phone that rings");
    assert_eq!(c.method(), "CANCEL");
    assert_eq!(c.top_via().unwrap().branch(), ia.top_via().unwrap().branch());
    assert!(recv(&a2).is_none());
}

#[test]
fn client_supplied_received_is_overwritten() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let a = g.a.try_clone().unwrap();
    let victim = sock();
    // no rport, sent-by = source, but a fake received= pointing elsewhere
    let m = request(
        "OPTIONS",
        &format!("sip:102@127.0.0.1:{}", addr(&a).port()),
        "101",
        &caller,
        "rv",
        "rv",
        "",
    )
    .replace(";rport", ";received=127.0.0.99");
    gsend(&mut g, &caller, &m);
    let f = recv(&a).expect("forwarded");
    let r = f.make_response(200, "OK", Some("x"));
    let ad = addr(&a);
    g.pbx.handle(&r.to_bytes(), ad);
    assert!(recv(&victim).is_none());
    assert_eq!(status(&recv(&caller)), 200, "response goes to the real source");
}

#[test]
fn group_gives_up_on_dead_phones() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, _) = group_invite(&mut g);
    // 103 never answers: INVITE retransmitted
    g.pbx.tick(later(0.6));
    assert_eq!(recv(&b).expect("retransmission").method(), "INVITE");
    assert_eq!(recv(&a).expect("102 hasn't answered either").method(), "INVITE");
    gresp(&mut g, &a, &ia, 486, "ta");
    assert_eq!(recv(&a).unwrap().method(), "ACK");
    assert!(recv(&caller).is_none());
    g.pbx.tick(later(DEAD_AFTER_SECS + 0.5));
    let mut got = None;
    while let Some(m) = recv(&caller) {
        got = Some(m.code());
    }
    assert_eq!(
        got,
        Some(486),
        "caller hears busy without waiting for the dead phone"
    );
}

const DEAD_AFTER_SECS: f64 = 4.0;

#[test]
fn group_ring_timeout() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 180, "ta");
    gresp(&mut g, &b, &ib, 180, "tb");
    while recv(&caller).is_some() {}
    g.pbx.tick(later(181.0));
    assert_eq!(recv(&a).unwrap().method(), "CANCEL");
    assert_eq!(recv(&b).unwrap().method(), "CANCEL");
    gresp(&mut g, &a, &ia, 487, "ta");
    gresp(&mut g, &b, &ib, 487, "tb");
    assert_eq!(status(&recv(&caller)), 480, "no answer");
}

#[test]
fn group_all_extensions_and_caller_excluded() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    // 200 = * : everyone but the calling phone (101) rings
    gsend(
        &mut g,
        &caller,
        &request("INVITE", "sip:200@pbx", "101", &caller, "s1", "star", ""),
    );
    assert_eq!(status(&recv(&caller)), 100);
    assert_eq!(recv(&g.a).unwrap().method(), "INVITE");
    assert_eq!(recv(&g.b).unwrap().method(), "INVITE");
    assert!(recv(&caller).is_none());
}

#[test]
fn group_with_one_phone_is_not_forked() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let a = g.a.try_clone().unwrap();
    g.pbx.reg.remove_all("103");
    let inv = request("INVITE", "sip:100@pbx", "101", &caller, "one", "one", "");
    gsend(&mut g, &caller, &inv);
    let ia = recv(&a).expect("102 rings");
    assert!(recv(&caller).is_none(), "no 100 Trying without a fork");
    assert_eq!(g.pbx.next_deadline(Instant::now()), None, "no timers");
    // busy -> caller; caller's ACK reaches 102
    gresp(&mut g, &a, &ia, 486, "ta");
    assert_eq!(status(&recv(&caller)), 486);
    let ack = inv
        .replace("INVITE sip:100@pbx", "ACK sip:100@pbx")
        .replace(" INVITE\r\n", " ACK\r\n")
        .replace("To: <sip:100@pbx>", "To: <sip:100@pbx>;tag=ta");
    gsend(&mut g, &caller, &ack);
    let ak = recv(&a).expect("ACK forwarded");
    assert_eq!(ak.method(), "ACK");
    assert_eq!(ak.top_via().unwrap().branch(), ia.top_via().unwrap().branch());
    // nobody registered at all -> 480
    g.pbx.reg.remove_all("102");
    gsend(
        &mut g,
        &caller,
        &request("INVITE", "sip:100@pbx", "101", &caller, "none", "none", ""),
    );
    assert_eq!(status(&recv(&caller)), 480);
}

#[test]
fn extension_on_two_devices_rings_both() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let a = g.a.try_clone().unwrap();
    let a2 = sock();
    let ad = addr(&a2);
    g.pbx.reg.update(
        "102",
        &format!("sip:102@127.0.0.1:{}", ad.port()),
        "",
        ad,
        3600,
        "dev2",
        1,
        "ua",
    );
    gsend(
        &mut g,
        &caller,
        &request("INVITE", "sip:102@pbx", "101", &caller, "two", "two", ""),
    );
    assert_eq!(status(&recv(&caller)), 100);
    assert_eq!(recv(&a).unwrap().method(), "INVITE");
    assert_eq!(recv(&a2).unwrap().method(), "INVITE");
    // one device of 102 calling 102 rings only the other one
    gsend(
        &mut g,
        &a2,
        &request("INVITE", "sip:102@pbx", "102", &a2, "self", "self", ""),
    );
    assert_eq!(recv(&a).unwrap().method(), "INVITE");
    assert!(recv(&a2).is_none());
}

#[test]
fn group_only_takes_calls() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    gsend(
        &mut g,
        &caller,
        &request("MESSAGE", "sip:100@pbx", "101", &caller, "m", "m", ""),
    );
    assert_eq!(status(&recv(&caller)), 405);
}

#[test]
fn group_limit_counts_only_ringing_calls() {
    // interop finding: finished calls (kept 32 s for retransmissions) used
    // to count, so redialling a busy group gave 503 after 4 tries
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    for n in 0..8 {
        let call = format!("redial{}", n);
        let inv = request("INVITE", "sip:100@pbx", "101", &caller, &call, &call, "");
        gsend(&mut g, &caller, &inv);
        assert_eq!(status(&recv(&caller)), 100, "try {}", n);
        let ia = recv(&a).unwrap();
        let ib = recv(&b).unwrap();
        gresp(&mut g, &a, &ia, 486, "ta");
        gresp(&mut g, &b, &ib, 486, "tb");
        while recv(&a).is_some() {}
        while recv(&b).is_some() {}
        assert_eq!(status(&recv(&caller)), 486, "try {}", n);
    }
    // ... while 4 calls actually ringing at once is still the limit
    for n in 0..5 {
        let call = format!("par{}", n);
        gsend(
            &mut g,
            &caller,
            &request("INVITE", "sip:100@pbx", "101", &caller, &call, &call, ""),
        );
        let want = if n < 4 { 100 } else { 503 };
        assert_eq!(status(&recv(&caller)), want, "parallel call {}", n);
    }
}

#[test]
fn keepalives_dont_starve_timers() {
    // interop finding: the main loop skipped the timers whenever a CRLF
    // keep-alive arrived, so enough keep-alives stalled a ringing group
    // call (no retransmissions, no final response)
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    gsend(
        &mut g,
        &caller,
        &request("INVITE", "sip:100@pbx", "101", &caller, "ka", "ka", ""),
    );
    assert_eq!(recv(&a).unwrap().method(), "INVITE");
    assert_eq!(recv(&b).unwrap().method(), "INVITE");
    let noise: SocketAddr = "127.0.0.1:9".parse().unwrap();
    g.pbx.step(Some((b"\r\n\r\n", noise, None)), later(0.6));
    assert_eq!(
        recv(&a).expect("retransmission despite keep-alive").method(),
        "INVITE"
    );
    assert_eq!(
        recv(&b).expect("retransmission despite keep-alive").method(),
        "INVITE"
    );
}

#[test]
fn group_late_answer_hangup_ignores_the_contact_host() {
    // security review: the ACK + BYE for a late 2xx went wherever the 2xx's
    // Contact pointed, so a phone could make the PBX send to any host
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let victim = sock();
    let (_, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 486, "ta");
    g.pbx.tick(later(4.5)); // 103 presumed dead -> caller gets 486
    while recv(&caller).is_some() {}
    while recv(&a).is_some() {}
    while recv(&b).is_some() {}
    let mut ok = ib.make_response(200, "OK", Some("tb"));
    let contact = format!("sip:x@{}", addr(&victim));
    ok.set("Contact", format!("<{}>", contact));
    g.pbx.handle(&ok.to_bytes(), addr(&b));
    let ack = recv(&b).expect("ACK to the phone that answered");
    let bye = recv(&b).expect("BYE to the phone that answered");
    assert_eq!((ack.method(), bye.method()), ("ACK", "BYE"));
    assert_eq!(bye.uri(), contact, "the Contact is still the Request-URI");
    assert!(recv(&victim).is_none(), "nothing sent to the Contact's host");
}

#[test]
fn cseq_of_2_pow_31_or_more_is_rejected() {
    // review finding: a group call with CSeq 4294967295 made the late-answer
    // BYE compute CSeq + 1 (panic in debug builds, 0 in release)
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    for (n, want) in [(4294967295u32, 400), (2147483648, 400), (2147483647, 100)] {
        let call = format!("cseq{}", n);
        let inv = request("INVITE", "sip:100@pbx", "101", &caller, &call, &call, "").replace(
            &format!("CSeq: {} INVITE", 1 + call.len()),
            &format!("CSeq: {} INVITE", n),
        );
        gsend(&mut g, &caller, &inv);
        assert_eq!(status(&recv(&caller)), want, "CSeq {}", n);
        let rang = recv(&g.a).is_some();
        assert_eq!(rang, want == 100, "CSeq {}: phones ring only if accepted", n);
        while recv(&g.b).is_some() {}
    }
}

#[test]
fn group_redirect_beats_failures() {
    // review finding: a phone forwarding the call (302) lost to a phone on
    // DND (480), so the caller heard "unavailable" instead of following
    // the forward. The lowest class wins (RFC 3261 16.7).
    for (first, second) in [(302, 480), (480, 302), (302, 486), (603, 302), (302, 500)] {
        let mut g = group_env();
        let caller = g.caller.try_clone().unwrap();
        let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
        let (_, ia, ib) = group_invite(&mut g);
        gresp(&mut g, &a, &ia, first, "ta");
        gresp(&mut g, &b, &ib, second, "tb");
        let mut fin = Vec::new();
        while let Some(m) = recv(&caller) {
            fin.push(m.code());
        }
        assert_eq!(fin, vec![302], "{} + {}", first, second);
    }
}

#[test]
fn group_all_silent_waits_for_timer_b() {
    // review finding: the 4 s dead-phone rule also fired when no phone had
    // responded at all (e.g. a packet filter or a slow network), so the
    // caller got 480 after 4 s. It needs one phone that did respond.
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let _ = group_invite(&mut g);
    for t in [0.6, 1.6, 3.6, 4.1, 7.6, 15.6] {
        g.pbx.tick(later(t));
        assert!(recv(&caller).is_none(), "no final at {} s", t);
    }
    g.pbx.tick(later(32.5));
    assert_eq!(status(&recv(&caller)), 480, "Timer B");

    // one phone responding late (after 4 s) still lets the silent one be
    // given up on at once
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let a = g.a.try_clone().unwrap();
    let (_, ia, _) = group_invite(&mut g);
    g.pbx.tick(later(4.1));
    assert!(recv(&caller).is_none());
    gresp(&mut g, &a, &ia, 486, "ta");
    g.pbx.tick(later(5.0));
    assert_eq!(status(&recv(&caller)), 486);
}

#[test]
fn group_caller_cancel_reason_is_passed_on() {
    // RFC 3326: a proxy SHOULD copy the Reason of a CANCEL it forwards; it
    // tells the phones why the call stopped (e.g. "missed call" or not)
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, ib) = group_invite(&mut g);
    gresp(&mut g, &a, &ia, 180, "ta");
    while recv(&caller).is_some() {}
    let reason = "Reason: Q.850;cause=16;text=\"Normal call clearing\"\r\nReason: SIP;cause=200\r\n";
    let cancel = request("CANCEL", "sip:100@pbx", "101", &caller, "g1", "gcall", reason);
    gsend(&mut g, &caller, &cancel);
    let want = Some("Q.850;cause=16;text=\"Normal call clearing\", SIP;cause=200");
    let c = recv(&a).expect("CANCEL to 102");
    assert_eq!(c.method(), "CANCEL");
    assert_eq!(c.hdr("Reason"), want);
    // also on the CANCEL deferred until the silent phone responds
    gresp(&mut g, &b, &ib, 100, "tb");
    let c = recv(&b).expect("deferred CANCEL to 103");
    assert_eq!(c.method(), "CANCEL");
    assert_eq!(c.hdr("Reason"), want);
}

/// Register another device for `ext` in the group env.
fn second_device(g: &mut Group, ext: &str, tag: &str) -> UdpSocket {
    let s = sock();
    let ad = addr(&s);
    let contact = format!("sip:{}@127.0.0.1:{}", ext, ad.port());
    g.pbx.reg.update(ext, &contact, "", ad, 3600, tag, 1, "ua");
    s
}

fn ack_final(g: &mut Group, inv: &str, fin: &Message) {
    let caller = g.caller.try_clone().unwrap();
    let ack = inv
        .replace("INVITE sip:", "ACK sip:")
        .replace(" INVITE\r\n", " ACK\r\n")
        .replace(
            &format!("To: <{}>", inv.split(' ').nth(1).unwrap()),
            &format!(
                "To: <{}>;tag={}",
                inv.split(' ').nth(1).unwrap(),
                fin.to_tag().unwrap()
            ),
        );
    gsend(g, &caller, &ack);
}

#[test]
fn group_decline_stops_that_extensions_other_devices_only() {
    // owner's decision (review finding): a 6xx from a device cancels the
    // other devices of the same extension; the other group members keep
    // ringing, and busy still beats declined for the caller's final
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let a2 = second_device(&mut g, "102", "dev2");
    let inv = request("INVITE", "sip:100@pbx", "101", &caller, "dec1", "dec1", "");
    gsend(&mut g, &caller, &inv);
    assert_eq!(status(&recv(&caller)), 100);
    let (ia, ia2, ib) = (recv(&a).unwrap(), recv(&a2).unwrap(), recv(&b).unwrap());
    for (p, i, t) in [(&a, &ia, "ta"), (&a2, &ia2, "ta2"), (&b, &ib, "tb")] {
        gresp(&mut g, p, i, 180, t);
    }
    while recv(&caller).is_some() {}
    gresp(&mut g, &a2, &ia2, 603, "ta2");
    assert_eq!(recv(&a2).unwrap().method(), "ACK");
    let c = recv(&a).expect("CANCEL to 102's other device");
    assert_eq!(c.method(), "CANCEL");
    assert_eq!(c.top_via().unwrap().branch(), ia.top_via().unwrap().branch());
    assert!(
        c.hdr("Reason").unwrap().starts_with("SIP;cause=603"),
        "{:?}",
        c.hdr("Reason")
    );
    assert!(recv(&b).is_none(), "103 keeps ringing");
    assert!(recv(&caller).is_none(), "the call goes on");
    gresp(&mut g, &a, &c, 200, "ta");
    gresp(&mut g, &a, &ia, 487, "ta");
    assert_eq!(recv(&a).unwrap().method(), "ACK");
    assert!(recv(&caller).is_none(), "103 still rings");
    gresp(&mut g, &b, &ib, 486, "tb");
    assert_eq!(recv(&b).unwrap().method(), "ACK");
    assert_eq!(status(&recv(&caller)), 486, "busy > declined");
}

#[test]
fn decline_on_one_device_of_a_dialled_extension_ends_the_call() {
    // RFC 3261 16.7: a 6xx cancels the other branches and is what the
    // caller gets, even over a busy device
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let a2 = second_device(&mut g, "102", "dev2");
    let a3 = second_device(&mut g, "102", "dev3");
    let inv = request("INVITE", "sip:102@pbx", "101", &caller, "dec2", "dec2", "");
    gsend(&mut g, &caller, &inv);
    assert_eq!(status(&recv(&caller)), 100);
    let (ia, ia2, ia3) = (recv(&a).unwrap(), recv(&a2).unwrap(), recv(&a3).unwrap());
    assert!(recv(&b).is_none());
    gresp(&mut g, &a3, &ia3, 486, "ta3");
    assert_eq!(recv(&a3).unwrap().method(), "ACK");
    gresp(&mut g, &a, &ia, 180, "ta");
    while recv(&caller).is_some() {}
    gresp(&mut g, &a2, &ia2, 603, "ta2");
    assert_eq!(recv(&a2).unwrap().method(), "ACK");
    let c = recv(&a).expect("CANCEL to the ringing device");
    assert_eq!(c.method(), "CANCEL");
    assert!(c.hdr("Reason").unwrap().starts_with("SIP;cause=603"));
    assert!(recv(&caller).is_none(), "final once the others have stopped");
    gresp(&mut g, &a, &c, 200, "ta");
    gresp(&mut g, &a, &ia, 487, "ta");
    assert_eq!(recv(&a).unwrap().method(), "ACK");
    let fin = recv(&caller).unwrap();
    assert_eq!(fin.code(), 603, "the decline, not busy / 487");
    ack_final(&mut g, &inv, &fin);
    g.pbx.tick(later(1.0));
    assert!(recv(&caller).is_none(), "ACKed");

    // a silent device: CANCEL once it responds, the 603 after 4 s
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let a = g.a.try_clone().unwrap();
    let a2 = second_device(&mut g, "102", "dev2");
    let inv = request("INVITE", "sip:102@pbx", "101", &caller, "dec3", "dec3", "");
    gsend(&mut g, &caller, &inv);
    assert_eq!(status(&recv(&caller)), 100);
    let (ia, ia2) = (recv(&a).unwrap(), recv(&a2).unwrap());
    gresp(&mut g, &a2, &ia2, 603, "ta2");
    assert_eq!(recv(&a2).unwrap().method(), "ACK");
    assert!(recv(&a).is_none() && recv(&caller).is_none());
    g.pbx.tick(later(4.1));
    let mut codes = Vec::new();
    while let Some(m) = recv(&caller) {
        codes.push(m.code());
    }
    assert_eq!(codes, vec![603]);
    while recv(&a).is_some() {}
    gresp(&mut g, &a, &ia, 180, "ta");
    let c = recv(&a).expect("deferred CANCEL");
    assert_eq!(c.method(), "CANCEL");
    assert!(c.hdr("Reason").unwrap().starts_with("SIP;cause=603"));
}

#[test]
fn group_cancelled_calls_dont_count_towards_the_callers_limit() {
    // review finding: a cancelled call whose phone never confirms the
    // CANCEL stays "ringing" for up to 32 s, so after hanging up on four
    // such calls the caller couldn't call a group for a while
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    for n in 0..4 {
        let call = format!("mute{}", n);
        gsend(
            &mut g,
            &caller,
            &request("INVITE", "sip:100@pbx", "101", &caller, &call, &call, ""),
        );
        assert_eq!(status(&recv(&caller)), 100);
        let (ia, ib) = (recv(&a).unwrap(), recv(&b).unwrap());
        gresp(&mut g, &a, &ia, 180, "ta");
        gresp(&mut g, &b, &ib, 180, "tb"); // 103 then goes off the network
        gsend(
            &mut g,
            &caller,
            &request("CANCEL", "sip:100@pbx", "101", &caller, &call, &call, ""),
        );
        let c = recv(&a).unwrap();
        gresp(&mut g, &a, &c, 200, "ta");
        gresp(&mut g, &a, &ia, 487, "ta");
        while recv(&a).is_some() {}
        while recv(&b).is_some() {}
        while recv(&caller).is_some() {}
    }
    for n in 0..5 {
        let call = format!("more{}", n);
        gsend(
            &mut g,
            &caller,
            &request("INVITE", "sip:100@pbx", "101", &caller, &call, &call, ""),
        );
        let want = if n < 4 { 100 } else { 503 };
        assert_eq!(status(&recv(&caller)), want, "call {} after 4 cancelled ones", n);
    }
}

#[test]
fn group_caller_limit_is_per_source_ip_not_via_port() {
    // security review: the limit was keyed by the Via reply address, so a
    // caller leaving out rport could pick a new "address" for every call
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let p = addr(&caller).port();
    for n in 0..8 {
        let call = format!("lim{}", n);
        let m = request("INVITE", "sip:100@pbx", "101", &caller, &call, &call, "").replace(
            &format!("127.0.0.1:{p};branch=z9hG4bK{call};rport"),
            &format!("127.0.0.1:{};branch=z9hG4bK{call}", 40000 + n),
        );
        gsend(&mut g, &caller, &m);
        if n < 4 {
            assert!(
                recv(&caller).is_none(),
                "call {}: 100 Trying goes to the Via port",
                n
            );
            assert_eq!(recv(&g.a).unwrap().method(), "INVITE", "call {} rings", n);
            assert_eq!(recv(&g.b).unwrap().method(), "INVITE");
        } else {
            assert_eq!(status(&recv(&caller)), 503, "call {}", n);
            assert!(recv(&g.a).is_none() && recv(&g.b).is_none());
        }
    }
}

#[test]
fn one_source_cannot_fill_the_fork_table() {
    // security review: one phone could fill all 256 fork slots (calls
    // cancelled at once, or answered busy, linger for 32 s or more), and
    // then every other phone's group calls got 503
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let att = UdpSocket::bind("127.0.0.2:0").unwrap();
    att.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
    let ad = addr(&att);
    g.pbx
        .reg
        .update("104", &format!("sip:104@{}", ad), "", ad, 3600, "att", 1, "ua");
    let mut accepted = 0;
    for n in 0..80 {
        let call = format!("flood{}", n);
        gsend(
            &mut g,
            &att,
            &request("INVITE", "sip:100@pbx", "104", &att, &call, &call, ""),
        );
        match status(&recv(&att)) {
            100 => accepted += 1,
            503 => continue,
            other => panic!("call {}: {}", n, other),
        }
        gsend(
            &mut g,
            &att,
            &request("CANCEL", "sip:100@pbx", "104", &att, &call, &call, ""),
        );
        assert_eq!(status(&recv(&att)), 200);
    }
    assert_eq!(accepted, 64, "a quarter of the table");
    gsend(
        &mut g,
        &caller,
        &request("INVITE", "sip:100@pbx", "101", &caller, "legit", "legit", ""),
    );
    assert_eq!(status(&recv(&caller)), 100, "other phones can still call groups");
}

/// The limits per caller have totals for all callers together: calls
/// ringing at once, and calls kept in all (here cancelled, but lingering).
#[cfg(target_os = "linux")] // callers on more loopback addresses than 127.0.0.1
#[test]
fn group_call_limits_also_count_all_callers_together() {
    for (callers, calls_each, cancel) in [(16, 4, false), (4, 64, true)] {
        let mut g = group_env();
        g.pbx.cfg.auth_calls = false; // these callers are not registered
        let invite = |s: &UdpSocket, call: &str| request("INVITE", "sip:100@pbx", "x", s, call, call, "");
        for ip in 1..=callers {
            let s = UdpSocket::bind(format!("127.0.1.{ip}:0")).unwrap();
            s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
            for n in 0..calls_each {
                let call = format!("all{ip}-{n}");
                gsend(&mut g, &s, &invite(&s, &call));
                assert_eq!(status(&recv(&s)), 100, "{call}");
                if cancel {
                    gsend(&mut g, &s, &invite(&s, &call).replace("INVITE", "CANCEL"));
                    assert_eq!(status(&recv(&s)), 200, "{call}");
                }
            }
        }
        let caller = g.caller.try_clone().unwrap();
        gsend(&mut g, &caller, &invite(&caller, "more"));
        assert_eq!(
            status(&recv(&caller)),
            503,
            "{callers} callers x {calls_each} calls"
        );
    }
}

/// 102 busy, 103 silent (frozen); the caller gets and ACKs 486; then the
/// fork expires (Timer B + linger). Returns 103's INVITE.
fn group_call_forgotten_by_the_fork(g: &mut Group, call: &str) -> Message {
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let inv = request("INVITE", "sip:100@pbx", "101", &caller, call, call, "");
    gsend(g, &caller, &inv);
    assert_eq!(status(&recv(&caller)), 100);
    let (ia, ib) = (recv(&a).unwrap(), recv(&b).unwrap());
    gresp(g, &a, &ia, 486, "ta");
    g.pbx.tick(later(4.5));
    let mut fin = None;
    while let Some(m) = recv(&caller) {
        fin = Some(m);
    }
    let fin = fin.unwrap();
    assert_eq!(fin.code(), 486);
    ack_final(g, &inv, &fin);
    g.pbx.tick(later(33.0)); // Timer B for 103
    g.pbx.tick(later(66.0)); // linger over
    assert_eq!(g.pbx.next_deadline(later(66.0)), None, "fork gone, PBX idle");
    while recv(&a).is_some() {}
    while recv(&b).is_some() {}
    ib
}

/// Lost fork state must not turn a response into a new transaction or a
/// stateless relay, even when it still has a valid caller Via and Contact.
fn assert_fork_responses_dropped(pbx: &mut Pbx, inv: &Message, src: &UdpSocket, peers: &[&UdpSocket]) {
    for code in [100, 180, 183, 200, 202, 486, 487, 603] {
        let mut r = inv.make_response(code, "Late", Some("late-phone"));
        r.set("Contact", format!("<sip:dialog@{}>", addr(peers[0])));
        // Retransmitted responses must be dropped too.
        for _ in 0..2 {
            pbx.handle(&r.to_bytes(), addr(src));
        }
    }
    // Responses to cleanup transactions also cannot recreate a forgotten fork.
    let n = inv.cseq().unwrap().0;
    for (method, suffix, seq) in [("CANCEL", "", n), ("BYE", "b", n + 1)] {
        let mut r = inv.make_response(200, "OK", Some("late-phone"));
        r.set("CSeq", format!("{} {}", seq, method));
        let mut via = r.top_via().unwrap();
        via.set_param("branch", Some(format!("{}{}", via.branch().unwrap(), suffix)));
        r.set("Via", via.to_string());
        pbx.handle(&r.to_bytes(), addr(src));
    }
    assert_eq!(pbx.next_deadline(Instant::now()), None, "no new state or timers");
    pbx.tick(later(700.0));
    assert_eq!(pbx.next_deadline(Instant::now()), None);
    for peer in peers {
        assert!(
            recv(peer).is_none(),
            "no forwarding or fabricated CANCEL/ACK/BYE to {}",
            addr(peer)
        );
    }
}

#[test]
fn group_responses_after_fork_linger_are_dropped() {
    let mut g = group_env();
    let (caller, a, b) = (
        g.caller.try_clone().unwrap(),
        g.a.try_clone().unwrap(),
        g.b.try_clone().unwrap(),
    );
    let contact = sock();
    let ib = group_call_forgotten_by_the_fork(&mut g, "frozen");
    assert_fork_responses_dropped(&mut g.pbx, &ib, &b, &[&contact, &caller, &a, &b]);
}

#[test]
fn unknown_fork_responses_are_dropped_even_with_tampered_routing() {
    let mut g = group_env();
    let b = g.b.try_clone().unwrap();
    let victim = sock();
    let ib = group_call_forgotten_by_the_fork(&mut g, "forged");
    // the right branch, from another address (spoofed or not): ignored
    let ok = ib.make_response(200, "OK", Some("x"));
    g.pbx.handle(&ok.to_bytes(), addr(&victim));
    assert!(recv(&victim).is_none() && recv(&b).is_none());
    // a tampered branch, or a different caller transaction: ignored
    let branch = ib.top_via().unwrap().branch().unwrap().to_string();
    let mut flipped = branch.clone();
    let last = flipped.pop().unwrap();
    flipped.push(if last == '0' { '1' } else { '0' });
    for (from, to) in [
        (branch.as_str(), flipped.as_str()),
        ("z9hG4bKforged", "z9hG4bKother"),
    ] {
        let mut m = ok.clone();
        let text = String::from_utf8(m.to_bytes()).unwrap().replacen(from, to, 1);
        m = Message::parse(text.as_bytes()).unwrap();
        g.pbx.handle(&m.to_bytes(), addr(&b));
        assert!(
            recv(&b).is_none() && recv(&victim).is_none(),
            "{} -> {}",
            from,
            to
        );
    }
    g.pbx.handle(&ok.to_bytes(), addr(&b));
    assert!(recv(&b).is_none(), "even the original branch is now unknown");
    assert!(recv(&g.caller).is_none(), "unknown branches are never relayed");
    assert!(recv(&victim).is_none());
}

#[test]
fn group_responses_after_restart_are_dropped() {
    // The routing key and registrations survive, but fork state does not.
    // Neither can authorize reconstruction of cleanup for an unknown fork.
    let dir = TestDir::create();
    let start = |s: UdpSocket| {
        let mut cfg =
            Config::parse("[extensions]\n101 = p\n102 = p\n103 = p\n[groups]\n100 = 102 103\n").unwrap();
        cfg.listen = format!("0.0.0.0:{}", s.local_addr().unwrap().port())
            .parse()
            .unwrap();
        cfg.state_file = Some(dir.join("state"));
        Pbx::new(cfg, s)
    };
    let mut pbx = start(UdpSocket::bind("127.0.0.1:0").unwrap());
    let (caller, a, b) = (sock(), sock(), sock());
    for (ext, p) in [("101", &caller), ("102", &a), ("103", &b)] {
        let ad = addr(p);
        pbx.reg
            .update(ext, &format!("sip:{}@{}", ext, ad), "", ad, 3600, ext, 1, "ua");
    }
    let inv = request("INVITE", "sip:100@pbx", "101", &caller, "rs", "rs", "");
    pbx.handle(inv.as_bytes(), addr(&caller));
    assert_eq!(status(&recv(&caller)), 100);
    let (ia, ib) = (recv(&a).unwrap(), recv(&b).unwrap());
    let port = pbx.cfg.listen.port();
    pbx.reg.save();
    drop(pbx);
    let mut pbx = start(UdpSocket::bind(("127.0.0.1", port)).unwrap());
    assert_eq!(pbx.reg.get("102").len(), 1, "registrations restored");
    let contact = sock();
    for (inv, phone) in [(&ia, &a), (&ib, &b)] {
        assert_fork_responses_dropped(&mut pbx, inv, phone, &[&contact, &caller, &a, &b]);
    }
}

#[test]
fn group_challenges_are_passed_on_together() {
    // RFC 3261 16.7 step 7: if the caller gets a 401/407, it carries the
    // challenges of every phone that asked for credentials
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (a, b) = (g.a.try_clone().unwrap(), g.b.try_clone().unwrap());
    let (_, ia, ib) = group_invite(&mut g);
    for (p, inv, code, name, realm) in [
        (&a, &ia, 401, "WWW-Authenticate", "a"),
        (&b, &ib, 407, "Proxy-Authenticate", "b"),
    ] {
        let mut r = inv.make_response(code, "Auth", Some("t"));
        r.headers.push(Header {
            name: name.into(),
            value: format!("Digest realm=\"{}\", nonce=\"n\"", realm),
        });
        g.pbx.handle(&r.to_bytes(), addr(p));
        assert_eq!(recv(p).unwrap().method(), "ACK");
    }
    let fin = recv(&caller).unwrap();
    assert_eq!(fin.code(), 401);
    assert_eq!(
        fin.hdr("WWW-Authenticate"),
        Some("Digest realm=\"a\", nonce=\"n\"")
    );
    assert_eq!(
        fin.hdr("Proxy-Authenticate"),
        Some("Digest realm=\"b\", nonce=\"n\"")
    );
    assert_eq!(fin.hdrs("WWW-Authenticate").count(), 1, "not duplicated");
}

#[test]
fn decline_from_a_device_already_given_up_on_still_counts() {
    // model check finding: a device that was silent past Timer B (frozen)
    // wakes up and its user declines: that must still stop the others
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let a = g.a.try_clone().unwrap();
    let a2 = second_device(&mut g, "102", "dev2");
    let inv = request("INVITE", "sip:102@pbx", "101", &caller, "dec4", "dec4", "");
    gsend(&mut g, &caller, &inv);
    assert_eq!(status(&recv(&caller)), 100);
    let (ia, ia2) = (recv(&a).unwrap(), recv(&a2).unwrap());
    gresp(&mut g, &a2, &ia2, 180, "ta2");
    assert_eq!(status(&recv(&caller)), 180);
    g.pbx.tick(later(33.0)); // Timer B for the silent device
    while recv(&a).is_some() {}
    assert!(recv(&caller).is_none(), "the other device still rings");
    gresp(&mut g, &a, &ia, 603, "ta");
    assert_eq!(recv(&a).unwrap().method(), "ACK");
    let c = recv(&a2).expect("CANCEL to the ringing device");
    assert_eq!(c.method(), "CANCEL");
    assert!(c.hdr("Reason").unwrap().starts_with("SIP;cause=603"));
    gresp(&mut g, &a2, &ia2, 183, "ta2");
    assert!(recv(&caller).is_none(), "no more ringing for a declined call");
    gresp(&mut g, &a2, &ia2, 487, "ta2");
    assert_eq!(status(&recv(&caller)), 603);
}
