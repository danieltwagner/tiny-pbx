//! Who may have requests forwarded, and where to (security audit): every
//! forwarding path applies the same authorization policy, and in-dialog
//! requests are only relayed to phones or between a dialog's endpoints.
//! Plus guards for legitimate routing that the policy must keep working.
use super::*;
use std::net::IpAddr;

fn with_to_tag(m: &str, ruri: &str, tag: &str) -> String {
    m.replace(&format!("To: <{}>", ruri), &format!("To: <{}>;tag={}", ruri, tag))
}

fn non_loopback_v4() -> Option<IpAddr> {
    interface_ips()
        .into_iter()
        .find(|ip| ip.is_ipv4() && !ip.is_loopback())
}

fn v6_sock() -> Option<UdpSocket> {
    let s = UdpSocket::bind("[::1]:0").ok()?;
    s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
    Some(s)
}

fn pbx_on(listen: &str, phones: &[(&str, &UdpSocket)]) -> Pbx {
    let s = UdpSocket::bind(listen).unwrap();
    let port = s.local_addr().unwrap().port();
    let mut cfg = Config::parse("[extensions]\n101 = pw101\n102 = pw102\n103 = pw103\n").unwrap();
    cfg.listen = SocketAddr::new(s.local_addr().unwrap().ip(), port);
    cfg.state_file = None;
    set_log_level(ERROR);
    let mut pbx = Pbx::new(cfg, s);
    for (ext, p) in phones {
        let a = addr(p);
        pbx.reg
            .update(ext, &format!("sip:{}@{}", ext, a), "", a, 3600, ext, 1, "ua");
    }
    pbx
}

fn respond_pbx(pbx: &mut Pbx, phone: &UdpSocket, req: &Message, code: u16, contact: bool) {
    let mut r = req.make_response(code, "X", Some("callee"));
    for rr in req.hdrs("Record-Route") {
        r.headers.push(Header {
            name: "Record-Route".into(),
            value: rr.to_string(),
        });
    }
    if contact {
        r.headers.push(Header {
            name: "Contact".into(),
            value: format!("<sip:102@{}>", addr(phone)),
        });
    }
    pbx.handle(&r.to_bytes(), addr(phone));
}

// ------------------------------------------------------------ guards

/// Loose outbound proxy preloaded, and prepended again on in-dialog requests
/// (pjsip does that), in front of our Record-Route.
#[test]
fn loose_outbound_proxy_prepended_in_dialog() {
    let mut e = env();
    let (a, b) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let ob = format!("<sip:127.0.0.1:{};lr>", e.port);
    let inv = request(
        "INVITE",
        "sip:102@pbx",
        "101",
        &a,
        "lob",
        "lob",
        &format!("Route: {}\r\n", ob),
    );
    send(&mut e, &a, &inv);
    let fi = recv(&b).expect("INVITE to 102");
    assert!(fi.hdr("Route").is_none());
    let rr = fi.hdr("Record-Route").unwrap().to_string();
    respond(&mut e, &b, &fi, 200, "callee", true);
    assert_eq!(status(&recv(&a)), 200);
    e.pbx.reg.remove_all("101");
    e.pbx.reg.remove_all("102");
    let target = format!("sip:102@127.0.0.1:{}", addr(&b).port());
    let route = format!("Route: {}, {}\r\n", ob, rr);
    let bye = with_to_tag(
        &request("BYE", &target, "101", &a, "lobbye", "lob", &route),
        &target,
        "callee",
    );
    send(&mut e, &a, &bye);
    assert_eq!(recv(&b).expect("BYE").method(), "BYE");
}

/// 101 on 127.0.0.1, 102 on another interface: double Record-Route, and the
/// dialog keeps working on the token alone once both registrations are gone.
#[test]
fn double_record_route_two_interfaces() {
    let Some(eth) = non_loopback_v4() else {
        eprintln!("no non-loopback IPv4 address, skipping");
        return;
    };
    let a = sock();
    let b = UdpSocket::bind(SocketAddr::new(eth, 0)).unwrap();
    b.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
    let mut pbx = pbx_on("0.0.0.0:0", &[("101", &a), ("102", &b)]);
    // This host's address may be a public one, which `allow` excludes by default.
    pbx.cfg.allow.push(Cidr { net: eth, len: 32 });
    let inv = request("INVITE", "sip:102@pbx", "101", &a, "drr", "drr", "");
    pbx.handle(inv.as_bytes(), addr(&a));
    let fi = recv(&b).expect("INVITE to 102");
    let rr: Vec<String> = fi.hdrs("Record-Route").map(str::to_string).collect();
    assert_eq!(rr.len(), 2, "double Record-Route expected");
    assert!(rr[0].contains(&eth.to_string()));
    assert!(rr[1].contains("127.0.0.1"));
    respond_pbx(&mut pbx, &b, &fi, 200, true);
    assert_eq!(status(&recv(&a)), 200);
    pbx.reg.remove_all("101");
    pbx.reg.remove_all("102");
    // caller's ACK: Route = reversed Record-Route
    let target = format!("sip:102@{}", addr(&b));
    let route = format!("Route: {}, {}\r\n", rr[1], rr[0]);
    let ack = with_to_tag(
        &request("ACK", &target, "101", &a, "drrack", "drr", &route),
        &target,
        "callee",
    );
    pbx.handle(ack.as_bytes(), addr(&a));
    let fa = recv(&b).expect("ACK must reach 102");
    assert!(fa.hdr("Route").is_none());
    // callee's BYE: Route = Record-Route order
    let caller = format!("sip:101@{}", addr(&a));
    let route = format!("Route: {}, {}\r\n", rr[0], rr[1]);
    let bye = with_to_tag(
        &request("BYE", &caller, "102", &b, "drrbye", "drr", &route),
        &caller,
        "f101",
    );
    pbx.handle(bye.as_bytes(), addr(&b));
    let fb = recv(&a).expect("BYE must reach 101");
    assert_eq!(fb.method(), "BYE");
    pbx.handle(&fb.make_response(200, "OK", None).to_bytes(), addr(&a));
    assert_eq!(status(&recv(&b)), 200);
}

/// IPv6 phones (and one IPv4 phone) on a dual-stack PBX, including a dialog
/// that outlives both registrations.
#[test]
fn ipv6_calls() {
    let Some(a) = v6_sock() else {
        eprintln!("no ::1, skipping");
        return;
    };
    let b = v6_sock().unwrap();
    let c = sock();
    let mut pbx = pbx_on("[::]:0", &[("101", &a), ("102", &b), ("103", &c)]);
    let port = pbx.cfg.listen.port();
    let pa = addr(&a).port();
    let inv = format!(
        "INVITE sip:102@[::1]:{port} SIP/2.0\r\nVia: SIP/2.0/UDP [::1]:{pa};branch=z9hG4bKv6;rport\r\n\
         Max-Forwards: 70\r\nFrom: <sip:101@pbx>;tag=f101\r\nTo: <sip:102@pbx>\r\nCall-ID: v6\r\n\
         CSeq: 1 INVITE\r\nContact: <sip:101@[::1]:{pa}>\r\nContent-Length: 0\r\n\r\n"
    );
    pbx.handle(inv.as_bytes(), addr(&a));
    let fi = recv(&b).expect("v6 INVITE to 102");
    let rr = fi.hdr("Record-Route").unwrap().to_string();
    respond_pbx(&mut pbx, &b, &fi, 200, true);
    assert_eq!(status(&recv(&a)), 200);
    // v4 phone 103 calls v6 phone 102
    let inv = request("INVITE", "sip:102@pbx", "103", &c, "v4v6", "v4v6", "");
    pbx.handle(inv.as_bytes(), addr(&c));
    let fi = recv(&b).expect("v4->v6 INVITE to 102");
    respond_pbx(&mut pbx, &b, &fi, 180, false);
    assert_eq!(status(&recv(&c)), 180);
    // the v6 dialog survives both registrations disappearing
    pbx.reg.remove_all("101");
    pbx.reg.remove_all("102");
    let caller = format!("sip:101@{}", addr(&a));
    let bye = format!(
        "BYE {caller} SIP/2.0\r\nVia: SIP/2.0/UDP {b};branch=z9hG4bKv6bye;rport\r\nRoute: {rr}\r\n\
         Max-Forwards: 70\r\nFrom: <sip:102@pbx>;tag=callee\r\nTo: <sip:101@pbx>;tag=f101\r\n\
         Call-ID: v6\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n",
        b = addr(&b)
    );
    pbx.handle(bye.as_bytes(), addr(&b));
    assert_eq!(recv(&a).expect("v6 BYE without registrations").method(), "BYE");
}

// ------------------------------------------------------------ authorization

/// A stranger whose Route named a registered phone's Contact skipped the 407
/// challenge (spoofed caller-ID, and the phone's responses flowed back to
/// it). Resending the INVITE without the Route then hit the transaction
/// cache and was forwarded with a dialog token minted for the stranger.
#[test]
fn foreign_route_to_a_phone_needs_the_same_authorization() {
    let mut e = env();
    let (att, p101, p102) = (
        e.attacker.try_clone().unwrap(),
        e.p101.try_clone().unwrap(),
        e.p102.try_clone().unwrap(),
    );
    let route = format!("Route: <sip:127.0.0.1:{};lr>\r\n", addr(&p102).port());
    let inv = request("INVITE", "sip:102@pbx", "101", &att, "fr1", "fr1", &route);
    send(&mut e, &att, &inv);
    let challenge = recv(&att).expect("challenged");
    assert_eq!(challenge.code(), 407);
    assert!(recv(&p102).is_none(), "unauthenticated INVITE reached 102");
    // not remembered as an authorized transaction either
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:102@pbx", "101", &att, "fr1", "fr1", ""),
    );
    assert_eq!(status(&recv(&att)), 407);
    assert!(recv(&p102).is_none(), "recalled without authorization");
    // in-dialog requests through such a Route need a token / registration
    let c102 = format!("sip:102@127.0.0.1:{}", addr(&p102).port());
    for method in ["BYE", "INVITE", "MESSAGE"] {
        let m = with_to_tag(
            &request(method, &c102, "101", &att, "fr2", "fr2", &route),
            &c102,
            "x",
        );
        send(&mut e, &att, &m);
        assert_eq!(status(&recv(&att)), 481, "{}", method);
        assert!(recv(&p102).is_none(), "{} reached 102", method);
    }
    // a registered phone may preload such a Route...
    send(
        &mut e,
        &p101,
        &request("INVITE", "sip:102@pbx", "101", &p101, "fr3", "fr3", &route),
    );
    assert_eq!(recv(&p102).expect("from a registered phone").method(), "INVITE");
    // ...and so may a caller that answers the challenge; its credentials stay here
    let nonce = get_nonce(&challenge, "Proxy-Authenticate");
    let pa = auth_hdr(
        "Proxy-Authorization",
        "103",
        "pw103",
        "INVITE",
        "sip:102@pbx",
        &nonce,
    );
    let inv = request("INVITE", "sip:102@pbx", "103", &att, "fr4", "fr4", &(route + &pa));
    send(&mut e, &att, &inv);
    let f = recv(&p102).expect("authenticated INVITE");
    assert!(f.hdr("Proxy-Authorization").is_none());
}

/// An in-dialog-looking request (To-tag) whose Request-URI is a registered
/// phone's Contact was forwarded without any check.
#[test]
fn in_dialog_request_to_a_phone_needs_a_registered_source_or_token() {
    let mut e = env();
    let (att, p101, p102) = (
        e.attacker.try_clone().unwrap(),
        e.p101.try_clone().unwrap(),
        e.p102.try_clone().unwrap(),
    );
    let c102 = format!("sip:102@127.0.0.1:{}", addr(&p102).port());
    for method in ["INVITE", "MESSAGE", "BYE", "REFER", "ACK"] {
        let m = with_to_tag(&request(method, &c102, "101", &att, "id1", "id1", ""), &c102, "x");
        send(&mut e, &att, &m);
        assert!(recv(&p102).is_none(), "{} from a stranger reached 102", method);
        let want = if method == "ACK" { 0 } else { 481 };
        assert_eq!(status(&recv(&att)), want, "{}", method);
    }
    let m = with_to_tag(
        &request("MESSAGE", &c102, "101", &p101, "id2", "id2", ""),
        &c102,
        "x",
    );
    send(&mut e, &p101, &m);
    assert_eq!(recv(&p102).expect("from a registered phone").method(), "MESSAGE");
}

/// A caller that never registered answers the 407 challenge: its dialog
/// (carrying our token) works in both directions, also after the callee's
/// registration is gone, and its retransmission is recalled unchanged.
#[test]
fn authenticated_stranger_dialog_works_both_ways() {
    let mut e = env();
    let (s, p102) = (e.attacker.try_clone().unwrap(), e.p102.try_clone().unwrap());
    send(
        &mut e,
        &s,
        &request("INVITE", "sip:102@pbx", "103", &s, "st1", "stc", ""),
    );
    let nonce = get_nonce(&recv(&s).unwrap(), "Proxy-Authenticate");
    let pa = auth_hdr(
        "Proxy-Authorization",
        "103",
        "pw103",
        "INVITE",
        "sip:102@pbx",
        &nonce,
    );
    let inv = request("INVITE", "sip:102@pbx", "103", &s, "st2", "stc", &pa);
    send(&mut e, &s, &inv);
    let fi = recv(&p102).expect("authenticated INVITE");
    assert!(fi.hdr("Proxy-Authorization").is_none());
    let rr = fi.hdr("Record-Route").unwrap().to_string();
    send(&mut e, &s, &inv);
    let again = recv(&p102).expect("retransmission");
    assert_eq!(
        again.to_bytes(),
        fi.to_bytes(),
        "retry must be the same credential-free INVITE"
    );
    respond(&mut e, &p102, &fi, 200, "callee", true);
    assert_eq!(status(&recv(&s)), 200);
    let route = format!("Route: {}\r\n", rr);
    let c102 = format!("sip:102@127.0.0.1:{}", addr(&p102).port());
    let c103 = format!("sip:103@127.0.0.1:{}", addr(&s).port());
    let ack = with_to_tag(
        &request("ACK", &c102, "103", &s, "st3", "stc", &route),
        &c102,
        "callee",
    );
    send(&mut e, &s, &ack);
    assert_eq!(recv(&p102).expect("ACK").method(), "ACK");
    // the callee hangs up on a Contact the PBX has no registration for
    let bye = with_to_tag(
        &request("BYE", &c103, "102", &p102, "st4", "stc", &route),
        &c103,
        "f103",
    );
    send(&mut e, &p102, &bye);
    assert_eq!(recv(&s).expect("BYE to the caller").method(), "BYE");
    e.pbx.reg.remove_all("102");
    let bye = with_to_tag(
        &request("BYE", &c102, "103", &s, "st5", "stc", &route),
        &c102,
        "callee",
    );
    send(&mut e, &s, &bye);
    assert_eq!(recv(&p102).expect("BYE to the callee").method(), "BYE");
}

// ------------------------------------------------------------ relay targets

/// Call 101 -> 102 and return the Record-Route (with our dialog token).
fn establish(e: &mut Env, call: &str) -> String {
    let (a, b) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    send(
        e,
        &a,
        &request("INVITE", "sip:102@pbx", "101", &a, call, call, ""),
    );
    let inv = recv(&b).unwrap();
    let rr = inv.hdr("Record-Route").unwrap().to_string();
    respond(e, &b, &inv, 200, "callee", true);
    assert_eq!(recv(&a).unwrap().code(), 200);
    rr
}

/// A registered phone (or anybody spoofing its address) could have the PBX
/// send any payload to whatever ip:port an in-dialog Request-URI named,
/// e.g. Internet hosts or services listening only on the PBX's localhost.
#[test]
fn in_dialog_requests_are_relayed_only_to_phones_or_the_dialog_peer() {
    let mut e = env();
    let (p101, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let victim = e.victim.try_clone().unwrap();
    let v = format!("sip:x@127.0.0.1:{}", addr(&victim).port());
    let msg = |from: &UdpSocket, ext: &str, branch: &str, route: &str| {
        with_to_tag(&request("MESSAGE", &v, ext, from, branch, "rl", route), &v, "1").replace(
            "Content-Length: 0\r\n\r\n",
            "Content-Length: 11\r\n\r\nset foo 1\r\n",
        )
    };
    send(&mut e, &p101, &msg(&p101, "101", "rl1", ""));
    assert!(recv(&victim).is_none(), "relayed for a registered source");
    assert_eq!(status(&recv(&p101)), 481);
    // a valid token for the 101 <-> 102 dialog only reaches those two
    let route = format!("Route: {}\r\n", establish(&mut e, "rl"));
    for (from, ext) in [(&p101, "101"), (&p102, "102")] {
        send(&mut e, from, &msg(from, ext, "rl2", &route));
        assert!(recv(&victim).is_none(), "relayed with {}'s token", ext);
        assert_eq!(status(&recv(from)), 481);
    }
    // not even once the registrations (that made the senders trusted) are gone
    e.pbx.reg.remove_all("101");
    e.pbx.reg.remove_all("102");
    send(&mut e, &p101, &msg(&p101, "101", "rl3", &route));
    assert!(recv(&victim).is_none(), "relayed on the token alone");
    assert_eq!(status(&recv(&p101)), 481);
    // ...while the dialog itself still works on the token
    let c102 = format!("sip:102@127.0.0.1:{}", addr(&p102).port());
    let bye = with_to_tag(
        &request("BYE", &c102, "101", &p101, "rl4", "rl", &route),
        &c102,
        "callee",
    );
    send(&mut e, &p101, &bye);
    assert_eq!(recv(&p102).expect("BYE to the dialog peer").method(), "BYE");
}

/// Registered phones are valid in-dialog destinations, by their source
/// address even when the Request-URI doesn't match their Contact.
#[test]
fn in_dialog_request_may_reach_a_registered_source_address() {
    let mut e = env();
    let p101 = e.p101.try_clone().unwrap();
    let p103 = sock();
    let a = addr(&p103);
    e.pbx
        .reg
        .update("103", "sip:103@192.0.2.1:5060", "", a, 3600, "c103", 1, "ua");
    let ruri = format!("sip:x@{}", a);
    let m = with_to_tag(
        &request("MESSAGE", &ruri, "101", &p101, "rs", "rs", ""),
        &ruri,
        "1",
    );
    send(&mut e, &p101, &m);
    assert_eq!(recv(&p103).expect("to 103's source address").method(), "MESSAGE");
}
