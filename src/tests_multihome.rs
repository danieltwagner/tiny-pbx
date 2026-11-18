//! Hosts with several addresses (audit): each phone hears from the PBX
//! address it uses -- replies from where the request arrived, requests from
//! where the phone registered to -- and Via / Record-Route name that
//! address. Real sockets and the real receive path (`Pbx::turn`): the PBX
//! listens on the wildcard address and tells 127.0.0.2 from 127.0.0.3
//! (all of 127/8 is local on Linux); the phones are on 127.0.0.1.
use super::*;
use std::net::IpAddr;

/// Our addresses the phones use.
const A: &str = "127.0.0.2";
const B: &str = "127.0.0.3";
const C: &str = "127.0.0.4";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

struct Live {
    pbx: Pbx,
    port: u16,
    buf: Vec<u8>,
}

/// A PBX on the wildcard address `bind` (None if there is no such
/// address family here).
fn live(bind: &str, state: Option<std::path::PathBuf>) -> Option<Live> {
    let s = UdpSocket::bind(bind).ok()?;
    // never block a test, whatever goes wrong
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let port = s.local_addr().unwrap().port();
    let mut cfg =
        Config::parse("[extensions]\n101 = pw101\n102 = pw102\n103 = pw103\n[groups]\n100 = 102 103\n")
            .unwrap();
    cfg.listen = s.local_addr().unwrap();
    cfg.state_file = state;
    set_log_level(ERROR);
    let pbx = Pbx::new(cfg, s);
    Some(Live {
        pbx,
        port,
        buf: vec![0; 65536],
    })
}

impl Live {
    /// `from` sends `msg` to our address `to`; the PBX handles it.
    fn send(&mut self, from: &UdpSocket, to: &str, msg: &[u8]) {
        from.send_to(msg, (to, self.port)).unwrap();
        self.pbx.turn(&mut self.buf);
    }

    /// The next message `phone` gets, and which of our addresses it came from.
    fn next(&self, phone: &UdpSocket, what: &str) -> (Message, IpAddr) {
        let mut buf = [0u8; 65536];
        let (n, from) = phone
            .recv_from(&mut buf)
            .unwrap_or_else(|e| panic!("{}: nothing ({})", what, e));
        assert_eq!(from.port(), self.port, "{}", what);
        (Message::parse(&buf[..n]).unwrap(), from.ip())
    }

    /// The next message `phone` gets, which must come from our address `at`.
    fn expect(&self, phone: &UdpSocket, at: &str, what: &str) -> Message {
        let (m, from) = self.next(phone, what);
        assert_eq!(from, ip(at), "{} came from the wrong address", what);
        m
    }

    /// `phone` registers `ext` with our address `server` (digest auth).
    fn register(&mut self, phone: &UdpSocket, ext: &str, server: &str) {
        let contact = format!("Contact: <sip:{ext}@{}>\r\n", addr(phone));
        self.register_contacts(phone, ext, server, 1, &contact);
    }

    /// An authenticated REGISTER with the given Contact header lines (empty: query).
    fn register_contacts(
        &mut self,
        phone: &UdpSocket,
        ext: &str,
        server: &str,
        seq: u32,
        contacts: &str,
    ) -> Message {
        let (p, port) = (addr(phone).port(), self.port);
        let uri = format!("sip:{}:{}", server, port);
        let reg = |cseq: u32, auth: &str| {
            format!(
                "REGISTER {uri} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{p};branch=z9hG4bKr{ext}{cseq};rport\r\n\
                 Max-Forwards: 70\r\nFrom: <sip:{ext}@pbx>;tag=r{ext}\r\nTo: <sip:{ext}@pbx>\r\n\
                 Call-ID: reg-{ext}-{p}\r\nCSeq: {cseq} REGISTER\r\n{contacts}\
                 Expires: 3600\r\n{auth}Content-Length: 0\r\n\r\n"
            )
        };
        self.send(phone, server, reg(seq, "").as_bytes());
        let r = self.expect(phone, server, "401");
        assert_eq!(r.code(), 401);
        let nonce = get_nonce(&r, "WWW-Authenticate");
        let pw = format!("pw{}", ext);
        let auth = auth_hdr("Authorization", ext, &pw, "REGISTER", &uri, &nonce);
        self.send(phone, server, reg(seq + 1, &auth).as_bytes());
        let ok = self.expect(phone, server, "REGISTER's 200");
        assert_eq!(ok.code(), 200);
        ok
    }

    /// `phone` answers `req` (copying its Record-Route), sending to our
    /// address `to`.
    fn answer(&mut self, phone: &UdpSocket, to: &str, req: &Message, code: u16, tag: &str) {
        let mut r = req.make_response(code, "X", Some(tag));
        for rr in req.hdrs("Record-Route") {
            r.headers.push(Header {
                name: "Record-Route".into(),
                value: rr.to_string(),
            });
        }
        if req.method() == "INVITE" {
            r.headers.push(Header {
                name: "Contact".into(),
                value: format!("<sip:x@{}>", addr(phone)),
            });
        }
        self.send(phone, to, &r.to_bytes());
    }
}

fn top_via(m: &Message) -> crate::sip::Via {
    m.top_via().unwrap()
}

fn in_dialog(m: String, ruri: &str, tag: &str) -> String {
    m.replace(&format!("To: <{}>", ruri), &format!("To: <{}>;tag={}", ruri, tag))
}

fn non_loopback_v4() -> Option<IpAddr> {
    interface_ips()
        .into_iter()
        .find(|ip| ip.is_ipv4() && !ip.is_loopback())
}

/// Audit repro: a reply left from whatever address routing preferred,
/// not from the one the phone had sent its request to.
#[test]
fn replies_come_from_the_address_the_request_went_to() {
    let eth = non_loopback_v4().map(|ip| ip.to_string());
    for bind in ["0.0.0.0:0", "[::]:0"] {
        let Some(mut l) = live(bind, None) else {
            continue; // no IPv6 here
        };
        let phone = sock();
        let p = addr(&phone).port();
        for server in [A, B].into_iter().chain(eth.as_deref()) {
            let opt = format!(
                "OPTIONS sip:{server}:{port} SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{p};branch=z9hG4bKo{server};rport\r\n\
                 Max-Forwards: 70\r\nFrom: <sip:101@{server}>;tag=o\r\nTo: <sip:{server}:{port}>\r\n\
                 Call-ID: opt-{server}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
                port = l.port
            );
            l.send(&phone, server, opt.as_bytes());
            let r = l.expect(&phone, server, &format!("{}: OPTIONS reply", bind));
            assert_eq!(r.code(), 200);
        }
        // a stranger's call is challenged from where it called
        let inv = request("INVITE", &format!("sip:102@{}", B), "101", &phone, "st", "st", "");
        l.send(&phone, B, inv.as_bytes());
        assert_eq!(l.expect(&phone, B, "407").code(), 407);
    }
}

#[test]
fn register_query_on_another_address_keeps_the_original_route() {
    let mut l = live("0.0.0.0:0", None).unwrap();
    let (phone, caller) = (sock(), sock());
    l.register(&phone, "101", A);
    let before = l.pbx.reg.lookup("101").unwrap();
    let ok = l.register_contacts(&phone, "101", B, 3, "");
    assert!(ok.hdr("Contact").unwrap().contains(&before.contact));
    assert_eq!(l.pbx.reg.lookup("101").unwrap(), before);

    l.register(&caller, "102", B);
    let inv = request("INVITE", "sip:101@pbx", "102", &caller, "query", "query", "");
    l.send(&caller, B, inv.as_bytes());
    assert_eq!(l.expect(&phone, A, "INVITE after query").method(), "INVITE");
}

#[test]
fn removing_a_contact_on_another_address_leaves_survivors_alone() {
    let mut l = live("0.0.0.0:0", None).unwrap();
    let phone = sock();
    let keep = format!("sip:keep@{}", addr(&phone));
    let remove = format!("sip:remove@{}", addr(&phone));
    let contacts = format!("Contact: <{keep}>, <{remove}>\r\n");
    l.register_contacts(&phone, "101", A, 1, &contacts);
    let before = l.pbx.reg.get("101");
    assert_eq!(before.len(), 2);
    l.register_contacts(&phone, "101", B, 3, "Contact: <sip:absent@pbx>;expires=0\r\n");
    assert_eq!(l.pbx.reg.get("101"), before, "unmatched removal");
    let survivor = before.into_iter().find(|b| b.contact == keep).unwrap();
    l.register_contacts(&phone, "101", B, 5, &format!("Contact: <{remove}>;expires=0\r\n"));
    assert_eq!(l.pbx.reg.get("101"), [survivor]);
}

/// 101 registered to A and 102 to B: each only ever hears from its own
/// address, in both directions and through a whole dialog, also once both
/// registrations are gone (the dialog's Record-Route says where).
#[test]
fn phones_registered_to_different_addresses_hear_only_from_those() {
    for bind in ["0.0.0.0:0", "[::]:0"] {
        let Some(mut l) = live(bind, None) else {
            continue;
        };
        let (pa, pb) = (sock(), sock());
        l.register(&pa, "101", A);
        l.register(&pb, "102", B);
        assert_eq!(l.pbx.reg.lookup("101").unwrap().local, Some(ip(A)));
        assert_eq!(l.pbx.reg.lookup("102").unwrap().local, Some(ip(B)));
        let port = l.port;
        let inv = request("INVITE", &format!("sip:102@{}", A), "101", &pa, "mh", "mh", "");
        l.send(&pa, A, inv.as_bytes());
        let fi = l.expect(&pb, B, "INVITE to 102");
        let via = top_via(&fi);
        assert_eq!((via.host.as_str(), via.port), (B, Some(port)));
        assert_eq!(via.param("pbx-in"), Some(Some(A)), "where the INVITE came in");
        let rr: Vec<String> = fi.hdrs("Record-Route").map(str::to_string).collect();
        assert_eq!(rr.len(), 2, "{:?}", rr);
        assert!(
            rr[0].starts_with(&format!("<sip:{}:{};lr;", B, port)),
            "{}",
            rr[0]
        );
        assert!(
            rr[1].starts_with(&format!("<sip:{}:{};lr;", A, port)),
            "{}",
            rr[1]
        );
        l.answer(&pb, B, &fi, 180, "callee");
        assert_eq!(l.expect(&pa, A, "180 to 101").code(), 180);
        l.answer(&pb, B, &fi, 200, "callee");
        assert_eq!(l.expect(&pa, A, "200 to 101").code(), 200);
        // 101's ACK, and 102's BYE and its 200, through the Record-Route
        let c102 = format!("sip:x@{}", addr(&pb));
        let c101 = format!("sip:101@{}", addr(&pa));
        let to_b = format!("Route: {}, {}\r\n", rr[1], rr[0]);
        let to_a = format!("Route: {}, {}\r\n", rr[0], rr[1]);
        let ack = in_dialog(
            request("ACK", &c102, "101", &pa, "mhack", "mh", &to_b),
            &c102,
            "callee",
        );
        l.send(&pa, A, ack.as_bytes());
        let fa = l.expect(&pb, B, "ACK to 102");
        assert_eq!((fa.method(), top_via(&fa).host.as_str()), ("ACK", B));
        let bye = in_dialog(
            request("BYE", &c101, "102", &pb, "mhbye", "mh", &to_a),
            &c101,
            "f101",
        );
        l.send(&pb, B, bye.as_bytes());
        let fb = l.expect(&pa, A, "BYE to 101");
        assert_eq!((fb.method(), top_via(&fb).host.as_str()), ("BYE", A));
        assert_eq!(top_via(&fb).param("pbx-in"), Some(Some(B)));
        l.answer(&pa, A, &fb, 200, "f101");
        assert_eq!(l.expect(&pb, B, "BYE's 200 to 102").code(), 200);
        // the same once both registrations are gone: by the Route alone
        l.pbx.reg.remove_all("101");
        l.pbx.reg.remove_all("102");
        let bye = in_dialog(
            request("BYE", &c102, "101", &pa, "mhbye2", "mh", &to_b),
            &c102,
            "callee",
        );
        l.send(&pa, A, bye.as_bytes());
        let fb = l.expect(&pb, B, "BYE to 102 without registrations");
        assert_eq!((fb.method(), top_via(&fb).host.as_str()), ("BYE", B));
        l.answer(&pb, B, &fb, 200, "callee");
        assert_eq!(l.expect(&pa, A, "its 200 to 101").code(), 200);
        assert!(recv(&pa).is_none() && recv(&pb).is_none());
    }
}

/// A group call: the caller hears everything from where it called, each
/// phone from where it registered to -- INVITE, its retransmission, the
/// CANCEL once another phone answered, the ACK for its 487.
#[test]
fn group_call_reaches_each_phone_from_its_address() {
    let Some(mut l) = live("0.0.0.0:0", None) else {
        return;
    };
    let (pa, pb, pc) = (sock(), sock(), sock());
    l.register(&pa, "101", A);
    l.register(&pb, "102", B);
    l.register(&pc, "103", C);
    let inv = request("INVITE", &format!("sip:100@{}", A), "101", &pa, "mhg", "mhg", "");
    l.send(&pa, A, inv.as_bytes());
    assert_eq!(l.expect(&pa, A, "100 Trying").code(), 100);
    let ib = l.expect(&pb, B, "INVITE to 102");
    let ic = l.expect(&pc, C, "INVITE to 103");
    assert_eq!(top_via(&ib).host, B);
    assert_eq!(top_via(&ic).host, C);
    l.pbx.tick(later(0.6));
    assert_eq!(l.expect(&pb, B, "retransmission to 102").method(), "INVITE");
    assert_eq!(l.expect(&pc, C, "retransmission to 103").method(), "INVITE");
    l.answer(&pb, B, &ib, 180, "tb");
    assert_eq!(l.expect(&pa, A, "180").code(), 180);
    l.answer(&pc, C, &ic, 200, "tc");
    assert_eq!(l.expect(&pa, A, "200").code(), 200);
    let cancel = l.expect(&pb, B, "CANCEL to 102");
    assert_eq!(cancel.method(), "CANCEL");
    l.answer(&pb, B, &cancel, 200, "tb");
    l.answer(&pb, B, &ib, 487, "tb");
    assert_eq!(l.expect(&pb, B, "ACK for 102's 487").method(), "ACK");
    assert!(recv(&pa).is_none() && recv(&pb).is_none() && recv(&pc).is_none());
}

/// The address a phone registered to is remembered across a restart; one
/// that is no longer ours isn't used (the kernel chooses, as before).
#[test]
fn registered_address_survives_restart_and_a_gone_one_is_not_used() {
    let dir = TestDir::create();
    let state = Some(dir.join("bindings.txt"));
    let Some(mut l) = live("0.0.0.0:0", state.clone()) else {
        return;
    };
    let (pa, pb) = (sock(), sock());
    l.register(&pa, "101", A);
    l.register(&pb, "102", B);
    let port = l.port;
    drop(l);
    let s = UdpSocket::bind(("0.0.0.0", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut cfg = Config::parse("[extensions]\n101 = pw101\n102 = pw102\n").unwrap();
    cfg.listen = s.local_addr().unwrap();
    cfg.state_file = state;
    let mut l = Live {
        pbx: Pbx::new(cfg, s),
        port,
        buf: vec![0; 65536],
    };
    let inv = request("MESSAGE", &format!("sip:102@{}", A), "101", &pa, "mhr", "mhr", "");
    l.send(&pa, A, inv.as_bytes());
    assert_eq!(l.expect(&pb, B, "MESSAGE after the restart").method(), "MESSAGE");
    // 102's address went away (TEST-NET: never ours)
    let b = l.pbx.reg.lookup("102").unwrap();
    l.pbx
        .reg
        .update_many(
            "102",
            &[(b.contact, b.params, 3600)],
            (b.source, Some(ip("192.0.2.1"))),
            &b.call_id,
            b.cseq + 1,
            &b.user_agent,
        )
        .unwrap();
    l.send(&pa, A, inv.replace("mhr", "mhr2").as_bytes());
    let (m, from) = l.next(&pb, "MESSAGE from wherever");
    assert_eq!(m.method(), "MESSAGE");
    assert_ne!(from, ip("192.0.2.1"));
    assert_ne!(top_via(&m).host, "192.0.2.1");
}
