//! Routing regressions from the reliability review.
use super::*;

fn add_second_account(e: &mut Env) {
    let a = addr(&e.p101);
    e.pbx
        .reg
        .update("103", &format!("sip:103@{}", a), "", a, 3600, "line3", 1, "ua");
}

#[test]
fn distinct_accounts_on_one_socket_can_call() {
    let mut e = env();
    add_second_account(&mut e);
    let phone = e.p101.try_clone().unwrap();
    send(
        &mut e,
        &phone,
        &request("INVITE", "sip:101@pbx", "103", &phone, "lines", "lines", ""),
    );
    let inv = recv(&phone).expect("the other account on this socket must ring");
    assert_eq!(inv.method(), "INVITE");
    assert_eq!(inv.uri(), format!("sip:101@{}", addr(&phone)));
}

#[test]
fn local_numbers_take_precedence_over_a_misconfigured_contact() {
    for host in ["127.0.0.1", "192.0.2.1", "pbx.test"] {
        let mut e = env();
        e.pbx.cfg.advertise = Some("192.0.2.1".parse().unwrap());
        e.pbx
            .cfg
            .groups
            .insert("200".into(), vec!["101".into(), "102".into()]);
        let authority = format!("{host}:{}", e.port);
        // 103 mistakenly advertises the server address, not its own.
        let caller = e.victim.try_clone().unwrap();
        e.pbx.reg.update(
            "103",
            &format!("sip:103@{authority}"),
            "",
            addr(&caller),
            3600,
            "103",
            1,
            "ua",
        );

        for number in ["102", "200"] {
            let uri = format!("sip:{number}@{authority}");
            send(
                &mut e,
                &caller,
                &request("INVITE", &uri, "103", &caller, number, number, ""),
            );
            let inv = recv(&e.p102).expect("102 must ring");
            assert_eq!(inv.uri(), format!("sip:102@{}", addr(&e.p102)));
            if number == "200" {
                assert_eq!(recv(&e.p101).expect("101 must also ring").method(), "INVITE");
                assert_eq!(status(&recv(&caller)), 100);
            }
        }
        assert!(recv(&caller).is_none(), "no INVITE to the misconfigured Contact");
    }
}

fn top_branch(m: &Message) -> String {
    m.top_via().unwrap().branch().unwrap().to_string()
}

/// Everything that arrives at `s` until it goes quiet.
fn drain(s: &UdpSocket) -> Vec<Message> {
    std::iter::from_fn(|| recv(s)).collect()
}

// Owner's decision (audit: DECT base handsets didn't all ring): a device
// with several accounts -- a DECT base registering every handset's
// extension from its one address, or a desk phone with two lines -- rings
// on each of its extensions in a group, and only the calling extension is
// left out on the calling device. (This replaces the earlier rule of
// ringing a device once and skipping every account of the calling device.)

#[test]
fn group_skips_only_the_calling_extension_on_a_shared_device() {
    let mut e = env();
    add_second_account(&mut e);
    e.pbx
        .cfg
        .groups
        .insert("100".into(), vec!["101".into(), "102".into(), "103".into()]);
    let phone = e.p101.try_clone().unwrap();
    send(
        &mut e,
        &phone,
        &request("INVITE", "sip:100@pbx", "101", &phone, "lines", "lines", ""),
    );
    assert_eq!(recv(&e.p102).unwrap().method(), "INVITE");
    let invites: Vec<String> = drain(&phone)
        .iter()
        .filter(|m| m.is_request())
        .map(|m| m.uri().to_string())
        .collect();
    assert_eq!(
        invites,
        [format!("sip:103@{}", addr(&phone))],
        "the device's other extension rings, the calling one doesn't"
    );
    // a caller that is no extension: nothing at its address rings
    send(
        &mut e,
        &phone,
        &request("INVITE", "sip:100@pbx", "anonymous", &phone, "anon", "anon", ""),
    );
    assert_eq!(recv(&e.p102).unwrap().method(), "INVITE");
    assert!(drain(&phone).is_empty());
}

#[test]
fn group_rings_every_account_on_a_shared_device() {
    let mut e = env();
    add_second_account(&mut e);
    e.pbx
        .cfg
        .groups
        .insert("100".into(), vec!["101".into(), "103".into()]);
    let caller = e.p102.try_clone().unwrap();
    send(
        &mut e,
        &caller,
        &request(
            "INVITE",
            "sip:100@pbx",
            "102",
            &caller,
            "group-lines",
            "group-lines",
            "",
        ),
    );
    let mut uris: Vec<String> = drain(&e.p101).iter().map(|m| m.uri().to_string()).collect();
    uris.sort();
    let a = addr(&e.p101);
    assert_eq!(uris, [format!("sip:101@{}", a), format!("sip:103@{}", a)]);
}

/// Audit repro: a DECT base (Gigaset, Yealink W-series) registers every
/// handset's extension from its single IP:port. Only one handset of group
/// 100 = 102 103 rang, and a handset calling `*` got 480 because every
/// other handset was skipped as "the caller". Each handset's fork branch is
/// its own: answering on one cancels the other at the same address.
/// Group 100 = 102 103 with both registered from one DECT base, called by
/// 101: the base and the INVITEs for its handsets 102 and 103.
fn dect_call(g: &mut Group, call: &str) -> (UdpSocket, Message, Message) {
    let caller = g.caller.try_clone().unwrap();
    let base = sock();
    let ad = addr(&base);
    g.pbx.reg.remove_all("102");
    g.pbx.reg.remove_all("103");
    for (ext, hs) in [("102", "hs1"), ("103", "hs2")] {
        g.pbx
            .reg
            .update(ext, &format!("sip:{}@{}", hs, ad), "", ad, 3600, ext, 1, "dect");
    }
    let inv = request("INVITE", "sip:100@pbx", "101", &caller, call, call, "");
    gsend(g, &caller, &inv);
    assert_eq!(status(&recv(&caller)), 100);
    let mut invites = drain(&base);
    invites.sort_by_key(|m| m.uri().to_string());
    let [h1, h2] = &invites[..] else {
        panic!("both handsets must ring, got {} INVITEs", invites.len());
    };
    assert_eq!(h1.uri(), format!("sip:hs1@{}", ad));
    assert_eq!(h2.uri(), format!("sip:hs2@{}", ad));
    (base, h1.clone(), h2.clone())
}

#[test]
fn dect_base_handsets_share_one_socket() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (base, h1, h2) = dect_call(&mut g, "dect1");
    let (h1, h2) = (&h1, &h2);
    let (b1, b2) = (top_branch(h1), top_branch(h2));
    assert_ne!(b1, b2);
    gresp(&mut g, &base, h1, 180, "t1");
    gresp(&mut g, &base, h2, 180, "t2");
    assert_eq!(status(&recv(&caller)), 180);
    assert_eq!(status(&recv(&caller)), 180);
    // handset 2 answers: handset 1, at the same address, is cancelled
    gresp(&mut g, &base, h2, 200, "t2");
    assert_eq!(status(&recv(&caller)), 200);
    let c = recv(&base).expect("CANCEL for handset 1");
    assert_eq!((c.method(), c.uri()), ("CANCEL", h1.uri()));
    assert_eq!(top_branch(&c), b1);
    assert!(recv(&base).is_none(), "nothing for the handset that answered");
    gresp(&mut g, &base, &c, 200, "t1");
    gresp(&mut g, &base, h1, 487, "t1");
    let ack = recv(&base).expect("ACK for handset 1's 487");
    assert_eq!(ack.method(), "ACK");
    assert_eq!(top_branch(&ack), b1);
    assert_eq!(ack.to_tag().as_deref(), Some("t1"));
    // the answer's retransmission still reaches the caller, and only it
    gresp(&mut g, &base, h2, 200, "t2");
    assert_eq!(status(&recv(&caller)), 200);
    assert!(recv(&base).is_none());
    // Once the fork is gone, neither handset's response is recovered.
    g.pbx.tick(later(40.0));
    assert_eq!(g.pbx.next_deadline(later(40.0)), None);
    gresp(&mut g, &base, h1, 180, "t1");
    gresp(&mut g, &base, h2, 200, "t2");
    assert!(recv(&base).is_none(), "no stateless cleanup after linger");
    assert!(recv(&caller).is_none());

    // handset 1 calls `*` while 101 is away: handset 2 on the same base
    // rings (it got 480 before), handset 1 doesn't
    g.pbx.reg.remove_all("101");
    let inv = request("INVITE", "sip:200@pbx", "102", &base, "dect2", "dect2", "");
    gsend(&mut g, &base, &inv);
    let got = drain(&base);
    assert_eq!(got.len(), 1, "one INVITE, no 480");
    assert_eq!((got[0].method(), got[0].uri()), ("INVITE", h2.uri()));
}

/// A device with several accounts on one SIP stack takes the first INVITE
/// and refuses the others as merged requests (482 Loop Detected, RFC 3261
/// 8.2.2.2: same Call-ID, From tag and CSeq; pjsua does so). That says
/// nothing about the callee, so it is never the caller's answer.
#[test]
fn merged_request_482_from_a_shared_device_is_not_the_answer() {
    let mut g = group_env();
    let caller = g.caller.try_clone().unwrap();
    let (base, h1, h2) = dect_call(&mut g, "merged");
    gresp(&mut g, &base, &h2, 482, "t2");
    assert_eq!(recv(&base).expect("ACK for the 482").method(), "ACK");
    gresp(&mut g, &base, &h1, 180, "t1");
    assert_eq!(status(&recv(&caller)), 180);
    // nobody picks up
    g.pbx.tick(later(181.0));
    let c = recv(&base).expect("CANCEL after ringing too long");
    assert_eq!(c.method(), "CANCEL");
    gresp(&mut g, &base, &c, 200, "t1");
    gresp(&mut g, &base, &h1, 487, "t1");
    let codes: Vec<u16> = drain(&caller).iter().map(|m| m.code()).collect();
    assert_eq!(codes, [480], "no answer, not \"Loop Detected\"");
}

#[test]
fn transaction_survives_binding_removal_and_replacement() {
    check_cached_transaction(false); // next hop from the Request-URI
    check_cached_transaction(true); // next hop from a preloaded Route
}

fn check_cached_transaction(preloaded: bool) {
    let mut e = env();
    let (a, b) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let uri = format!("sip:opaque@{};line=one", addr(&b));
    e.pbx
        .reg
        .update("102", &uri, "", addr(&b), 3600, "new-contact", 1, "ua");
    let (ruri, routes) = if preloaded {
        ("sip:102@pbx", format!("Route: <{};lr>\r\n", uri))
    } else {
        (uri.as_str(), String::new())
    };
    let original = request("INVITE", ruri, "101", &a, "contact", "contact", &routes);
    send(&mut e, &a, &original);
    let inv = recv(&b).unwrap();
    let branch = inv.top_via().unwrap().branch().unwrap().to_string();
    e.pbx.reg.remove_all("102");
    let replacement = sock();
    e.pbx.reg.update(
        "102",
        &format!("sip:102@{}", addr(&replacement)),
        "",
        addr(&replacement),
        3600,
        "replacement",
        1,
        "ua",
    );
    // Retransmission must not be treated as a fresh unknown-Contact call.
    send(&mut e, &a, &original);
    assert_eq!(
        recv(&b)
            .expect("INVITE retry must reach the original phone")
            .uri(),
        ruri
    );
    assert!(recv(&replacement).is_none());
    let cancel = original.replace("INVITE", "CANCEL");
    send(&mut e, &a, &cancel);
    let cancel = recv(&b).expect("CANCEL must follow the original INVITE");
    assert_eq!(cancel.method(), "CANCEL");
    assert_eq!(cancel.uri(), ruri);
    assert_eq!(cancel.hdr("Route"), inv.hdr("Route"));
    assert_eq!(cancel.top_via().unwrap().branch(), Some(branch.as_str()));
    respond(&mut e, &b, &inv, 487, "callee", false);
    assert_eq!(recv(&a).unwrap().code(), 487);
    let mut ack = Message::parse(original.replace("INVITE", "ACK").as_bytes()).unwrap();
    ack.set("To", format!("<{}>;tag=callee", ruri));
    e.pbx.handle(&ack.to_bytes(), addr(&a));
    let ack = recv(&b).expect("negative ACK must also use the saved destination");
    assert_eq!(ack.method(), "ACK");
    assert_eq!(ack.uri(), ruri);
    assert_eq!(ack.top_via().unwrap().branch(), Some(branch.as_str()));
    assert!(recv(&replacement).is_none());
}

#[test]
fn cached_transaction_requires_the_same_route_set() {
    let mut e = env();
    let (a, b) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let original = request("INVITE", "sip:102@pbx", "101", &a, "routes", "routes", "");
    send(&mut e, &a, &original);
    assert_eq!(recv(&b).expect("102 must ring").method(), "INVITE");
    // Same branch and Call-ID, but with a Route the INVITE did not have:
    // not the remembered request, so a foreign Route is refused as usual.
    let foreign = format!("Route: <sip:127.0.0.1:{};lr>\r\n", addr(&e.victim).port());
    let changed = request("INVITE", "sip:102@pbx", "101", &a, "routes", "routes", &foreign);
    for msg in [changed.replace("INVITE", "CANCEL"), changed] {
        send(&mut e, &a, &msg);
        assert_eq!(status(&recv(&a)), 403);
        assert!(recv(&b).is_none(), "relayed with a foreign Route");
        assert!(recv(&e.victim).is_none());
    }
    // Unchanged, the CANCEL still follows the INVITE.
    send(&mut e, &a, &original.replace("INVITE", "CANCEL"));
    let cancel = recv(&b).expect("CANCEL must follow the INVITE");
    assert_eq!(cancel.method(), "CANCEL");
}

fn establish(e: &mut Env) -> String {
    let (a, b) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    send(
        e,
        &a,
        &request("INVITE", "sip:102@pbx", "101", &a, "dialog", "dialog", ""),
    );
    let inv = recv(&b).unwrap();
    let rr = inv.hdr("Record-Route").unwrap().to_string();
    respond(e, &b, &inv, 200, "callee", true);
    assert_eq!(recv(&a).unwrap().code(), 200);
    rr
}

fn bye(from: &UdpSocket, to: &UdpSocket, route: &str, call: &str) -> String {
    let uri = format!("sip:peer@{}", addr(to));
    request(
        "BYE",
        &uri,
        "101",
        from,
        "bye",
        call,
        &format!("Route: {}\r\n", route),
    )
    .replace(&format!("To: <{}>", uri), &format!("To: <{}>;tag=callee", uri))
}

fn check_bye(e: &mut Env, route: &str) {
    let (a, b) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    for (from, to) in [(&a, &b), (&b, &a)] {
        send(e, from, &bye(from, to, route, "dialog"));
        let forwarded = recv(to).expect("BYE must not depend on a live registration");
        assert_eq!(forwarded.method(), "BYE");
        assert!(forwarded.hdr("Route").is_none());
        e.pbx
            .handle(&forwarded.make_response(200, "OK", None).to_bytes(), addr(to));
        assert_eq!(recv(from).unwrap().code(), 200);
    }
    assert_eq!(e.pbx.next_deadline(Instant::now()), None);
}

#[test]
fn dialog_routes_survive_both_registrations_disappearing() {
    let mut e = env();
    let route = establish(&mut e);
    e.pbx.reg.remove_all("101");
    e.pbx.reg.remove_all("102");
    check_bye(&mut e, &route);
    // A To-tag or a copied token does not by itself authorize another source
    // or call. Do these checks after removal, without live-binding fallbacks.
    let (a, b, other) = (
        e.p101.try_clone().unwrap(),
        e.p102.try_clone().unwrap(),
        e.attacker.try_clone().unwrap(),
    );
    send(&mut e, &other, &bye(&other, &b, &route, "dialog"));
    assert_eq!(recv(&other).unwrap().code(), 481);
    send(&mut e, &a, &bye(&a, &b, &route, "different-call"));
    assert_eq!(recv(&a).unwrap().code(), 481);
    let plain = format!("<sip:127.0.0.1:{};lr>", e.port);
    send(&mut e, &a, &bye(&a, &b, &plain, "dialog"));
    assert_eq!(recv(&a).unwrap().code(), 481);
    assert!(recv(&b).is_none());
}

#[test]
fn dialog_routes_survive_registration_expiry() {
    let mut e = env();
    for (ext, p) in [("101", &e.p101), ("102", &e.p102)] {
        e.pbx.reg.update(
            ext,
            &format!("sip:{}@{}", ext, addr(p)),
            "",
            addr(p),
            1,
            "short",
            1,
            "ua",
        );
    }
    let route = establish(&mut e);
    std::thread::sleep(Duration::from_millis(1100));
    assert!(e.pbx.reg.get("101").is_empty());
    assert!(e.pbx.reg.get("102").is_empty());
    check_bye(&mut e, &route);
}

fn persistent_env() -> (Env, TestDir) {
    let mut e = env();
    let dir = TestDir::create();
    let bindings = e.pbx.reg.all();
    e.pbx.cfg.state_file = Some(dir.join("bindings.txt"));
    restart(&mut e);
    for (ext, b) in bindings {
        e.pbx.reg.update(
            &ext,
            &b.contact,
            &b.params,
            b.source,
            3600,
            &b.call_id,
            b.cseq,
            &b.user_agent,
        );
    }
    (e, dir)
}

fn restart(e: &mut Env) {
    e.pbx.reg.save();
    let cfg = e.pbx.cfg.clone();
    let placeholder = Pbx::new(Config::parse("[extensions]\n1=pw").unwrap(), sock());
    drop(std::mem::replace(&mut e.pbx, placeholder));
    e.pbx = Pbx::new(cfg, UdpSocket::bind(("127.0.0.1", e.port)).unwrap());
}

#[test]
fn ringing_response_and_cancel_keep_their_branches_across_restart() {
    let (mut e, _dir) = persistent_env();
    let (a, b) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    for final_code in [200, 486] {
        let call = format!("restart-{}", final_code);
        let original = request("INVITE", "sip:102@pbx", "101", &a, &call, &call, "");
        send(&mut e, &a, &original);
        let inv = recv(&b).unwrap();
        respond(&mut e, &b, &inv, 180, "callee", false);
        assert_eq!(recv(&a).unwrap().code(), 180);
        restart(&mut e);
        if final_code == 486 {
            send(&mut e, &a, &original.replace("INVITE", "CANCEL"));
            let cancel = recv(&b).unwrap();
            assert_eq!(cancel.method(), "CANCEL");
            assert_eq!(
                cancel.top_via().unwrap().branch(),
                inv.top_via().unwrap().branch()
            );
        }
        respond(&mut e, &b, &inv, final_code, "callee", true);
        assert_eq!(
            recv(&a)
                .expect("old transaction response must survive restart")
                .code(),
            final_code
        );
        if final_code == 486 {
            let ack = original
                .replace("INVITE", "ACK")
                .replace("To: <sip:102@pbx>", "To: <sip:102@pbx>;tag=callee");
            send(&mut e, &a, &ack);
            assert_eq!(
                recv(&b).unwrap().top_via().unwrap().branch(),
                inv.top_via().unwrap().branch()
            );
        }
    }
}

#[test]
fn dialog_route_survives_restart_without_either_registration() {
    let (mut e, _dir) = persistent_env();
    let route = establish(&mut e);
    e.pbx.reg.remove_all("101");
    e.pbx.reg.remove_all("102");
    restart(&mut e);
    check_bye(&mut e, &route);
}
