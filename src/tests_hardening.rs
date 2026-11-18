//! Hardening against devices on the LAN that can't be trusted (second
//! security review): password guessing, replayed credentials, one phone
//! taking over another's calls, oversized registrations, log abuse.
use super::*;

/// A REGISTER for `ext` from `s` (Contact: its own address), with `auth`
/// (a complete header line or "").
fn reg_msg(s: &UdpSocket, ext: &str, call: &str, cseq: u32, auth: &str) -> String {
    let p = addr(s).port();
    format!(
        "REGISTER sip:127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:{p};branch=z9hG4bKh{call}{cseq};rport\r\n\
         From: <sip:{ext}@pbx>;tag=h\r\nTo: <sip:{ext}@pbx>\r\nCall-ID: {call}\r\nCSeq: {cseq} REGISTER\r\n\
         Contact: <sip:{ext}@127.0.0.1:{p}>\r\n{auth}Content-Length: 0\r\n\r\n"
    )
}

/// The nonce of a fresh 401 challenge for `s`.
fn reg_nonce(e: &mut Env, s: &UdpSocket, ext: &str, call: &str) -> String {
    send(e, s, &reg_msg(s, ext, call, 1, ""));
    let r = recv(s).unwrap();
    assert_eq!(r.code(), 401);
    get_nonce(&r, "WWW-Authenticate")
}

// ------------------------------------------------------------ password guessing

/// Whether a password is right can't be learnt without a round trip: a
/// made-up (or old) nonce gets a fresh challenge, right password or not.
#[test]
fn made_up_nonce_is_no_password_oracle() {
    let mut e = env();
    let att = e.attacker.try_clone().unwrap();
    let bogus = "0000000000ffffffffffffffffffff00";
    for (i, pw) in ["pw103", "nope"].iter().enumerate() {
        let a = auth_hdr("Authorization", "103", pw, "REGISTER", "sip:127.0.0.1", bogus);
        send(&mut e, &att, &reg_msg(&att, "103", "oracle", 2 + i as u32, &a));
        let r = recv(&att).unwrap();
        assert_eq!(r.code(), 401, "password {pw}");
        assert!(r.hdr("WWW-Authenticate").unwrap().contains("stale=true"));
    }
    assert!(e.pbx.reg.lookup("103").is_none());
    // with a nonce of ours, a wrong password is still a plain 403
    let nonce = reg_nonce(&mut e, &att, "103", "oracle");
    let a = auth_hdr(
        "Authorization",
        "103",
        "nope",
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
    );
    send(&mut e, &att, &reg_msg(&att, "103", "oracle", 9, &a));
    assert_eq!(status(&recv(&att)), 403);
}

// ------------------------------------------------------------ replayed credentials

/// A LAN host that saw a phone's REGISTER replays its Authorization from
/// the phone's address (spoofed): new Call-ID, Contact: *, Expires: 0.
#[test]
fn replayed_register_credentials_are_refused() {
    let mut e = env();
    let phone = sock();
    let nonce = reg_nonce(&mut e, &phone, "103", "phone");
    let auth = auth_hdr(
        "Authorization",
        "103",
        "pw103",
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
    );
    let msg = reg_msg(&phone, "103", "phone", 2, &auth);
    send(&mut e, &phone, &msg);
    assert_eq!(status(&recv(&phone)), 200);
    // a retransmission of that very request is fine (our 200 may be lost)
    send(&mut e, &phone, &msg);
    assert_eq!(status(&recv(&phone)), 200);
    let wipe = msg.replace("Call-ID: phone", "Call-ID: attacker").replace(
        &format!("Contact: <sip:103@127.0.0.1:{}>", addr(&phone).port()),
        "Contact: *\r\nExpires: 0",
    );
    send(&mut e, &phone, &wipe);
    let r = recv(&phone).unwrap();
    assert_eq!(r.code(), 401, "replayed response: a fresh challenge");
    assert!(r.hdr("WWW-Authenticate").unwrap().contains("stale=true"));
    assert_eq!(e.pbx.reg.get("103").len(), 1, "still registered");
    // the phone itself goes on with the next count
    let next = auth_hdr_nc(
        "Authorization",
        "103",
        "pw103",
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
        2,
    );
    send(&mut e, &phone, &reg_msg(&phone, "103", "phone", 3, &next));
    assert_eq!(status(&recv(&phone)), 200);
}

/// A phone that answers the challenge without qop (RFC 2069: old or minimal
/// devices) can register. Its answer carries no nonce count, so it is good
/// for that one request only.
#[test]
fn register_without_qop_is_accepted_once() {
    let mut e = env();
    let phone = sock();
    let nonce = reg_nonce(&mut e, &phone, "103", "old");
    let auth = |pw: &str| {
        let ha1 = md5_hex(&format!("103:pbx:{pw}"));
        let ha2 = md5_hex("REGISTER:sip:127.0.0.1");
        let resp = md5_hex(&format!("{ha1}:{nonce}:{ha2}"));
        format!(
            "Authorization: Digest username=\"103\", realm=\"pbx\", nonce=\"{nonce}\", \
             uri=\"sip:127.0.0.1\", response=\"{resp}\"\r\n"
        )
    };
    send(&mut e, &phone, &reg_msg(&phone, "103", "old", 2, &auth("nope")));
    assert_eq!(status(&recv(&phone)), 403);
    let msg = reg_msg(&phone, "103", "old", 3, &auth("pw103"));
    send(&mut e, &phone, &msg);
    assert_eq!(status(&recv(&phone)), 200);
    assert_eq!(e.pbx.reg.get("103").len(), 1);
    // a retransmission is fine (our 200 may be lost) ...
    send(&mut e, &phone, &msg);
    assert_eq!(status(&recv(&phone)), 200);
    // ... the same answer in another request (replayed, or a phone reusing
    // the nonce for its refresh) gets a fresh challenge
    send(&mut e, &phone, &reg_msg(&phone, "103", "old", 4, &auth("pw103")));
    let r = recv(&phone).unwrap();
    assert_eq!(r.code(), 401);
    assert!(r.hdr("WWW-Authenticate").unwrap().contains("stale=true"));
}

/// Proxy-Authorization computed for one request is no good for another:
/// not for another Request-URI, nor for another call to the same one.
#[test]
fn proxy_credentials_are_good_for_one_request() {
    let mut e = env();
    let (att, p101, p102) = (
        e.attacker.try_clone().unwrap(),
        e.p101.try_clone().unwrap(),
        e.p102.try_clone().unwrap(),
    );
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:102@pbx", "101", &att, "p0", "p0", ""),
    );
    let nonce = get_nonce(&recv(&att).unwrap(), "Proxy-Authenticate");
    let pa = auth_hdr(
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
        &request("INVITE", "sip:101@pbx", "101", &att, "p1", "p1", &pa),
    );
    assert_eq!(status(&recv(&att)), 403, "credentials for sip:102@pbx");
    assert!(recv(&p101).is_none());
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:102@pbx", "101", &att, "p2", "p2", &pa),
    );
    assert_eq!(recv(&p102).expect("first use").method(), "INVITE");
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:102@pbx", "101", &att, "p3", "p3", &pa),
    );
    assert_eq!(status(&recv(&att)), 407, "second use: challenged again");
    assert!(recv(&p102).is_none());
    // a MESSAGE retransmitted unchanged is forwarded again (only the phone
    // answers retransmissions of non-INVITE requests)
    let pa = auth_hdr_nc(
        "Proxy-Authorization",
        "101",
        "pw101",
        "MESSAGE",
        "sip:102@pbx",
        &nonce,
        2,
    );
    let msg = request("MESSAGE", "sip:102@pbx", "101", &att, "p4", "p4", &pa);
    for _ in 0..2 {
        send(&mut e, &att, &msg);
        assert_eq!(recv(&p102).expect("MESSAGE").method(), "MESSAGE");
    }
}

/// Bad guesses don't lock a source out: valid credentials work immediately,
/// without waiting or changing the source address or nonce.
#[test]
fn registration_works_after_repeated_bad_guesses() {
    let mut e = env();
    let phone = sock();
    let nonce = reg_nonce(&mut e, &phone, "103", "guess");
    let mut nc = 0;
    let mut attempt = |e: &mut Env, pw: &str| {
        nc += 1;
        let a = auth_hdr_nc(
            "Authorization",
            "103",
            pw,
            "REGISTER",
            "sip:127.0.0.1",
            &nonce,
            nc,
        );
        send(e, &phone, &reg_msg(&phone, "103", "guess", 1 + nc, &a));
        status(&recv(&phone))
    };
    for i in 0..20 {
        assert_eq!(attempt(&mut e, &format!("guess{i}")), 403);
    }
    assert!(e.pbx.reg.lookup("103").is_none());
    assert_eq!(attempt(&mut e, "pw103"), 200);
    assert!(e.pbx.reg.lookup("103").is_some());
    assert_eq!(attempt(&mut e, "still-wrong"), 403);
}

#[test]
fn proxy_authorization_works_after_repeated_bad_guesses() {
    let mut e = env();
    let phone = sock();
    send(
        &mut e,
        &phone,
        &request("MESSAGE", "sip:102@pbx", "103", &phone, "guess", "guess", ""),
    );
    let nonce = get_nonce(&recv(&phone).unwrap(), "Proxy-Authenticate");
    for i in 0..=20 {
        let pw = if i == 20 {
            "pw103".to_string()
        } else {
            format!("guess{i}")
        };
        let a = auth_hdr(
            "Proxy-Authorization",
            "103",
            &pw,
            "MESSAGE",
            "sip:102@pbx",
            &nonce,
        );
        let call = format!("guess{i}");
        send(
            &mut e,
            &phone,
            &request("MESSAGE", "sip:102@pbx", "103", &phone, &call, &call, &a),
        );
        if i < 20 {
            assert_eq!(status(&recv(&phone)), 403);
        }
    }
    let forwarded = recv(&e.p102).expect("correct credentials work immediately");
    assert_eq!(forwarded.method(), "MESSAGE");
    assert!(forwarded.hdr("Proxy-Authorization").is_none());
    assert!(recv(&phone).is_none());
}

// ------------------------------------------------------------ enumeration

/// A stranger is challenged whatever it dials, so it can't tell which
/// numbers exist; after authenticating it gets the 404. Registered phones
/// get a 404 for a misdial straight away.
#[test]
fn strangers_cannot_tell_which_numbers_exist() {
    let mut e = env();
    e.pbx.cfg.groups.insert("100".into(), vec!["101".into()]);
    let att = e.attacker.try_clone().unwrap();
    for (method, number) in [
        ("INVITE", "103"), // configured, not registered
        ("INVITE", "999"),
        ("MESSAGE", "999"),
        ("MESSAGE", "100"), // a group: 405 for calls only
        ("OPTIONS", "999"),
    ] {
        let ruri = format!("sip:{number}@pbx");
        let call = format!("en-{method}-{number}");
        send(&mut e, &att, &request(method, &ruri, "x", &att, &call, &call, ""));
        assert_eq!(status(&recv(&att)), 407, "{method} {number}");
    }
    for number in ["101", "999"] {
        let ruri = format!("sip:{number}@pbx");
        let call = format!("en-sub-{number}");
        let sub = request("SUBSCRIBE", &ruri, "x", &att, &call, &call, "Event: presence\r\n");
        send(&mut e, &att, &sub);
        assert_eq!(status(&recv(&att)), 489, "SUBSCRIBE {number}");
    }
    let cancel = request("CANCEL", "sip:999@pbx", "x", &att, "en-c", "en-c", "");
    send(&mut e, &att, &cancel);
    assert_eq!(status(&recv(&att)), 481, "CANCEL to nowhere");
    // authenticated: the truth
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:999@pbx", "103", &att, "en1", "en1", ""),
    );
    let nonce = get_nonce(&recv(&att).unwrap(), "Proxy-Authenticate");
    let pa = auth_hdr(
        "Proxy-Authorization",
        "103",
        "pw103",
        "INVITE",
        "sip:999@pbx",
        &nonce,
    );
    send(
        &mut e,
        &att,
        &request("INVITE", "sip:999@pbx", "103", &att, "en2", "en2", &pa),
    );
    assert_eq!(status(&recv(&att)), 404);
    // registered phones: no challenge for a misdial
    let p101 = e.p101.try_clone().unwrap();
    send(
        &mut e,
        &p101,
        &request("MESSAGE", "sip:999@pbx", "101", &p101, "en3", "en3", ""),
    );
    assert_eq!(status(&recv(&p101)), 404);
    send(
        &mut e,
        &p101,
        &request("MESSAGE", "sip:100@pbx", "101", &p101, "en4", "en4", ""),
    );
    assert_eq!(status(&recv(&p101)), 405);
    // A registered address alone is not enough when From claims another
    // configured extension: don't reveal destinations before authorization.
    for (number, code) in [("999", 404), ("100", 405)] {
        let ruri = format!("sip:{number}@pbx");
        let call = format!("en-mismatch-{number}");
        send(
            &mut e,
            &p101,
            &request("MESSAGE", &ruri, "103", &p101, &call, &call, ""),
        );
        let challenge = recv(&p101).unwrap();
        assert_eq!(challenge.code(), 407);
        let nonce = get_nonce(&challenge, "Proxy-Authenticate");
        let a = auth_hdr("Proxy-Authorization", "103", "pw103", "MESSAGE", &ruri, &nonce);
        send(
            &mut e,
            &p101,
            &request("MESSAGE", &ruri, "103", &p101, &call, &call, &a),
        );
        assert_eq!(status(&recv(&p101)), code);
    }
}

/// Before authenticating, REGISTER for a number that isn't an extension
/// gets the same answers as for one that is.
#[test]
fn register_does_not_reveal_which_extensions_exist() {
    let mut e = env();
    let shape = |m: &Message| {
        let names: Vec<String> = m.headers.iter().map(|h| h.name.clone()).collect();
        let challenge = m
            .hdr("WWW-Authenticate")
            .map(|c| c.replace(&get_nonce(m, "WWW-Authenticate"), "N"));
        (m.code(), names, challenge)
    };
    let mut answers = Vec::new();
    for ext in ["103", "999"] {
        let s = sock();
        send(&mut e, &s, &reg_msg(&s, ext, "enum", 1, ""));
        let challenge = recv(&s).unwrap();
        let nonce = get_nonce(&challenge, "WWW-Authenticate");
        let a = auth_hdr("Authorization", ext, "guess", "REGISTER", "sip:127.0.0.1", &nonce);
        send(&mut e, &s, &reg_msg(&s, ext, "enum", 2, &a));
        answers.push((shape(&challenge), shape(&recv(&s).unwrap())));
    }
    assert_eq!(answers[0], answers[1]);
    assert_eq!((answers[0].0).0, 401);
    assert_eq!((answers[0].1).0, 403);
}

// ------------------------------------------------------------ one phone, another's calls

/// REGISTER `ext` from `s` with these Contact header values (a full 401
/// round trip). Returns the final response's status.
fn register_contacts(e: &mut Env, s: &UdpSocket, ext: &str, contacts: &[&str], call: &str) -> u16 {
    let nonce = reg_nonce(e, s, ext, call);
    let a = auth_hdr(
        "Authorization",
        ext,
        &format!("pw{ext}"),
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
    );
    let own = format!("Contact: <sip:{}@127.0.0.1:{}>\r\n", ext, addr(s).port());
    let mine: String = contacts.iter().map(|c| format!("Contact: {}\r\n", c)).collect();
    send(e, s, &reg_msg(s, ext, call, 2, &a).replace(&own, &mine));
    status(&recv(s))
}

/// A "phone" on another host than the others (all 127.0.0.1): the same
/// host may register several extensions with one address (several lines).
fn other_host() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.2:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
    s
}

/// 103 registers 102's Contact to receive the re-INVITEs, BYE, INFO and
/// MESSAGEs of 102's calls (in-dialog requests are routed by Contact).
#[test]
fn an_extension_cannot_register_another_ones_contact() {
    let mut e = env();
    let (p101, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    send(
        &mut e,
        &p101,
        &request("INVITE", "sip:102@pbx", "101", &p101, "d1", "dlg", ""),
    );
    let inv = recv(&p102).unwrap();
    let rr = inv.hdr("Record-Route").unwrap().to_string();
    respond(&mut e, &p102, &inv, 200, "t102", true);
    assert_eq!(status(&recv(&p101)), 200);
    let evil = other_host();
    let c102 = format!("sip:102@127.0.0.1:{}", addr(&p102).port());
    for contact in [
        format!("<{c102}>"),
        format!("<sip:x@127.0.0.1:{};transport=udp>", addr(&p102).port()),
    ] {
        assert_eq!(
            register_contacts(&mut e, &evil, "103", &[&contact], "ev"),
            403,
            "{contact}"
        );
    }
    assert!(e.pbx.reg.lookup("103").is_none());
    let reinv = request(
        "INVITE",
        &c102,
        "101",
        &p101,
        "d2",
        "dlg",
        &format!("Route: {}\r\n", rr),
    )
    .replace(&format!("To: <{}>", c102), &format!("To: <{}>;tag=t102", c102));
    send(&mut e, &p101, &reinv);
    assert_eq!(recv(&p102).expect("102 gets its re-INVITE").method(), "INVITE");
    assert!(recv(&evil).is_none());
    // unregistering such a Contact is harmless and allowed
    let c = format!("<{c102}>;expires=0");
    assert_eq!(register_contacts(&mut e, &evil, "103", &[&c], "ev2"), 200);
    assert_eq!(e.pbx.reg.get("102").len(), 1);
}

/// A phone with several lines registers them all with the same address,
/// and a phone that is where its Contact says always gets it (and the
/// in-dialog requests), even if another extension claimed it first.
#[test]
fn shared_contacts_that_are_fine() {
    let mut e = env();
    let phone = sock();
    let c = |ext: &str| format!("<sip:{}@127.0.0.1:{}>", ext, addr(&phone).port());
    assert_eq!(register_contacts(&mut e, &phone, "103", &[&c("103")], "l1"), 200);
    assert_eq!(
        register_contacts(&mut e, &phone, "102", &[&c("102")], "l2"),
        200,
        "second line"
    );
    // 101, on another host, claims an address where nobody is registered
    // yet...
    let (squatter, victim) = (other_host(), sock());
    let at = format!("<sip:x@127.0.0.1:{}>", addr(&victim).port());
    assert_eq!(register_contacts(&mut e, &squatter, "101", &[&at], "sq"), 200);
    // ... the phone that is there registers anyway, and gets its requests
    let mine = format!("<sip:102@127.0.0.1:{}>", addr(&victim).port());
    assert_eq!(register_contacts(&mut e, &victim, "102", &[&mine], "v"), 200);
    let u = Uri::parse(&mine[1..mine.len() - 1]).unwrap();
    assert_eq!(e.pbx.reg.find_by_contact(&u).unwrap().source, addr(&victim));
    // and the squatter can't refresh its claim any more
    assert_eq!(register_contacts(&mut e, &squatter, "101", &[&at], "sq"), 403);
}

/// A phone that got a new address re-registers with its Call-ID: its old
/// address must not stay trusted (calls without a password) and keep
/// ringing until the old binding expires.
#[test]
fn moved_phone_leaves_no_binding_behind() {
    let mut e = env();
    let (old, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let moved = sock();
    // env() registered 101 with Call-ID "101"
    let nonce = reg_nonce(&mut e, &moved, "101", "101");
    let a = auth_hdr(
        "Authorization",
        "101",
        "pw101",
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
    );
    send(&mut e, &moved, &reg_msg(&moved, "101", "101", 5, &a));
    assert_eq!(status(&recv(&moved)), 200);
    let l = e.pbx.reg.get("101");
    assert_eq!(l.len(), 1, "{l:?}");
    assert_eq!(l[0].source, addr(&moved));
    send(
        &mut e,
        &old,
        &request("INVITE", "sip:102@pbx", "101", &old, "st1", "st1", ""),
    );
    assert_eq!(status(&recv(&old)), 407, "the old address is a stranger now");
    assert!(recv(&p102).is_none());
    send(
        &mut e,
        &p102,
        &request("INVITE", "sip:101@pbx", "102", &p102, "st2", "st2", ""),
    );
    assert_eq!(recv(&moved).expect("rings where 101 is now").method(), "INVITE");
    assert!(recv(&old).is_none());
    // another device of 101 (its own Call-ID) is not affected
    let second = sock();
    let nonce = reg_nonce(&mut e, &second, "101", "second");
    let a = auth_hdr(
        "Authorization",
        "101",
        "pw101",
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
    );
    send(&mut e, &second, &reg_msg(&second, "101", "second", 2, &a));
    assert_eq!(status(&recv(&second)), 200);
    assert_eq!(e.pbx.reg.get("101").len(), 2);
}

// ------------------------------------------------------------ oversized registrations

/// A Contact of `len` bytes with `n` URI parameters (and a +sip.instance).
fn big_contact(host_port: &str, n: usize, len: usize) -> String {
    let mut c = format!("<sip:103@{host_port};transport=udp");
    for i in 1..n {
        c.push_str(&format!(";p{i}=v"));
    }
    c.push('>');
    c.push_str(";+sip.instance=\"<urn:uuid:");
    while c.len() + 2 < len {
        c.push('0');
    }
    c.push_str(">\"");
    c
}

#[test]
fn oversized_contacts_are_refused() {
    let mut e = env();
    let s = sock();
    let hp = addr(&s).to_string();
    for (contact, what) in [
        (
            big_contact(&hp, 8, crate::registrar::MAX_CONTACT_LEN + 1),
            "too long",
        ),
        (
            big_contact(&hp, crate::registrar::MAX_CONTACT_PARAMS + 1, 600),
            "too many parameters",
        ),
    ] {
        assert_eq!(
            register_contacts(&mut e, &s, "103", &[&contact], what),
            400,
            "{what}"
        );
    }
    let many: Vec<String> = (0..=crate::registrar::MAX_CONTACTS)
        .map(|i| format!("<sip:103@127.0.0.1:{};line={i}>", addr(&s).port()))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(register_contacts(&mut e, &s, "103", &many, "many"), 400);
    assert!(e.pbx.reg.lookup("103").is_none());
    // a long Contact of a real phone (Linphone with push parameters)
    let linphone = format!(
        "<sip:103@{hp};transport=udp;pn-prid={};pn-provider=fcm;pn-param=929724111839;pn-silent=1;\
         pn-timeout=0;pn-msg-str=IM_MSG;pn-call-str=IC_MSG;pn-groupchat-str=GC_MSG;\
         pn-call-snd=notes_of_the_optimistic.caf;pn-msg-snd=msg.caf>;\
         +sip.instance=\"<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>\";\
         +org.linphone.specs=\"conference/1.0,ephemeral/1.1,groupchat/1.1,lime\"",
        "x".repeat(163)
    );
    assert_eq!(register_contacts(&mut e, &s, "103", &[&linphone], "lp"), 200);
}

/// Five devices with the largest Contacts allowed can neither make the
/// next REGISTER slow nor its 200 OK (which lists them all) too big.
#[test]
fn largest_registrations_stay_cheap() {
    let mut e = env();
    let max = (
        crate::registrar::MAX_CONTACT_PARAMS,
        crate::registrar::MAX_CONTACT_LEN,
    );
    let devices: Vec<UdpSocket> = (0..crate::registrar::MAX_BINDINGS_PER_EXT)
        .map(|_| sock())
        .collect();
    for (i, d) in devices.iter().enumerate() {
        let c = big_contact(&addr(d).to_string(), max.0, max.1).replacen(
            "<urn:uuid:0",
            &format!("<urn:uuid:{i}"),
            1,
        );
        assert_eq!(
            register_contacts(&mut e, d, "103", &[&c], &format!("big{i}")),
            200
        );
    }
    assert_eq!(e.pbx.reg.get("103").len(), devices.len());
    // the worst REGISTER: as many such Contacts as allowed
    let s = sock();
    let contacts: Vec<String> = (0..crate::registrar::MAX_CONTACTS)
        .map(|i| big_contact(&format!("127.0.0.1:{}", 40000 + i), max.0, max.1))
        .collect();
    let contacts: Vec<&str> = contacts.iter().map(String::as_str).collect();
    let t = Instant::now();
    let before = e.pbx.reg.get("103");
    assert_eq!(register_contacts(&mut e, &s, "103", &contacts, "worst"), 403);
    assert_eq!(e.pbx.reg.get("103"), before);
    assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
    // A query still gets 200 OK, listing every unchanged binding.
    let phone = sock();
    let nonce = reg_nonce(&mut e, &phone, "103", "phone");
    let a = auth_hdr(
        "Authorization",
        "103",
        "pw103",
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
    );
    let query = reg_msg(&phone, "103", "phone", 2, &a)
        .replace(&format!("Contact: <sip:103@{}>\r\n", addr(&phone)), "");
    send(&mut e, &phone, &query);
    let r = recv(&phone).expect("200 OK");
    assert_eq!(r.code(), 200);
    assert_eq!(r.hdrs("Contact").count(), crate::registrar::MAX_BINDINGS_PER_EXT);
    assert!(r.to_bytes().len() < 16 * 1024, "{} bytes", r.to_bytes().len());
}

// ------------------------------------------------------------ logs

/// One summary line per REGISTER, however many Contacts it has, with the
/// User-Agent and URIs cut short.
#[test]
fn a_register_logs_one_short_line() {
    let mut e = env();
    let s = sock();
    let p = addr(&s).port();
    let ua = format!("User-Agent: {}\r\n", "U".repeat(30000));
    let nonce = reg_nonce(&mut e, &s, "103", "amp");
    test_log::start();
    for (i, n) in [
        crate::registrar::MAX_BINDINGS_PER_EXT,
        crate::registrar::MAX_CONTACTS,
        1000,
    ]
    .into_iter()
    .enumerate()
    {
        let contacts: String = (0..n)
            .map(|i| format!("Contact: <sip:{}{}@127.0.0.1:{p}>\r\n", i, "x".repeat(150)))
            .collect();
        let a = auth_hdr_nc(
            "Authorization",
            "103",
            "pw103",
            "REGISTER",
            "sip:127.0.0.1",
            &nonce,
            1 + i as u32,
        );
        let own = format!("Contact: <sip:103@127.0.0.1:{p}>\r\n");
        let msg = reg_msg(&s, "103", "amp", 2 + i as u32, &a).replace(&own, &(contacts + &ua));
        send(&mut e, &s, &msg);
        assert_eq!(status(&recv(&s)), [200, 403, 400][i]);
    }
    let log = test_log::take();
    // One bounded summary for each successful or refused REGISTER.
    assert_eq!(log.len(), 3, "{log:#?}");
    assert!(log.iter().all(|l| l.len() < 1000), "{log:#?}");
    assert!(
        log[0].contains("103 from 127.0.0.1") && log[0].contains("2 more"),
        "{log:#?}"
    );
    assert!(log[1].contains("exceeds the binding limit"), "{log:#?}");
}

/// Strangers' requests don't get packet text into the log at INFO, and
/// what phones send is escaped and cut short.
#[test]
fn log_lines_carry_no_raw_packet_text() {
    let mut e = env();
    let (att, p101) = (e.attacker.try_clone().unwrap(), e.p101.try_clone().unwrap());
    let inj = "\x1b[2K\r2025-01-01 00:00:00 INFO 101 registered from 1.2.3.4 \x1b]0;pwned\x07";
    let evil_from =
        |m: String, user: &str| m.replace("From: <sip:101@pbx>", &format!("From: <sip:{}@pbx>", user));
    test_log::start();
    for user in [inj.to_string(), "A".repeat(60000)] {
        send(
            &mut e,
            &att,
            &evil_from(request("INVITE", "sip:999@pbx", "101", &att, "i", "i", ""), &user),
        );
        assert_eq!(status(&recv(&att)), 407);
        let bye = request("BYE", "sip:102@pbx", "101", &att, "b", "b", "")
            .replace("To: <sip:102@pbx>", "To: <sip:102@pbx>;tag=1");
        send(&mut e, &att, &evil_from(bye, &user));
        assert_eq!(status(&recv(&att)), 481);
    }
    assert_eq!(
        test_log::take(),
        Vec::<String>::new(),
        "nothing at INFO for strangers"
    );
    // a phone's misdial is logged, harmlessly
    for user in [inj.to_string(), "A".repeat(60000)] {
        send(
            &mut e,
            &p101,
            &evil_from(
                request("INVITE", "sip:999@pbx", "101", &p101, "j", "j", ""),
                &user,
            ),
        );
        assert_eq!(status(&recv(&p101)), 404);
    }
    let log = test_log::take();
    assert_eq!(log.len(), 2, "{log:#?}");
    for l in &log {
        assert!(!l.chars().any(|c| c.is_control()), "{l:?}");
        assert!(l.len() < 300, "{} bytes", l.len());
    }
    assert!(log[0].contains("\\x1b[2K\\x0d2025"), "{:?}", log[0]);
}

/// With log = debug every packet is dumped, but credential headers are
/// hidden, including folded lines that contain the digest response.
#[test]
fn packet_dumps_hide_folded_credentials() {
    let mut e = env();
    let s = sock();
    let nonce = reg_nonce(&mut e, &s, "103", "dump");
    let a = auth_hdr(
        "Authorization",
        "103",
        "pw103",
        "REGISTER",
        "sip:127.0.0.1",
        &nonce,
    );
    let response = a.split("response=\"").nth(1).unwrap()[..32].to_string();
    let folded = a
        .replace(", response=", ",\r\n response=")
        .replace(", algorithm=", ",\r\n\talgorithm=");
    // Also redact malformed credentials in a header the registrar ignores.
    let headers =
        format!("{folded}pRoXy-aUtHoRiZaTiOn: Digest\r\n\tresponse=\"é-unclosed\r\nX-Next: visible\r\n");
    test_log::start_debug();
    send(&mut e, &s, &reg_msg(&s, "103", "dump", 2, &headers));
    assert_eq!(status(&recv(&s)), 200);
    let log = test_log::take().join("\n");
    assert!(
        log.contains("<<< ") && log.contains("Authorization: …\n …\n\t…"),
        "{log}"
    );
    assert!(
        log.contains("pRoXy-aUtHoRiZaTiOn: …\n\t…\nX-Next: visible"),
        "{log}"
    );
    for secret in [&response, &nonce, "username=\"103\"", "é-unclosed"] {
        assert!(!log.contains(secret), "{log}");
    }
    assert!(!log.contains('\r'));
}

// ------------------------------------------------------------ caller ID

/// 101 (trusted by its address) claims to be 103 ("Mom") in the headers
/// phones prefer for the caller's name and number; and the callee claims
/// to be someone else in its answer.
#[test]
fn identity_headers_are_not_passed_on() {
    let mut e = env();
    let (p101, p102) = (e.p101.try_clone().unwrap(), e.p102.try_clone().unwrap());
    let extra = "P-Asserted-Identity: \"Mom\" <sip:103@pbx>\r\nremote-party-id: \"Mom\" <sip:103@pbx>;party=calling\r\n\
                 P-Preferred-Identity: <sip:103@pbx>\r\n";
    send(
        &mut e,
        &p101,
        &request("INVITE", "sip:102@pbx", "101", &p101, "pai", "pai", extra),
    );
    let f = recv(&p102).unwrap();
    for h in ["P-Asserted-Identity", "Remote-Party-ID", "P-Preferred-Identity"] {
        assert!(f.hdr(h).is_none(), "{h} passed on");
    }
    assert!(f.hdr("From").unwrap().starts_with("<sip:101@pbx>"));
    let mut ok = f.make_response(200, "OK", Some("t"));
    ok.headers.push(Header {
        name: "P-Asserted-Identity".into(),
        value: "\"Mom\" <sip:103@pbx>".into(),
    });
    e.pbx.handle(&ok.to_bytes(), addr(&p102));
    let r = recv(&p101).unwrap();
    assert_eq!(r.code(), 200);
    assert!(r.hdr("P-Asserted-Identity").is_none());
}
