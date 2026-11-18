//! Registration regressions, including authenticated REGISTER packet handling.

use super::*;
use crate::config::Config;
use crate::proxy::Pbx;
use crate::sip::Message;
use crate::util::md5_hex;
use std::net::UdpSocket;
use std::time::Duration;
use RegisterError::{StaleCSeq, TooManyContacts};

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn updates(contacts: &[(&str, &str, u32)]) -> Vec<(String, String, u32)> {
    contacts
        .iter()
        .map(|(c, p, e)| (c.to_string(), p.to_string(), *e))
        .collect()
}

#[test]
fn wildcard_replay_cannot_remove_newer_registration() {
    let mut r = Registrar::new(None, 3600);
    let contact = "sip:101@phone";
    r.update("101", contact, "", addr(5001), 60, "call", 10, "ua");
    assert_eq!(r.unregister_all("101", "call", 11), Ok(true));
    r.update("101", contact, "", addr(5001), 60, "call", 12, "ua");
    let before = r.get("101");
    for seq in [11, 12] {
        assert_eq!(r.unregister_all("101", "call", seq), Err(StaleCSeq));
        assert_eq!(r.get("101"), before);
    }
    assert_eq!(r.unregister_all("101", "call", 13), Ok(true));
    assert_eq!(r.unregister_all("101", "call", 13), Ok(false));
}

#[test]
fn wildcard_checks_every_binding_before_removing_any() {
    let mut r = Registrar::new(None, 3600);
    r.update("101", "sip:101@one", "", addr(5001), 60, "call", 10, "ua");
    r.update("101", "sip:101@two", "", addr(5002), 60, "other", 900, "ua");
    r.update("101", "sip:101@three", "", addr(5003), 60, "call", 20, "ua");
    r.update("102", "sip:102@four", "", addr(5004), 60, "call", 99, "ua");
    let before = r.all();
    assert_eq!(r.unregister_all("101", "call", 15), Err(StaleCSeq));
    assert_eq!(r.all(), before);
    // The other device's Call-ID has an independent sequence space.
    assert_eq!(r.unregister_all("101", "call", 21), Ok(true));
    assert_eq!(r.get("102").len(), 1);
    assert_eq!(r.unregister_all("102", "new-call", 1), Ok(true));
}

fn replacement_ordering(migrate_source: bool) {
    let mut r = Registrar::new(None, 3600);
    let a = "sip:101@phone;line=a";
    let b = "sip:101@phone;line=b";
    let inst = if migrate_source {
        ";+sip.instance=\"<urn:uuid:device>\""
    } else {
        ""
    };
    let new_source = if migrate_source { addr(5002) } else { addr(5001) };
    r.update("101", a, inst, addr(5001), 60, "call", 10, "ua");
    // A different device (its own Call-ID) must survive migration, even
    // with a higher CSeq.
    r.update(
        "101",
        "sip:101@other",
        "",
        addr(5003),
        60,
        "other-call",
        99,
        "other",
    );
    let migrated = if migrate_source {
        Change::Moved
    } else {
        Change::New
    };
    assert_eq!(
        r.update("101", b, inst, new_source, 60, "call", 11, "ua"),
        migrated
    );
    let before = r.get("101");
    assert_eq!(
        r.update_many(
            "101",
            &updates(&[(a, inst, 60)]),
            (addr(5001), None),
            "call",
            10,
            "ua"
        ),
        Err(StaleCSeq)
    );
    assert_eq!(r.get("101"), before);
    assert_eq!(r.lookup("101").unwrap().contact, b);
    // A reboot/new Call-ID may legitimately start again at 1.
    assert_eq!(
        r.update("101", a, inst, new_source, 60, "reboot", 1, "ua"),
        Change::New
    );
    assert_eq!(r.get("101").len(), 2);
    assert_eq!(r.lookup("101").unwrap().contact, a);
}

#[test]
fn same_source_contact_migration_checks_cseq() {
    replacement_ordering(false);
}

#[test]
fn same_instance_contact_and_source_migration_checks_cseq() {
    replacement_ordering(true);
}

#[test]
fn replacement_validates_all_device_identities() {
    let mut r = Registrar::new(None, 3600);
    let inst = ";+sip.instance=\"<urn:uuid:two>\"";
    r.update("101", "sip:101@one", "", addr(5001), 60, "call", 10, "ua");
    r.update("101", "sip:101@two", inst, addr(5002), 60, "call", 20, "ua");
    let before = r.get("101");
    let contacts = updates(&[("sip:101@new", inst, 60)]);
    for contact in ["sip:101@new", "sip:101@one"] {
        assert_eq!(
            r.update_many(
                "101",
                &updates(&[(contact, inst, 60)]),
                (addr(5001), None),
                "call",
                11,
                "ua"
            ),
            Err(StaleCSeq)
        );
        assert_eq!(r.get("101"), before);
    }
    assert!(r
        .update_many("101", &contacts, (addr(5001), None), "call", 21, "ua")
        .is_ok());
    assert_eq!(r.get("101").len(), 1);
}

#[test]
fn contact_uri_equivalence() {
    let equivalent = [
        (
            "sip:101@phone;transport=udp;line=abc",
            "sip:101@phone;line=abc;transport=udp",
        ),
        ("SIP:Alice@PHONE;Transport=UDP", "sip:Alice@phone;transport=udp"),
        ("sip:%61lice:p%77@phone", "sip:alice:pw@phone"),
        ("sip:alice@phone;line=%61bc", "sip:alice@phone;LINE=ABC"),
        (
            "sip:alice@phone?Subject=Hello&Priority=urgent",
            "sip:alice@PHONE?priority=URGENT&s=hello",
        ),
        ("sip:alice@phone", "sip:alice@phone;extension=present"),
        ("sip:alice@phone;foo=one", "sip:alice@phone;bar=two"),
        ("sip:alice@[2001:DB8::1]:5060", "sip:alice@[2001:db8::1]:5060"),
        ("sip:a%2fb@phone", "sip:a%2Fb@phone"),
        (
            "sip:phone;method=REGISTER;transport=udp",
            "sip:phone;Transport=UDP;Method=REGISTER",
        ),
    ];
    for (a, b) in equivalent {
        assert!(same_contact(a, b), "{a} != {b}");
        assert!(same_contact(b, a), "{b} != {a}");
        let mut r = Registrar::new(None, 3600);
        r.update("101", a, "", addr(5001), 60, "call", 1, "ua");
        assert_eq!(
            r.update("101", b, "", addr(5001), 0, "call", 2, "ua"),
            Change::Removed
        );
        assert!(r.get("101").is_empty());
    }
}

#[test]
fn distinct_contact_uris_do_not_unregister_each_other() {
    let distinct = [
        ("sip:Alice@phone", "sip:alice@phone"),
        ("sip:alice:pw@phone", "sip:alice:PW@phone"),
        ("sip:alice:pw@phone", "sip:alice@phone"),
        ("sip:alice:@phone", "sip:alice@phone"),
        ("sip:alice@phone", "sips:alice@phone"),
        ("sip:alice@phone", "sip:alice@other"),
        ("sip:alice@phone", "sip:phone"),
        ("sip:alice@phone", "sip:alice@phone:5060"),
        ("sips:alice@phone", "sips:alice@phone:5061"),
        ("sip:alice@phone:5060", "sip:alice@phone:5061"),
        ("sip:alice@phone", "sip:alice@phone;transport=udp"),
        ("sip:alice@phone;transport=udp", "sip:alice@phone;transport=tcp"),
        ("sip:alice@phone", "sip:alice@phone;user=ip"),
        ("sip:alice@phone", "sip:alice@phone;ttl=1"),
        ("sip:alice@phone", "sip:alice@phone;method=REGISTER"),
        (
            "sip:alice@phone;method=REGISTER",
            "sip:alice@phone;method=register",
        ),
        ("sip:alice@phone", "sip:alice@phone;maddr=phone"),
        ("sip:alice@phone;line=a", "sip:alice@phone;line=b"),
        ("sip:alice@phone", "sip:alice@phone?Subject=hello"),
        ("sip:alice@phone?Subject=Hello", "sip:alice@phone?Subject=Goodbye"),
        ("sip:alice@phone?Call-ID=Abc", "sip:alice@phone?Call-ID=abc"),
        ("sip:a/b@phone", "sip:a%2Fb@phone"),
    ];
    for (a, b) in distinct {
        assert!(!same_contact(a, b), "{a} == {b}");
        assert!(!same_contact(b, a), "{b} == {a}");
        let mut r = Registrar::new(None, 3600);
        r.update("101", a, "", addr(5001), 60, "call", 1, "ua");
        let before = r.get("101");
        assert_eq!(
            r.update("101", b, "", addr(5001), 0, "call", 2, "ua"),
            Change::Ignored
        );
        assert_eq!(r.get("101"), before, "unregister {b} removed {a}");
    }
}

#[test]
fn equivalent_refresh_keeps_wire_representation_and_checks_ordering() {
    let mut r = Registrar::new(None, 3600);
    let a = "sip:101@phone;transport=udp;line=abc";
    let b = "SIP:101@PHONE;line=abc;Transport=UDP";
    r.update("101", a, "", addr(5001), 60, "call", 10, "ua");
    assert_eq!(
        r.update("101", b, "", addr(5002), 60, "call", 11, "ua"),
        Change::Moved
    );
    assert_eq!(r.get("101").len(), 1);
    assert_eq!(r.lookup("101").unwrap().contact, b);
    let before = r.get("101");
    for exp in [0, 60] {
        assert_eq!(
            r.update_many(
                "101",
                &updates(&[(a, "", exp)]),
                (addr(5001), None),
                "call",
                10,
                "ua"
            ),
            Err(StaleCSeq)
        );
        assert_eq!(r.get("101"), before);
    }
}

#[test]
fn duplicate_register_is_ok_but_does_not_refresh_or_replace() {
    let mut r = Registrar::new(None, 3600);
    let first = updates(&[("sip:101@phone;line=a", "", 60)]);
    let initial = (addr(5001), Some("127.0.0.2".parse().unwrap()));
    assert_eq!(
        r.update_many("101", &first, initial, "call", 10, "ua"),
        Ok(vec![Change::New])
    );
    let before = r.get("101");
    assert_eq!(
        r.update_many("101", &first, (addr(5001), None), "call", 10, "ua"),
        Ok(vec![Change::Ignored])
    );
    assert_eq!(r.get("101"), before);
    let alternate = updates(&[("sip:101@phone;line=b", "", 60)]);
    assert_eq!(
        r.update_many("101", &alternate, (addr(5001), None), "call", 10, "ua"),
        Ok(vec![Change::Ignored])
    );
    assert_eq!(r.get("101"), before);
    assert_eq!(
        r.update_many("101", &first, (addr(5002), None), "call", 10, "ua"),
        Err(StaleCSeq)
    );
    assert_eq!(
        r.update_many("101", &first, (addr(5001), None), "call", 9, "ua"),
        Err(StaleCSeq)
    );
    assert_eq!(r.get("101"), before);
}

#[test]
fn multi_contact_stale_request_is_atomic_in_either_order() {
    let mut r = Registrar::new(None, 3600);
    r.update("101", "sip:101@one", "", addr(5001), 60, "call", 10, "ua");
    r.update("101", "sip:101@two", "", addr(5002), 60, "call", 20, "ua");
    let before = r.get("101");
    for first in ["sip:101@one", "sip:101@new"] {
        for exp in [0, 60] {
            let mut contacts = updates(&[(first, "", exp), ("sip:101@two", "", exp)]);
            for _ in 0..2 {
                assert_eq!(
                    r.update_many("101", &contacts, (addr(5003), None), "call", 11, "ua"),
                    Err(StaleCSeq)
                );
                assert_eq!(r.get("101"), before);
                contacts.reverse();
            }
        }
    }
}

#[test]
fn same_request_contacts_are_not_stale_and_bindings_stay_bounded() {
    let mut r = Registrar::new(None, 3600);
    let contacts = updates(&[("sip:101@one", "", 60), ("sip:101@two", "", 60)]);
    assert!(r
        .update_many("101", &contacts, (addr(5001), None), "call", 10, "ua")
        .is_ok());
    // Both Contacts are kept: one request's Contacts don't replace each other.
    assert_eq!(r.get("101").len(), 2);
    assert_eq!(r.lookup("101").unwrap().contact, "sip:101@two");
    for i in 0..20 {
        r.update(
            "101",
            &format!("sip:101@phone{i}"),
            "",
            addr(5100 + i),
            60,
            &format!("call{i}"),
            1,
            "ua",
        );
        assert!(r.get("101").len() <= MAX_BINDINGS_PER_EXT);
        assert_eq!(
            r.lookup("101").unwrap().source,
            addr(5100 + i),
            "the newest gets in"
        );
    }
    assert_eq!(r.get("101").len(), MAX_BINDINGS_PER_EXT);
}

/// update_many's changes must describe what is stored afterwards: a
/// contact reported as New/Refreshed/Moved (the last time it appears in
/// the request) is registered, one reported as Removed/Ignored is not.
fn apply_and_check(
    r: &mut Registrar,
    contacts: &[(&str, &str, u32)],
    source: SocketAddr,
    cseq: u32,
) -> Vec<Change> {
    let ups = updates(contacts);
    let changes = r
        .update_many("101", &ups, (source, None), "call", cseq, "ua")
        .unwrap();
    assert_eq!(changes.len(), ups.len());
    let stored = r.get("101");
    for (k, ((contact, _, _), change)) in ups.iter().zip(&changes).enumerate() {
        if ups[k + 1..].iter().any(|(c, _, _)| same_contact(c, contact)) {
            continue;
        }
        let is_stored = stored.iter().any(|b| same_contact(&b.contact, contact));
        let says_stored = matches!(change, Change::New | Change::Refreshed | Change::Moved);
        assert_eq!(
            is_stored, says_stored,
            "{contact}: {change:?}, stored: {stored:?}"
        );
    }
    changes
}

#[test]
fn multi_contact_register_keeps_every_contact() {
    use Change::*;
    let mut r = Registrar::new(None, 3600);
    let (v4, v6) = ("sip:101@192.168.1.5:5060", "sip:101@[fd00::5]:5060");
    let both = [(v4, "", 600), (v6, "", 600)];
    assert_eq!(apply_and_check(&mut r, &both, addr(5060), 1), [New, New]);
    assert_eq!(r.get("101").len(), 2);
    assert_eq!(
        apply_and_check(&mut r, &both, addr(5060), 2),
        [Refreshed, Refreshed]
    );
    assert_eq!(r.get("101").len(), 2);
    // One of them unregistered, the other refreshed, in one request.
    assert_eq!(
        apply_and_check(&mut r, &[(v6, "", 0), (v4, "", 600)], addr(5060), 3),
        [Removed, Refreshed]
    );
    assert_eq!(r.get("101").len(), 1);
    // A later REGISTER of the same device still replaces its old Contact
    // (e.g. a new contact user or port), and then adds the second one.
    let moved = [("sip:101@192.168.1.5:5062", "", 600), (v6, "", 600)];
    assert_eq!(apply_and_check(&mut r, &moved, addr(5060), 4), [New, New]);
    assert_eq!(r.get("101").len(), 2);
    assert!(!r.get("101").iter().any(|b| b.contact == v4));
    // The same Contact twice, or added and removed again.
    let mut r = Registrar::new(None, 3600);
    assert_eq!(
        apply_and_check(&mut r, &[(v4, "", 600), (v4, "", 300)], addr(5060), 1),
        [New, Refreshed]
    );
    assert_eq!(r.lookup("101").unwrap().expires_in(mono_now()), 300);
    assert_eq!(r.get("101").len(), 1);
    assert_eq!(
        apply_and_check(&mut r, &[(v6, "", 600), (v6, "", 0)], addr(5060), 2),
        [New, Removed]
    );
    assert!(r.get("101").iter().all(|b| b.contact != v6));
}

#[test]
fn refreshing_one_contact_keeps_an_unlisted_sibling() {
    let mut r = Registrar::new(None, 3600);
    let (v4, v6) = ("sip:101@192.168.1.5", "sip:101@[fd00::5]");
    let src = addr(5060);
    apply_and_check(&mut r, &[(v4, "", 600), (v6, "", 900)], src, 1);
    let sibling = r.get("101").into_iter().find(|b| b.contact == v6).unwrap();
    assert_eq!(
        apply_and_check(&mut r, &[(v4, "", 300)], src, 2),
        [Change::Refreshed]
    );
    assert!(
        r.get("101").contains(&sibling),
        "unlisted Contact must keep its expiry and CSeq"
    );
}

#[test]
fn multi_contact_register_respects_the_device_limit() {
    let mut r = Registrar::new(None, 3600);
    let names: Vec<String> = (0..7).map(|i| format!("sip:101@10.0.0.{i}")).collect();
    let many: Vec<(&str, &str, u32)> = names.iter().map(|n| (n.as_str(), "", 600)).collect();
    assert_eq!(
        r.update_many("101", &updates(&many), (addr(5060), None), "call", 1, "ua"),
        Err(TooManyContacts)
    );
    assert!(r.get("101").is_empty(), "no partial acceptance");
    assert!(r
        .update_many("101", &updates(&many[..5]), (addr(5060), None), "call", 1, "ua")
        .is_ok());
    let before = r.get("101");
    // A request that refreshes/removes old bindings and adds too many is
    // rejected without changing expiry, CSeq, or any of the old Contacts.
    let mut excessive = many.clone();
    excessive[0].2 = 0;
    assert_eq!(
        r.update_many("101", &updates(&excessive), (addr(5060), None), "call", 2, "ua"),
        Err(TooManyContacts)
    );
    assert_eq!(r.get("101"), before);
    // Only the final size matters: adding before removing is fine. The
    // remaining listed Contacts protect the device's other bindings.
    let mut replacement = vec![many[5]];
    replacement.extend_from_slice(&many[..5]);
    replacement[1].2 = 0;
    assert!(r
        .update_many("101", &updates(&replacement), (addr(5060), None), "call", 2, "ua")
        .is_ok());
    let stored = r.get("101");
    assert_eq!(stored.len(), MAX_BINDINGS_PER_EXT);
    assert!(!stored.iter().any(|b| b.contact == names[0]));
    assert!(stored.iter().any(|b| b.contact == names[5]));
}

fn pbx() -> Pbx {
    let sock = UdpSocket::bind(addr(0)).unwrap();
    let mut cfg = Config::parse("[extensions]\n101=pw\n102=pw\n").unwrap();
    cfg.listen = sock.local_addr().unwrap();
    Pbx::new(cfg, sock)
}

struct Client {
    socket: UdpSocket,
    /// The nonce of the challenge, once answered.
    nonce: Option<String>,
    /// The last nonce count used with it (every request uses the next).
    nc: std::cell::Cell<u32>,
}

impl Client {
    fn new(pbx: &mut Pbx) -> Self {
        let socket = UdpSocket::bind(addr(0)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut client = Self {
            socket,
            nonce: None,
            nc: Default::default(),
        };
        let challenge = client.register(pbx, "auth", 1, &[], None);
        assert_eq!(challenge.code(), 401);
        let nonce = challenge
            .hdr("WWW-Authenticate")
            .unwrap()
            .split("nonce=\"")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .unwrap();
        client.nonce = Some(nonce.to_string());
        client
    }

    /// Credentials for the next request, as a phone computes them.
    fn authorization(&self) -> Option<String> {
        let nonce = self.nonce.as_ref()?;
        let nc = self.nc.get() + 1;
        self.nc.set(nc);
        let response = md5_hex(&format!(
            "{}:{}:{:08x}:abc:auth:{}",
            md5_hex("101:pbx:pw"),
            nonce,
            nc,
            md5_hex("REGISTER:sip:pbx")
        ));
        Some(format!(
            "Digest username=\"101\", realm=\"pbx\", nonce=\"{}\", uri=\"sip:pbx\", response=\"{}\", \
             qop=auth, nc={:08x}, cnonce=\"abc\"",
            nonce, response, nc
        ))
    }

    fn register(
        &self,
        pbx: &mut Pbx,
        call_id: &str,
        cseq: u32,
        contacts: &[&str],
        expires: Option<u32>,
    ) -> Message {
        self.register_with(pbx, call_id, cseq, contacts, expires, "")
    }

    /// `extra`: more header lines, each ending in CRLF.
    fn register_with(
        &self,
        pbx: &mut Pbx,
        call_id: &str,
        cseq: u32,
        contacts: &[&str],
        expires: Option<u32>,
        extra: &str,
    ) -> Message {
        self.send(pbx, &self.request(call_id, cseq, contacts, expires, extra))
    }

    fn request(
        &self,
        call_id: &str,
        cseq: u32,
        contacts: &[&str],
        expires: Option<u32>,
        extra: &str,
    ) -> String {
        let source = self.socket.local_addr().unwrap();
        let mut text = format!(
            "REGISTER sip:pbx SIP/2.0\r\nVia: SIP/2.0/UDP {};branch=z9hG4bK{};rport\r\nFrom: <sip:101@pbx>;tag=test\r\nTo: <sip:101@pbx>\r\nCall-ID: {}\r\nCSeq: {} REGISTER\r\n", source, cseq, call_id, cseq
        );
        for contact in contacts {
            text.push_str(&format!("Contact: {}\r\n", contact));
        }
        if let Some(expires) = expires {
            text.push_str(&format!("Expires: {}\r\n", expires));
        }
        if let Some(authorization) = self.authorization() {
            text.push_str(&format!("Authorization: {}\r\n", authorization));
        }
        text.push_str(extra);
        text.push_str("Content-Length: 0\r\n\r\n");
        text
    }

    fn send(&self, pbx: &mut Pbx, text: &str) -> Message {
        self.send_to(pbx, text, None)
    }

    fn send_to(&self, pbx: &mut Pbx, text: &str, local: Option<IpAddr>) -> Message {
        let src = self.socket.local_addr().unwrap();
        pbx.step(Some((text.as_bytes(), src, local)), Instant::now());
        let mut buf = [0; 65535];
        let n = self.socket.recv(&mut buf).unwrap();
        Message::parse(&buf[..n]).unwrap()
    }
}

/// A delayed copy of either transaction gets 200 with today's Contacts,
/// but cannot recreate a removed binding or unregister a newer device.
#[test]
fn completed_registers_survive_contact_and_wildcard_removal() {
    for wildcard in [false, true] {
        let mut pbx = pbx();
        let phone = Client::new(&mut pbx);
        let contact = ["<sip:101@phone>"];
        let add = phone.request("device", 1, &contact, Some(600), "");
        let remove = phone.request("device", 2, if wildcard { &["*"] } else { &contact }, Some(0), "");
        assert_eq!(phone.send(&mut pbx, &add).code(), 200);
        assert_eq!(phone.send(&mut pbx, &remove).code(), 200);
        let duplicate = phone.send(&mut pbx, &add);
        assert_eq!(duplicate.code(), 200);
        assert!(duplicate.hdr("Contact").is_none());
        assert!(pbx.reg.get("101").is_empty());

        // The new binding's local address must survive the delayed copies too.
        let new = phone.request("after-reboot", 1, &contact, Some(600), "");
        let local = Some("127.0.0.2".parse().unwrap());
        assert_eq!(phone.send_to(&mut pbx, &new, local).code(), 200);
        assert_eq!(pbx.reg.lookup("101").unwrap().local, local);
        let before = pbx.reg.get("101");
        for request in [&remove, &add] {
            let duplicate = phone.send(&mut pbx, request);
            assert_eq!(duplicate.code(), 200);
            assert!(duplicate.hdr("Contact").unwrap().contains(contact[0]));
            assert_eq!(pbx.reg.get("101"), before);
        }
    }
}

#[test]
fn register_error_is_repeatable_but_a_fresh_attempt_can_succeed() {
    let mut pbx = pbx();
    let phone = Client::new(&mut pbx);
    let contact = ["<sip:101@phone>"];
    assert_eq!(
        phone.register(&mut pbx, "device", 2, &contact, Some(600)).code(),
        200
    );
    let rejected = phone.request("device", 1, &contact, Some(600), "");
    assert_eq!(phone.send(&mut pbx, &rejected).code(), 500);
    assert_eq!(
        phone.register(&mut pbx, "device", 3, &contact, Some(0)).code(),
        200
    );
    assert_eq!(phone.send(&mut pbx, &rejected).code(), 500);
    assert!(pbx.reg.get("101").is_empty());
    // Same SIP fields, fresh Digest count: the old error doesn't stick.
    assert_eq!(
        phone.register(&mut pbx, "device", 1, &contact, Some(600)).code(),
        200
    );
}

/// Saturation must not shorten the promised transaction lifetime, and
/// retransmissions must not extend it. The monotonic test clock lets the
/// entire window pass without sleeping.
#[test]
fn register_transaction_capacity_and_expiry() {
    let mut pbx = pbx();
    let phone = Client::new(&mut pbx);
    let other = Client::new(&mut pbx);
    let first = phone.request("device", 1, &["<sip:101@phone>"], Some(600), "");
    assert_eq!(phone.send(&mut pbx, &first).code(), 200);
    test_clock::advance(5); // the first transaction will release its slot before all the others
    assert_eq!(other.register(&mut pbx, "other", 1, &["*"], Some(0)).code(), 200);
    for seq in 2..crate::proxy::REGISTER_LIMIT as u32 {
        assert_eq!(
            other.register(&mut pbx, "other", seq, &["*"], Some(0)).code(),
            200
        );
    }
    let new = other.request("other", 1000, &["<sip:101@other>"], Some(600), "");
    test_clock::step_wall(60);
    test_clock::advance(26);
    let full = other.send(&mut pbx, &new);
    assert_eq!(full.code(), 503);
    assert!(full.hdr("Retry-After").is_some());
    assert_eq!(phone.send(&mut pbx, &first).code(), 200);
    assert!(pbx.reg.get("101").is_empty());
    test_clock::advance(1);
    assert_eq!(other.send(&mut pbx, &new).code(), 200);
    assert_eq!(pbx.reg.lookup("101").unwrap().contact, "sip:101@other");
}

#[test]
fn register_packets_reject_stale_wildcard_and_allow_newer() {
    let mut pbx = pbx();
    let client = Client::new(&mut pbx);
    let contact = ["<sip:101@phone>"];
    assert_eq!(
        client.register(&mut pbx, "call", 10, &contact, Some(60)).code(),
        200
    );
    assert_eq!(client.register(&mut pbx, "call", 11, &["*"], Some(0)).code(), 200);
    assert_eq!(
        client.register(&mut pbx, "call", 12, &contact, Some(60)).code(),
        200
    );
    let before = pbx.reg.get("101");
    assert_eq!(client.register(&mut pbx, "call", 11, &["*"], Some(0)).code(), 500);
    assert_eq!(pbx.reg.get("101"), before);
    let query = client.register(&mut pbx, "call", 13, &[], None);
    assert_eq!(query.code(), 200);
    assert!(query.hdr("Contact").unwrap().contains(contact[0]));
    assert_eq!(client.register(&mut pbx, "call", 14, &["*"], Some(0)).code(), 200);
    assert!(pbx.reg.get("101").is_empty());
}

#[test]
fn register_packets_reject_migration_replay_and_unregister_equivalent_uri() {
    let mut pbx = pbx();
    let client = Client::new(&mut pbx);
    let a = ["<sip:101@phone;line=a;transport=udp>"];
    let b = ["<sip:101@phone;line=b;transport=udp>"];
    assert_eq!(client.register(&mut pbx, "call", 10, &a, Some(60)).code(), 200);
    assert_eq!(client.register(&mut pbx, "call", 11, &b, Some(60)).code(), 200);
    let before = pbx.reg.get("101");
    assert_eq!(client.register(&mut pbx, "call", 10, &a, Some(60)).code(), 500);
    assert_eq!(pbx.reg.get("101"), before);
    let reordered = ["<SIP:101@PHONE;Transport=UDP;line=b>"];
    let response = client.register(&mut pbx, "call", 12, &reordered, Some(0));
    assert_eq!(response.code(), 200);
    assert!(response.hdr("Contact").is_none());
    assert!(pbx.reg.get("101").is_empty());
}

#[test]
fn register_packets_with_two_contacts_register_both() {
    let mut pbx = pbx();
    let client = Client::new(&mut pbx);
    let contacts = ["<sip:101@192.168.1.5:5060>", "<sip:101@[fd00::5]:5060>"];
    let response = client.register(&mut pbx, "call", 10, &contacts, Some(600));
    assert_eq!(response.code(), 200);
    let listed: Vec<&str> = response.hdrs("Contact").collect();
    assert_eq!(listed.len(), 2, "{listed:?}");
    for c in contacts {
        assert!(
            listed
                .iter()
                .any(|l| l.starts_with(c) && l.ends_with(";expires=600")),
            "{c} not in {listed:?}"
        );
    }
    assert_eq!(pbx.reg.get("101").len(), 2);
}

#[test]
fn register_packets_out_of_order_are_logged() {
    let mut pbx = pbx();
    let client = Client::new(&mut pbx);
    let contact = ["<sip:101@phone>"];
    assert_eq!(
        client.register(&mut pbx, "call", 10, &contact, Some(60)).code(),
        200
    );
    crate::util::test_log::start();
    assert_eq!(
        client.register(&mut pbx, "call", 9, &contact, Some(60)).code(),
        500
    );
    assert_eq!(client.register(&mut pbx, "call", 9, &["*"], Some(0)).code(), 500);
    let log = crate::util::test_log::take();
    let rejected: Vec<_> = log
        .iter()
        .filter(|l| l.contains("CSeq 9") && l.contains("rejected"))
        .collect();
    assert_eq!(rejected.len(), 2, "{log:?}");
    assert!(
        rejected[0].starts_with("WARN") && rejected[0].contains("101"),
        "{log:?}"
    );
}

#[test]
fn register_packets_with_a_huge_user_agent_store_a_short_one() {
    let mut pbx = pbx();
    let client = Client::new(&mut pbx);
    let ua = format!("Phone/1.0 {}", "é".repeat(5000));
    crate::util::test_log::start();
    let response = client.register_with(
        &mut pbx,
        "call",
        10,
        &["<sip:101@phone>"],
        Some(60),
        &format!("User-Agent: {ua}\r\n"),
    );
    assert_eq!(response.code(), 200);
    let stored = pbx.reg.lookup("101").unwrap().user_agent;
    assert_eq!(stored.chars().count(), MAX_USER_AGENT);
    assert!(ua.starts_with(&stored));
    let log = crate::util::test_log::take();
    assert!(log.iter().any(|l| l.contains("registered from")), "{log:?}");
    assert!(log.iter().all(|l| l.len() < 600), "{log:?}");
}

#[test]
fn register_packets_do_not_partially_apply_invalid_contact_lists() {
    let mut pbx = pbx();
    let first = Client::new(&mut pbx);
    let second = Client::new(&mut pbx);
    assert_eq!(
        first
            .register(&mut pbx, "call", 10, &["<sip:101@one>"], Some(60))
            .code(),
        200
    );
    assert_eq!(
        second
            .register(&mut pbx, "call", 20, &["<sip:101@two>"], Some(60))
            .code(),
        200
    );
    let before = pbx.reg.get("101");
    for (last, status) in [
        ("<sip:101@two>;expires=0", 500),
        ("<tel:123>", 400),
        ("<sip:101@new>;expires=1", 423),
    ] {
        let response = first.register(&mut pbx, "call", 11, &["<sip:101@one>;expires=0", last], Some(60));
        assert_eq!(response.code(), status);
        assert_eq!(pbx.reg.get("101"), before);
    }
}

#[test]
fn granted_interval_is_capped_at_max_expires_and_defaults_to_default_expires() {
    let mut pbx = pbx();
    (pbx.cfg.default_expires, pbx.cfg.max_expires) = (300, 600);
    let phone = Client::new(&mut pbx);
    for (seq, asked, granted) in [(1, Some(99_999), ";expires=600"), (2, None, ";expires=300")] {
        let ok = phone.register(&mut pbx, "device", seq, &["<sip:101@phone>"], asked);
        assert_eq!(ok.code(), 200);
        assert!(ok.hdr("Contact").unwrap().ends_with(granted), "{asked:?}");
    }
}

/// `Contact: *` only unregisters: it needs `Expires: 0` and no other Contact.
#[test]
fn wildcard_contact_must_be_alone_and_have_expires_zero() {
    let mut pbx = pbx();
    let phone = Client::new(&mut pbx);
    let contact = "<sip:101@phone>";
    let ok = phone.register(&mut pbx, "device", 1, &[contact], Some(600));
    assert_eq!(ok.code(), 200);
    let bad: [(&[&str], Option<u32>); 3] = [(&["*"], Some(600)), (&["*"], None), (&["*", contact], Some(0))];
    for (seq, (contacts, expires)) in (2..).zip(bad) {
        let refused = phone.register(&mut pbx, "device", seq, contacts, expires);
        assert_eq!(refused.code(), 400, "{contacts:?} {expires:?}");
        assert_eq!(pbx.reg.get("101").len(), 1);
    }
}

#[test]
fn over_capacity_register_is_refused_without_partial_updates() {
    let mut pbx = pbx();
    let client = Client::new(&mut pbx);
    assert_eq!(
        client
            .register(&mut pbx, "capacity", 1, &["<sip:101@old>"], Some(600))
            .code(),
        200
    );
    let before = pbx.reg.get("101");
    let contacts: Vec<String> = (0..=MAX_BINDINGS_PER_EXT)
        .map(|i| format!("<sip:101@phone{i}>"))
        .collect();
    let mut refs: Vec<&str> = contacts.iter().map(String::as_str).collect();
    refs.insert(0, "<sip:101@old>;expires=0");
    assert_eq!(
        client.register(&mut pbx, "capacity", 2, &refs, Some(600)).code(),
        403
    );
    assert_eq!(pbx.reg.get("101"), before);
    // The rejected CSeq was not committed either; a smaller retry works.
    assert_eq!(
        client
            .register(&mut pbx, "capacity", 2, &refs[..3], Some(600))
            .code(),
        200
    );
    assert_eq!(pbx.reg.get("101").len(), 2);
}

// ------------------------------------------------------------ clock / state file

use crate::util::test_clock;

/// A state file line as `save` writes it, with wall-clock times.
fn state_line(ext: &str, port: u16, expires: u64, registered: u64) -> String {
    format!("{ext}\tsip:{ext}@127.0.0.1:{port}\t\t127.0.0.1:{port}\t{expires}\t{registered}\tcall-{port}\t1\tua\n")
}

#[test]
fn wall_clock_steps_do_not_expire_or_extend_bindings() {
    let mut r = Registrar::new(None, 3600);
    r.update("101", "sip:101@phone", "", addr(5001), 60, "call", 1, "ua");
    // NTP sets the clock a year forward (a Pi without RTC that booted with
    // an old time), then back again: the phone stays registered ...
    test_clock::step_wall(365 * 86400);
    assert_eq!(r.get("101").len(), 1, "a clock step expired the binding");
    assert!(r.registered_from(addr(5001), Some("101")));
    test_clock::step_wall(-2 * 365 * 86400);
    assert_eq!(r.lookup("101").unwrap().expires_in(mono_now()), 60);
    // ... until its 60 s have really passed.
    test_clock::advance(59);
    assert_eq!(r.get("101").len(), 1);
    test_clock::advance(1);
    assert!(r.get("101").is_empty());
    assert!(!r.registered_from(addr(5001), None));
}

#[test]
fn restored_bindings_are_limited_to_max_expires() {
    let dir = crate::util::TestDir::create();
    let path = dir.join("bindings.txt");
    let wall = crate::util::now_unix();
    let mut text =
        String::from("# ext\tcontact\tparams\tsource\texpires\tregistered\tcall-id\tcseq\tuser-agent\n");
    text += &state_line("101", 5001, wall + 99_999_999_999_999, wall); // hand-edited / clock was far ahead
    text += &state_line("101", 5002, wall + 100, wall - 50);
    text += &state_line("101", 5003, wall - 1, wall - 3600); // expired
    text += &state_line("102", 5004, u64::MAX, u64::MAX);
    std::fs::write(&path, text).unwrap();
    let r = Registrar::new(Some(path.clone()), 600);
    let now = mono_now();
    let left = |port| {
        r.all()
            .into_iter()
            .find(|(_, b)| b.source == addr(port))
            .map(|(_, b)| b.expires_in(now))
    };
    assert_eq!(left(5001), Some(600));
    assert_eq!(left(5002), Some(100));
    assert_eq!(left(5003), None);
    assert_eq!(left(5004), Some(600));
    // A binding "registered in the future" is not newer than everything else.
    assert!(r.lookup("102").unwrap().registered <= now);
    // Saving writes sane wall-clock times again.
    let mut r = r;
    r.save();
    let saved = std::fs::read_to_string(&path).unwrap();
    for line in saved.lines().filter(|l| !l.starts_with('#')) {
        let expires: u64 = line.split('\t').nth(4).unwrap().parse().unwrap();
        assert!(expires <= wall + 601, "{line}");
    }
    // The wall clock was set back by a year since the file was written:
    // the remaining time is still at most max_expires.
    test_clock::step_wall(-365 * 86400);
    let r = Registrar::new(Some(path.clone()), 3600);
    assert!(r.all().iter().all(|(_, b)| b.expires_in(mono_now()) <= 3600));
    assert_eq!(r.all().len(), 3);
}

#[test]
fn restored_bindings_respect_the_per_extension_limit() {
    let dir = crate::util::TestDir::create();
    let path = dir.join("bindings.txt");
    let wall = crate::util::now_unix();
    // A hand-edited or older file may contain more than the limit.
    let text: String = (0..8)
        .map(|i| {
            state_line(
                "101",
                5000 + i,
                wall + if i == 0 { 3000 } else { 600 + i as u64 },
                wall - 100,
            )
        })
        .collect();
    std::fs::write(&path, text).unwrap();
    let r = Registrar::new(Some(path), 3600);
    let mut kept: Vec<u16> = r.get("101").iter().map(|b| b.source.port()).collect();
    kept.sort();
    assert_eq!(
        kept,
        [5000, 5001, 5002, 5003, 5004],
        "excess rows are skipped, not used to evict earlier rows"
    );
}

/// A softphone that restarts on a new port without unregistering must not
/// lock its extension until the old bindings expire: a phone that registers
/// always gets in, and what makes room is what its own host left behind,
/// not the desk phone, even if that one refreshed before all the restarts.
#[test]
fn binding_limit_drops_what_a_restarting_softphone_left_behind() {
    let at = |host: u8, port: u16| SocketAddr::from(([10, 0, 0, host], port));
    crate::util::test_log::start();
    let mut r = Registrar::new(None, 3600);
    r.update(
        "101",
        "sip:101@10.0.0.5",
        "",
        at(5, 5060),
        3600,
        "desk",
        1,
        "desk",
    );
    test_clock::advance(100);
    // Six starts within one refresh interval of the desk phone, each with a
    // new port and Call-ID.
    for i in 0..6u16 {
        test_clock::advance(10);
        let soft = updates(&[(&format!("sip:101@10.0.0.9:{}", 40000 + i), "", 3600)]);
        assert_eq!(
            r.update_many(
                "101",
                &soft,
                (at(9, 40000 + i), None),
                &format!("soft{i}"),
                1,
                "soft"
            ),
            Ok(vec![Change::New])
        );
        let l = r.get("101");
        assert!(l.len() <= MAX_BINDINGS_PER_EXT);
        assert!(
            l.iter().any(|b| b.user_agent == "desk"),
            "desk phone dropped: {l:?}"
        );
        assert_eq!(l[0].contact, soft[0].0, "the newest device must be kept");
    }
    let mut ports: Vec<u16> = r.get("101").iter().map(|b| b.source.port()).collect();
    ports.sort();
    // Its two oldest leftovers went, the desk phone and the newest four stayed.
    assert_eq!(ports, [5060, 40002, 40003, 40004, 40005]);
    let log = crate::util::test_log::take();
    let dropped: Vec<_> = log.iter().filter(|l| l.contains("dropped")).collect();
    assert_eq!(dropped.len(), 2, "{log:?}");
    assert!(dropped[0].contains("sip:101@10.0.0.9:40000") && dropped[0].contains("more than 5 devices"));
}

/// With nothing of its own to replace, a sixth device takes the place of
/// the one heard from longest ago: never its own, and not a phone that
/// keeps refreshing.
#[test]
fn binding_limit_otherwise_drops_the_binding_heard_from_longest_ago() {
    let at = |host: u8| SocketAddr::from(([10, 0, 0, host], 5060));
    let contact = |host: u8| format!("sip:101@10.0.0.{host}");
    let mut r = Registrar::new(None, 3600);
    for host in 1..=5u8 {
        test_clock::advance(60);
        r.update(
            "101",
            &contact(host),
            "",
            at(host),
            3600,
            &format!("c{host}"),
            1,
            "ua",
        );
    }
    // The first one refreshes, so the second is now the stalest.
    test_clock::advance(60);
    assert_eq!(
        r.update("101", &contact(1), "", at(1), 3600, "c1", 2, "ua"),
        Change::Refreshed
    );
    // A new device is not the one dropped, even with the shortest interval.
    assert_eq!(
        r.update("101", &contact(6), "", at(6), 60, "c6", 1, "ua"),
        Change::New
    );
    let mut hosts: Vec<SocketAddr> = r.get("101").iter().map(|b| b.source).collect();
    hosts.sort();
    assert_eq!(hosts, [at(1), at(3), at(4), at(5), at(6)]);
    // Expired bindings don't count towards the limit.
    test_clock::advance(61);
    assert!(!r.registered_from(at(6), None));
    crate::util::test_log::start();
    r.update("101", &contact(7), "", at(7), 60, "c7", 1, "ua");
    assert_eq!(r.get("101").len(), MAX_BINDINGS_PER_EXT);
    assert!(crate::util::test_log::take().is_empty(), "nothing had to go");
}

/// The same through REGISTER packets: the sixth device gets 200 OK, and the
/// reply lists the five bindings that are left.
#[test]
fn sixth_device_registers_and_the_stalest_binding_goes() {
    let mut pbx = pbx();
    let phones: Vec<Client> = (0..=MAX_BINDINGS_PER_EXT)
        .map(|_| Client::new(&mut pbx))
        .collect();
    let mut first = String::new();
    for (i, phone) in phones.iter().enumerate() {
        test_clock::advance(1);
        let contact = format!("<sip:101@phone{i}>");
        let request = phone.request(&format!("call{i}"), 1, &[&contact], Some(600), "");
        let reply = phone.send(&mut pbx, &request);
        if i == 0 {
            first = request;
        }
        assert_eq!(reply.code(), 200, "phone{i}");
        let listed: Vec<&str> = reply.hdrs("Contact").collect();
        assert_eq!(listed.len(), (i + 1).min(MAX_BINDINGS_PER_EXT));
        assert!(listed.iter().any(|c| c.contains(&contact)), "{listed:?}");
    }
    let left = pbx.reg.get("101");
    assert_eq!(left.len(), MAX_BINDINGS_PER_EXT);
    assert!(!left.iter().any(|b| b.contact == "sip:101@phone0"), "{left:?}");
    // A retransmission from the evicted device does not evict its successor.
    let duplicate = phones[0].send(&mut pbx, &first);
    assert_eq!(duplicate.code(), 200);
    assert!(duplicate.hdrs("Contact").all(|c| !c.contains("@phone0>")));
    assert_eq!(pbx.reg.get("101"), left);
}

#[test]
fn register_reply_never_echoes_absurd_restored_expiry() {
    let dir = crate::util::TestDir::create();
    let path = dir.join("bindings.txt");
    let wall = crate::util::now_unix();
    std::fs::write(&path, state_line("101", 5001, wall + 99_999_999_999_999, wall)).unwrap();
    let sock = UdpSocket::bind(addr(0)).unwrap();
    let mut cfg = Config::parse("[extensions]\n101=pw\n").unwrap();
    cfg.listen = sock.local_addr().unwrap();
    cfg.state_file = Some(path);
    let mut pbx = Pbx::new(cfg, sock);
    let client = Client::new(&mut pbx);
    let query = client.register(&mut pbx, "auth", 2, &[], None);
    assert_eq!(query.code(), 200);
    let contact = query.hdr("Contact").unwrap();
    assert!(contact.ends_with(";expires=3600"), "{contact}");
}

#[test]
fn damaged_state_file_keeps_good_lines_without_repairing_invalid_rows() {
    let dir = crate::util::TestDir::create();
    let path = dir.join("bindings.txt");
    let wall = crate::util::now_unix();
    let mut data = b"\xef\xbb\xbf# ext\tcontact\n".to_vec();
    data.extend(state_line("101", 5001, wall + 600, wall).as_bytes());
    // Invalid UTF-8 loses only this row, not the entire file.
    data.extend(
        state_line("102", 5002, wall + 600, wall)
            .replace("ua", "u\u{1}a")
            .as_bytes(),
    );
    let n = data.len() - 3;
    data[n] = 0xff;
    data.extend(b"garbage\n\n");
    data.extend(
        state_line("103", 5003, wall + 600, wall)
            .replace("127.0.0.1:5003\t", "nowhere\t")
            .as_bytes(),
    );
    data.extend(
        state_line("104", 5004, wall + 600, wall)
            .replace("\n", "\textra\tfields\r\n")
            .as_bytes(),
    );
    std::fs::write(&path, &data).unwrap();
    crate::util::test_log::start();
    let mut r = Registrar::new(Some(path.clone()), 3600);
    let exts: Vec<String> = r.all().into_iter().map(|(e, _)| e).collect();
    assert_eq!(exts, ["101", "104"]);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        data,
        "loading (`status`) never writes"
    );
    assert_eq!(crate::util::test_log::take().len(), 1, "one warning for the file");
    // The next save replaces the cache with valid rows, without backup/repair.
    r.update(
        "101",
        "sip:101@127.0.0.1:5001",
        "",
        addr(5001),
        600,
        "call-5001",
        2,
        "ua",
    );
    r.save();
    let saved = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        saved.lines().filter(|l| !l.starts_with('#')).count(),
        2,
        "{saved}"
    );
    assert_eq!(Registrar::new(Some(path), 3600).all().len(), 2);
    assert!(!dir.join("bindings.txt.bad").exists());
}

#[test]
fn unreadable_cache_does_not_prevent_in_memory_registration() {
    let dir = crate::util::TestDir::create();
    let path = dir.join("bindings.txt");
    // Something that exists but can't be read as a file (works as root too).
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("inside"), "x").unwrap();
    let mut r = Registrar::new(Some(path.clone()), 3600);
    assert!(r.all().is_empty());
    r.update("101", "sip:101@phone", "", addr(5001), 600, "call", 1, "ua");
    r.save();
    assert_eq!(std::fs::read_to_string(path.join("inside")).unwrap(), "x");
    assert_eq!(r.all().len(), 1);
    assert!(!dir.join("bindings.txt.tmp").exists());
}

#[test]
fn failed_save_leaves_no_temporary_file_and_keeps_the_old_one() {
    let dir = crate::util::TestDir::create();
    let path = dir.join("bindings.txt");
    let tmp = dir.join("bindings.txt.tmp");
    let mut r = Registrar::new(Some(path.clone()), 3600);
    r.update("101", "sip:101@phone", "", addr(5001), 600, "call", 1, "ua");
    r.save();
    let before = std::fs::read(&path).unwrap();
    assert!(!tmp.exists());
    // A full disk: writing the temporary file fails with ENOSPC.
    if std::os::unix::fs::symlink("/dev/full", &tmp).is_ok() && std::path::Path::new("/dev/full").exists() {
        r.update("102", "sip:102@phone", "", addr(5002), 600, "call", 1, "ua");
        r.save();
        assert!(
            std::fs::symlink_metadata(&tmp).is_err(),
            "temporary file left behind"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // ... and the next save works again.
        r.save();
        assert_eq!(Registrar::new(Some(path), 3600).all().len(), 2);
    }
}

#[test]
fn state_file_round_trip_survives_separators_in_values() {
    let dir = crate::util::TestDir::create();
    let path = dir.join("bindings.txt");
    let mut r = Registrar::new(Some(path.clone()), 3600);
    r.update(
        "101",
        "sip:101@phone",
        ";x=\"a\tb\"",
        addr(5060),
        600,
        "cid\twith tab",
        7,
        "UA\twith\ttabs\r\n",
    );
    r.update("102", "sip:102@phone", "", addr(5061), 600, "c2", 1, "ua");
    r.save();
    let r2 = Registrar::new(Some(path), 3600);
    let b = r2.lookup("101").expect("binding with tabs in its values lost");
    assert_eq!(
        (
            b.params.as_str(),
            b.call_id.as_str(),
            b.cseq,
            b.user_agent.as_str()
        ),
        (";x=\"a b\"", "cid with tab", 7, "UA with tabs  ")
    );
    assert_eq!(r2.lookup("102").unwrap().call_id, "c2");
}
