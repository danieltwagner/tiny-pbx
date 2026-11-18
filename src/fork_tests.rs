//! Focused cleanup regressions. Timer tests use one clock origin and exact
//! deadlines; the socket test also exercises the proxy's BYE response dispatch.

use super::*;
use crate::config::Config;
use crate::proxy::Pbx;
use std::net::UdpSocket;

fn invite(uri: &str, via: &str) -> Message {
    Message::parse(
        format!(
            "INVITE {uri} SIP/2.0\r\nVia: SIP/2.0/UDP {via}\r\n\
         From: <sip:101@pbx>;tag=caller\r\nTo: <sip:100@pbx>\r\n\
         Call-ID: cleanup\r\nCSeq: 7 INVITE\r\nMax-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap()
}

/// Our address the caller's INVITE arrived on, and the ones phone i
/// registered to: everything to them must leave from those.
const CALLER_LOCAL: &str = "127.0.0.9";

fn phone_local(i: usize) -> std::net::IpAddr {
    format!("127.0.0.{}", 10 + i).parse().unwrap()
}

fn fork(now: Instant) -> Fork {
    let caller = invite("sip:100@pbx", "127.0.0.1:5101;branch=z9hG4bK-caller");
    let targets = (0..2)
        .map(|i| {
            let branch = format!("z9hG4bK-pbx-test{i}");
            let mut m = caller.clone();
            m.set_uri(format!("sip:{}@127.0.0.1:{}", 102 + i, 5102 + i));
            m.insert_top("Via", format!("SIP/2.0/UDP 127.0.0.1:5060;branch={branch}"), true);
            Target {
                branch,
                invite: m,
                dst: format!("127.0.0.1:{}", 5102 + i).parse().unwrap(),
                local: Some(phone_local(i)),
                ext: format!("{}", 102 + i),
                who: format!("phone{i}"),
            }
        })
        .collect();
    Fork::new(
        key_of(&caller).unwrap(),
        caller,
        "127.0.0.1:5101".parse().unwrap(),
        "127.0.0.1".parse().unwrap(),
        Some(CALLER_LOCAL.parse().unwrap()),
        "local".into(),
        "cleanup".into(),
        targets,
        now,
    )
    .0
}

fn response(f: &Fork, i: usize, code: u16) -> Message {
    let mut r = f.branches[i].t.invite.make_response(code, "X", Some("phone"));
    r.set("Contact", format!("<{}>", f.branches[i].t.invite.uri()));
    r
}

fn caller_ack(f: &mut Fork, now: Instant) {
    let mut ack = f.invite.clone();
    ack.start = request("ACK", ack.uri());
    ack.set("CSeq", "7 ACK".into());
    assert!(f.on_caller(&ack, f.caller, now).is_empty());
}

/// Phone 0 rejected, phone 1 was silent, caller got and ACKed the failure.
/// Timer B has now expired; the fork is in its original linger period.
fn failed_fork(now: Instant) -> Fork {
    let mut f = fork(now);
    let r = response(&f, 0, 486);
    f.on_response(0, r, now + Duration::from_secs(1));
    let out = f.tick(now + DEAD_AFTER);
    assert!(out.iter().any(|o| o.msg.code() == 486 && o.dst == f.caller));
    caller_ack(&mut f, now + DEAD_AFTER);
    assert!(matches!(f.branches[1].cancel, Cancel::Wanted));
    assert!(f.tick(now + TIMER_B).is_empty(), "no INVITE retry at Timer B");
    assert_eq!(f.branches[1].state, State::TimedOut);
    assert!(matches!(f.branches[1].cancel, Cancel::Wanted));
    assert_eq!(f.quiet_since, Some(now + TIMER_B));
    f
}

fn only_method(out: &[Out], method: &str) {
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].msg.method(), method);
}

fn assert_retry(out: &[Out], initial: &Out) {
    only_method(out, initial.msg.method());
    assert_eq!(out[0].msg.to_bytes(), initial.msg.to_bytes());
    assert_eq!(out[0].dst, initial.dst);
}

fn assert_linger(f: &mut Fork, quiet: Instant) {
    assert_eq!(f.quiet_since, Some(quiet));
    assert_eq!(f.next_deadline(quiet), quiet + LINGER);
    assert!(!f.finished(quiet + LINGER - Duration::from_nanos(1)));
    assert!(f.tick(quiet + LINGER).is_empty());
    assert!(f.finished(quiet + LINGER));
    // This is the same removal/deadline contract used by Pbx::tick.
    let active = [f].into_iter().filter(|f| !f.finished(quiet + LINGER));
    assert_eq!(active.map(|f| f.next_deadline(quiet + LINGER)).min(), None);
}

#[test]
fn challenges_in_mixed_fork_failures() {
    for (challenge, other, single_extension, expected) in [
        (401, 480, false, 401),
        (407, 486, false, 407),
        (401, 603, false, 401),
        (401, 603, true, 603),  // one extension's decline is final
        (407, 302, false, 302), // redirect still wins
    ] {
        let header = if challenge == 401 {
            "WWW-Authenticate"
        } else {
            "Proxy-Authenticate"
        };
        let value = "Digest realm=\"phone\", nonce=\"n\"";
        for order in [[0, 1], [1, 0]] {
            let now = Instant::now();
            let mut f = fork(now);
            if single_extension {
                f.branches[1].t.ext = f.branches[0].t.ext.clone();
            }
            let mut finals = Vec::new();
            for i in order {
                let mut r = response(&f, i, if i == 0 { challenge } else { other });
                if i == 0 {
                    r.set(header, value.into());
                }
                finals.extend(f.on_response(i, r, now).into_iter().filter(|o| o.dst == f.caller));
            }
            assert_eq!(finals.len(), 1);
            let r = &finals[0].msg;
            assert_eq!(r.code(), expected, "{challenge} vs {other}, order {order:?}");
            assert_eq!(r.hdr(header), (expected == challenge).then_some(value));
        }
    }
}

#[test]
fn only_generated_acks_copy_outbound_branch_credentials() {
    let now = Instant::now();
    let mut f = fork(now);
    // The PBX's own realm was present in the incoming INVITE but stripped
    // before forwarding. Only the credentials actually sent to a phone belong in its ACK.
    f.invite.set("Proxy-Authorization", "Digest realm=\"pbx\"".into());
    for (i, b) in f.branches.iter_mut().enumerate() {
        b.t.invite
            .set("Authorization", format!("Digest realm=\"phone{i}\""));
        for realm in ["p1", "p2"] {
            b.t.invite
                .insert_top("Proxy-Authorization", format!("Digest realm=\"{realm}\""), false);
        }
    }
    let busy = response(&f, 0, 486);
    let out = f.on_response(0, busy, now);
    only_method(&out, "ACK");
    let neg_ack = &out[0].msg;

    // Caller got the failure while branch 1 was still silent; late ringing
    // and then a racing answer trigger CANCEL, followed by ACK and BYE.
    let late = now + DEAD_AFTER;
    f.tick(late);
    let ringing = response(&f, 1, 180);
    let cancel = f.on_response(1, ringing, late);
    only_method(&cancel, "CANCEL");
    let ok = response(&f, 1, 200);
    let cleanup = f.on_response(1, ok, late);
    assert_eq!(cleanup.len(), 2);
    assert_eq!((cleanup[0].msg.method(), cleanup[1].msg.method()), ("ACK", "BYE"));
    for name in ["Authorization", "Proxy-Authorization"] {
        for (i, ack) in [neg_ack, &cleanup[0].msg].into_iter().enumerate() {
            assert_eq!(
                ack.hdrs(name).collect::<Vec<_>>(),
                f.branches[i].t.invite.hdrs(name).collect::<Vec<_>>(),
            );
        }
        assert!(cancel[0].msg.hdr(name).is_none());
        assert!(cleanup[1].msg.hdr(name).is_none());
    }
}

#[test]
fn dropped_bye_retries_same_transaction_and_duplicate_200_only_gets_ack() {
    let origin = Instant::now();
    let mut f = failed_fork(origin);
    let start = origin + TIMER_B + LINGER - Duration::from_secs(1);
    let ok = response(&f, 1, 200);
    let out = f.on_response(1, ok.clone(), start);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].msg.method(), "ACK");
    let bye = &out[1];
    assert_eq!(bye.msg.method(), "BYE");
    assert_eq!(bye.msg.cseq(), Some((8, "BYE".into())));
    assert_ne!(
        bye.msg.top_via().unwrap().branch(),
        f.branches[1].t.invite.top_via().unwrap().branch()
    );
    assert_eq!(f.quiet_since, None);
    assert_eq!(f.next_deadline(start), start + T1);
    only_method(&f.on_response(1, ok, start + T1 / 2), "ACK");
    assert_eq!(
        f.next_deadline(start),
        start + T1,
        "200 must not reset retry timer"
    );
    for millis in [500, 1500, 3500, 7500, 11500] {
        let at = start + Duration::from_millis(millis);
        assert_retry(&f.tick(at), bye);
        assert!(f.next_deadline(at) > at, "no overdue timer spin");
    }
    assert!(
        !f.finished(origin + TIMER_B + LINGER),
        "old linger cannot reap BYE"
    );
    assert!(f.finished(origin + MAX_AGE), "hard lifetime cap still applies");
}

#[test]
fn bye_final_response_completes_and_duplicate_answers_do_not_restart_it() {
    for code in [200, 481] {
        let origin = Instant::now();
        let mut f = failed_fork(origin);
        let start = origin + TIMER_B + Duration::from_secs(1);
        let ok = response(&f, 1, 200);
        let out = f.on_response(1, ok.clone(), start);
        let bye = &out[1];
        let branch = bye.msg.top_via().unwrap();
        assert_eq!(f.hangup_branch_index(branch.branch().unwrap()), Some(1));
        assert_retry(&f.tick(start + T1), bye); // first BYE was dropped
        let done = start + Duration::from_secs(1);
        let final_response = bye.msg.make_response(code, "X", Some("phone"));
        assert!(f.on_hangup_response(1, &final_response, done).is_empty());
        assert!(f.branches[1].bye.is_none());
        only_method(&f.on_response(1, ok, done + T1), "ACK");
        assert!(f.tick(done + T2).is_empty());
        assert_linger(&mut f, done);
    }
}

#[test]
fn bye_provisional_or_unrelated_final_does_not_complete_transaction() {
    let origin = Instant::now();
    let mut f = failed_fork(origin);
    let start = origin + TIMER_B + Duration::from_secs(1);
    let ok = response(&f, 1, 200);
    let out = f.on_response(1, ok, start);
    let bye = &out[1];
    let mut unrelated = bye.msg.make_response(200, "OK", None);
    unrelated.set("CSeq", "7 INVITE".into());
    f.on_hangup_response(1, &unrelated, start);
    let trying = bye.msg.make_response(100, "Trying", None);
    f.on_hangup_response(1, &trying, start + T1 / 2);
    assert_retry(&f.tick(start + T1), bye);
    let next = start + T1 + T2;
    f.on_hangup_response(1, &trying, next - T1);
    assert_eq!(
        f.next_deadline(start),
        next,
        "duplicate 1xx must not postpone retry"
    );
    assert_retry(&f.tick(next), bye);
    assert!(f.tick(start + TIMER_B).is_empty());
    assert_linger(&mut f, start + TIMER_B);
}

#[test]
fn bye_timeout_is_bounded_even_with_repeated_late_answers() {
    let origin = Instant::now();
    let mut f = failed_fork(origin);
    let start = origin + TIMER_B + Duration::from_secs(1);
    let ok = response(&f, 1, 200);
    let out = f.on_response(1, ok.clone(), start);
    let bye = &out[1];
    let timeout = start + TIMER_B;
    let mut next = f.next_deadline(start);
    while next < timeout {
        only_method(&f.on_response(1, ok.clone(), next), "ACK");
        assert_retry(&f.tick(next), bye);
        let after = f.next_deadline(next);
        assert!(after > next);
        next = after;
    }
    assert_eq!(next, timeout);
    assert!(f.tick(timeout).is_empty());
    only_method(&f.on_response(1, ok, timeout + T1), "ACK");
    assert!(
        f.branches[1].bye.is_none(),
        "late 200 must not restart timed-out BYE"
    );
    assert_linger(&mut f, timeout);
}

#[test]
fn late_100_after_timer_b_starts_retried_cancel_and_invite_final_stops_it() {
    let origin = Instant::now();
    let mut f = failed_fork(origin);
    let start = origin + TIMER_B + LINGER - Duration::from_secs(1);
    let trying = response(&f, 1, 100);
    let out = f.on_response(1, trying, start);
    only_method(&out, "CANCEL");
    let cancel = &out[0];
    assert_eq!(cancel.msg.uri(), f.branches[1].t.invite.uri());
    assert_eq!(
        cancel.msg.top_via().unwrap().branch(),
        Some(f.branches[1].t.branch.as_str())
    );
    assert_eq!(cancel.msg.cseq(), Some((7, "CANCEL".into())));
    assert!(cancel.msg.hdr("Reason").is_none());
    assert_eq!(f.quiet_since, None);
    assert_retry(&f.tick(start + T1), cancel); // drop first CANCEL
    let ringing = response(&f, 1, 180);
    assert!(f
        .on_response(1, ringing, start + Duration::from_secs(1))
        .is_empty());
    assert_retry(&f.tick(start + T1 * 3), cancel);
    assert!(!f.finished(origin + TIMER_B + LINGER));
    let done = start + Duration::from_secs(2);
    let terminated = response(&f, 1, 487);
    only_method(&f.on_response(1, terminated, done), "ACK");
    assert!(matches!(f.branches[1].cancel, Cancel::Done));
    assert_linger(&mut f, done);
}

#[test]
fn late_cancel_provisional_and_final_responses_are_processed() {
    for code in [200, 481] {
        let origin = Instant::now();
        let mut f = failed_fork(origin);
        let start = origin + TIMER_B + Duration::from_secs(1);
        let ringing = response(&f, 1, 180);
        let out = f.on_response(1, ringing.clone(), start);
        only_method(&out, "CANCEL");
        let cancel = &out[0];
        f.on_response(1, cancel.msg.make_response(100, "Trying", None), start);
        assert_retry(&f.tick(start + T1), cancel);
        assert_eq!(f.next_deadline(start), start + T1 + T2);
        let done = start + Duration::from_secs(1);
        assert!(f
            .on_response(1, cancel.msg.make_response(code, "X", None), done)
            .is_empty());
        assert!(f.on_response(1, ringing, done + T1).is_empty());
        assert!(f.tick(done + T2).is_empty());
        assert_linger(&mut f, done);
    }
}

#[test]
fn late_cancel_timeout_is_not_extended_or_restarted_by_provisionals() {
    let origin = Instant::now();
    let mut f = failed_fork(origin);
    let start = origin + TIMER_B + Duration::from_secs(1);
    let ringing = response(&f, 1, 180);
    let out = f.on_response(1, ringing.clone(), start);
    only_method(&out, "CANCEL");
    let timeout = start + TIMER_B;
    let mut next = f.next_deadline(start);
    while next < timeout {
        assert!(f.on_response(1, ringing.clone(), next).is_empty());
        assert_retry(&f.tick(next), &out[0]);
        let after = f.next_deadline(next);
        assert!(after > next);
        next = after;
    }
    assert_eq!(next, timeout);
    assert!(f.tick(timeout).is_empty());
    assert!(f.on_response(1, ringing, timeout + T1).is_empty());
    assert_linger(&mut f, timeout);
}

#[test]
fn late_cancel_answer_race_preserves_successful_fork_and_elsewhere_reason() {
    let origin = Instant::now();
    let mut f = fork(origin);
    let winner = response(&f, 0, 200);
    f.on_response(0, winner, origin + Duration::from_secs(1));
    assert!(f.tick(origin + TIMER_B).is_empty());
    let start = origin + TIMER_B + Duration::from_secs(1);
    let trying = response(&f, 1, 100);
    let out = f.on_response(1, trying, start);
    only_method(&out, "CANCEL");
    assert_eq!(out[0].msg.hdr("Reason"), Some(ELSEWHERE));
    let racing = response(&f, 1, 200);
    let done = start + T1;
    let out = f.on_response(1, racing, done);
    assert_eq!(out.len(), 1);
    assert_eq!((out[0].msg.code(), out[0].dst), (200, f.caller));
    assert!(f.branches[1].bye.is_none(), "caller owns this successful dialog");
    assert_linger(&mut f, done);
}

#[test]
fn late_cancel_answer_after_failure_switches_to_bye_cleanup() {
    let origin = Instant::now();
    let mut f = failed_fork(origin);
    let start = origin + TIMER_B + Duration::from_secs(1);
    let trying = response(&f, 1, 100);
    only_method(&f.on_response(1, trying, start), "CANCEL");
    let ok = response(&f, 1, 200);
    let out = f.on_response(1, ok, start + T1);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].msg.method(), "ACK");
    assert_eq!(out[1].msg.method(), "BYE");
    assert_retry(&f.tick(start + T1 * 2), &out[1]);
    assert!(matches!(f.branches[1].cancel, Cancel::Done));
}

#[test]
fn hangup_goes_to_the_branch_address_whatever_the_contact_says() {
    // security review: the ACK + BYE for a late 2xx used to go to any
    // literal host:port in the phone's Contact, so a phone could aim PBX
    // traffic at another host. The Contact is only the Request-URI.
    let origin = Instant::now();
    let mut f = fork(origin);
    let t = &mut f.branches[1].t;
    let mapped = t.dst;
    for (registered, contact) in [
        ("sip:103@10.0.0.7", "sip:dialog@10.0.0.7:5060;transport=udp"),
        ("sip:103@127.0.0.1:5103", "sip:dialog@127.0.0.1:5103"),
        ("sip:103@10.0.0.7:5060", "sip:dialog@127.0.0.1:5199"),
        ("sip:103@127.0.0.1:5103", "sip:dialog@192.0.2.1:5060"),
        ("sip:103@10.0.0.7", "sip:dialog@[::1]:5199"),
        ("sip:103@phone.invalid", "sip:dialog@other.invalid"),
    ] {
        t.invite.set_uri(registered.into());
        let mut ok = t.invite.make_response(200, "OK", Some("phone"));
        ok.set("Contact", format!("<{contact}>"));
        for out in hang_up(t, &ok) {
            assert_eq!(out.dst, mapped, "{registered} -> {contact}");
            assert_eq!(out.msg.uri(), contact);
        }
    }
    let ok = t.invite.make_response(200, "OK", Some("phone"));
    for out in hang_up(t, &ok) {
        assert_eq!(out.dst, mapped);
        assert_eq!(out.msg.uri(), t.invite.uri(), "no Contact: the INVITE's R-URI");
    }
}

#[test]
fn hangup_cseq_does_not_overflow() {
    let origin = Instant::now();
    let mut f = fork(origin);
    let t = &mut f.branches[1].t;
    t.invite.set("CSeq", format!("{} INVITE", u32::MAX));
    let ok = t.invite.make_response(200, "OK", Some("phone"));
    let [ack, bye] = hang_up(t, &ok);
    assert_eq!(ack.msg.cseq(), Some((u32::MAX, "ACK".into())));
    assert_eq!(bye.msg.cseq(), Some((u32::MAX, "BYE".into())));
}

#[test]
fn fork_branches_are_unique_and_distinct_from_stateless_branches() {
    let a = branch_id();
    let b = branch_id();
    assert_ne!(a, b);
    assert!(a.starts_with("z9hG4bK-pbx-fork-"));
    assert!(b.starts_with("z9hG4bK-pbx-fork-"));
}

#[test]
fn hangup_ack_answers_an_offer_in_the_2xx() {
    // The caller's INVITE had no SDP (delayed offer), so the late 2xx
    // carries an offer and our ACK must carry an answer (RFC 3261
    // 13.2.2.4): every stream declined.
    let origin = Instant::now();
    let mut f = fork(origin);
    let t = &mut f.branches[1].t;
    let mut ok = t.invite.make_response(200, "OK", Some("phone"));
    ok.set("Content-Type", "application/sdp".into());
    ok.body = b"v=0\r\no=- 1 1 IN IP4 192.0.2.9\r\ns=-\r\nc=IN IP4 192.0.2.9\r\nt=0 0\r\n\
        m=audio 4000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\nm=video 4002 RTP/SAVP 96\r\n"
        .to_vec();
    let [ack, bye] = hang_up(t, &ok);
    let sdp = String::from_utf8(ack.msg.body.clone()).unwrap();
    assert_eq!(ack.msg.hdr("Content-Type"), Some("application/sdp"));
    let m: Vec<&str> = sdp.lines().filter(|l| l.starts_with("m=")).collect();
    assert_eq!(m, ["m=audio 0 RTP/AVP 0", "m=video 0 RTP/SAVP 96"]);
    assert!(sdp.starts_with("v=0\r\n") && sdp.contains("\r\nt=0 0\r\n"));
    assert!(bye.msg.body.is_empty() && bye.msg.hdr("Content-Type").is_none());
    // with an offer in the INVITE, the 2xx had the answer: ACK without body
    t.invite.body = b"v=0\r\n".to_vec();
    t.invite.set("Content-Type", "application/sdp".into());
    let [ack, _] = hang_up(t, &ok);
    assert!(ack.msg.body.is_empty() && ack.msg.hdr("Content-Type").is_none());
}

#[test]
fn second_answer_during_linger_extends_it() {
    // A second phone answering while the fork lingers gets its 2xx passed
    // on; the fork must then stay for that phone's 2xx retransmissions
    // (otherwise they would be dropped as responses to a forgotten call).
    let origin = Instant::now();
    let mut f = fork(origin);
    let first = response(&f, 0, 200);
    f.on_response(0, first, origin + Duration::from_secs(1));
    assert!(f.tick(origin + TIMER_B).is_empty()); // silent phone 1 given up
    assert_eq!(f.quiet_since, Some(origin + TIMER_B));
    let late = origin + TIMER_B + LINGER - Duration::from_secs(2);
    let second = response(&f, 1, 200);
    let out = f.on_response(1, second.clone(), late);
    assert_eq!((out.len(), out[0].msg.code(), out[0].dst), (1, 200, f.caller));
    assert!(!f.finished(origin + TIMER_B + LINGER));
    assert!(!f.finished(late + LINGER - Duration::from_nanos(1)));
    // its retransmission doesn't extend it any further
    f.on_response(1, second, late + T1);
    assert!(f.finished(late + LINGER));
}

fn socket() -> UdpSocket {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    s
}

fn recv(s: &UdpSocket) -> Option<Message> {
    let mut buf = [0; 65536];
    s.recv_from(&mut buf)
        .ok()
        .map(|(n, _)| Message::parse(&buf[..n]).unwrap())
}

#[test]
fn proxy_hangs_up_at_the_branch_address_and_consumes_bye_responses() {
    // Whether the 2xx's Contact names another listener or the registered
    // one behind a source-address mapping: ACK + BYE go to where the INVITE
    // went, with the Contact as Request-URI.
    for distinct in [true, false] {
        let server = socket();
        let (caller, a, b, dialog) = (socket(), socket(), socket(), socket());
        let mut cfg = Config::parse("[extensions]\n101=p\n102=p\n103=p\n[groups]\n100=102 103\n").unwrap();
        cfg.listen = server.local_addr().unwrap();
        cfg.state_file = None;
        let mut pbx = Pbx::new(cfg, server);
        for (ext, phone) in [("101", &caller), ("102", &a), ("103", &b)] {
            let ad = phone.local_addr().unwrap();
            let contact = if ext == "103" {
                "sip:103@10.0.0.7:5060".to_string()
            } else {
                format!("sip:{ext}@{ad}")
            };
            pbx.reg.update(ext, &contact, "", ad, 3600, ext, 1, "test");
        }
        let req = invite(
            "sip:100@pbx",
            &format!("{};branch=z9hG4bK-caller;rport", caller.local_addr().unwrap()),
        );
        pbx.handle(&req.to_bytes(), caller.local_addr().unwrap());
        assert_eq!(recv(&caller).unwrap().code(), 100);
        let ia = recv(&a).unwrap();
        let ib = recv(&b).unwrap();
        for (phone, inv) in [(&a, &ia), (&b, &ib)] {
            pbx.handle(
                &inv.make_response(486, "Busy", Some("phone")).to_bytes(),
                phone.local_addr().unwrap(),
            );
            assert_eq!(recv(phone).unwrap().method(), "ACK");
        }
        assert_eq!(recv(&caller).unwrap().code(), 486);
        let mut ack = req.clone();
        ack.start = request("ACK", req.uri());
        ack.set("CSeq", "7 ACK".into());
        pbx.handle(&ack.to_bytes(), caller.local_addr().unwrap());
        let contact = if distinct {
            format!("sip:dialog@{}", dialog.local_addr().unwrap())
        } else {
            "sip:dialog@10.0.0.7:5060;transport=udp".to_string()
        };
        let mut ok = ib.make_response(200, "OK", Some("phone"));
        ok.set("Contact", format!("<{contact}>"));
        pbx.handle(&ok.to_bytes(), b.local_addr().unwrap());
        let dst = &b;
        assert_eq!(recv(dst).unwrap().method(), "ACK");
        let bye = recv(dst).unwrap();
        assert_eq!((bye.method(), bye.uri()), ("BYE", contact.as_str()));
        assert!(recv(&dialog).is_none(), "nothing to the host in the Contact");
        assert!(recv(&caller).is_none());
        // Provisional BYE response must be dispatched, but not stop retries.
        pbx.handle(
            &bye.make_response(100, "Trying", None).to_bytes(),
            dst.local_addr().unwrap(),
        );
        pbx.tick(pbx.next_deadline(Instant::now()).unwrap());
        assert_eq!(recv(dst).unwrap().to_bytes(), bye.to_bytes());
        pbx.handle(
            &bye.make_response(200, "OK", None).to_bytes(),
            dst.local_addr().unwrap(),
        );
        pbx.handle(&ok.to_bytes(), b.local_addr().unwrap());
        assert_eq!(recv(dst).unwrap().method(), "ACK");
        pbx.tick(Instant::now() + T2);
        assert!(
            recv(dst).is_none(),
            "BYE final must stop timer; duplicate 200 must not restart it"
        );
        pbx.tick(Instant::now() + LINGER + Duration::from_secs(1));
        assert_eq!(
            pbx.next_deadline(Instant::now()),
            None,
            "idle returns to zero wakeups"
        );
    }
}

// Keep the randomized simulator separate from these focused regressions.
#[path = "fork_stress_tests.rs"]
mod stress;
