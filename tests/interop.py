#!/usr/bin/env python3
"""Interop test suite for the pbx: pjsua phones + sipp scenarios on loopback.

Usage: tests/interop.py [--slow] [--serial] [--host 127.0.0.2] [--port 5060]
                        [--only NAME[,NAME...]]

Ring-group / forking tests live in groups.py and run alongside (in a second
thread, --serial: afterwards) against a second PBX instance (--group-host,
default 127.0.0.4:5060) with their own phones. --slow adds the tests that
wait for real protocol timers or generate load.

Runs the PBX binary (target/debug/tiny-pbx, built with cargo, or $PBX_BIN) on
127.0.0.2:5060 (phones use 127.0.0.1, so PBX and phones have different IPs
and plain port-less URIs like sip:102@127.0.0.2 are exercised), starts
three pjsua "phones" (101, 102, 103) and runs every test
in order; later tests rely on earlier ones (registrations), so --only is
meant for debugging. Logs of every process end up in tests/out/loopback/.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
import re
import sys
import traceback
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import groups
from harness import (
    HERE,
    MEDIA_SECS,
    Fail,
    Pbx,
    Pjsua,
    RawUA,
    Suite,
    check,
    check_tone,
    digest_header,
    find_bin,
    first_line,
    fresh_dir,
    header,
    run_sipp,
    quit_all,
    select_tests,
    sipp_error_text,
    udp_bound,
    wait_until,
    write_tone,
)

# "Nothing else must arrive" windows. Loopback latency is sub-millisecond;
# a retransmission (T1) would come after 0.5 s, so windows that are meant to
# catch one end 0.65 s after the message that would be retransmitted.
QUIET = 0.3
RETX_WINDOW = 0.65

TONE_A = 1000  # played by 101 (and 105)
TONE_B = 440  # played by 102 and 103

PASSWORDS = {"101": "pw101", "102": "pw102", "103": "pw103", "104": "pw104", "105": "pw105"}


class Env:
    def __init__(self, args):
        self.port = args.port
        self.host = args.host
        self.out = fresh_dir(os.path.join(HERE, "out", "loopback"))
        self.bin = find_bin()
        write_tone(os.path.join(self.out, "tone_a.wav"), TONE_A)
        write_tone(os.path.join(self.out, "tone_b.wav"), TONE_B)
        conf = (
            "listen = %s:%d\nrealm = pbx\n[extensions]\n" % (self.host, self.port)
            + "".join("%s = %s\n" % kv for kv in sorted(PASSWORDS.items()))
            + "[groups]\n110 = 104 105\n"  # the two lines of t_multi_line's phone
        )
        self.pbx = Pbx(self.bin, self.out, conf)
        self.uas = {}
        self.retired = []
        self.seg = 0
        self.g = groups.GroupEnv(self.out, self.bin, args.group_host)

    def phone(self, name, ext, port, password=None, **kw):
        kw.setdefault("pbx_host", self.host)
        kw.setdefault("pbx_port", self.port)
        kw.setdefault("bound_addr", "127.0.0.1")
        ua = Pjsua(name, self.out, ext, password or PASSWORDS[ext], port, 4000 + (port % 100) * 20, **kw)
        self.uas[name] = ua
        return ua

    def tone_check(self, ua, start, want, other):
        self.seg += 1
        path = os.path.join(self.out, "seg%02d_%s.wav" % (self.seg, ua.name))
        ua.rec_segment(start, path)
        return check_tone(path, want, other)

    def sipp(self, scenario, local_port, extra=(), **kw):
        return run_sipp(
            self.out,
            os.path.join(HERE, "sipp", scenario) if scenario else None,
            "%s:%d" % (self.host, self.port),
            local_port,
            extra=extra,
            **kw
        )

    def retire(self, name):
        ua = self.uas.pop(name)
        ua.retire()
        self.retired.append(ua)

    def close(self):
        quit_all(list(self.uas.values()) + self.retired + self.g.thaw())
        self.pbx.stop()
        self.g.pbx.stop()


# ---------------------------------------------------------------- helpers


def pkts(env, since, direction=None, peer=None, first=None, contains=None):
    """PBX log packets so far (after a sync barrier, so nothing is missing
    that the PBX did before now)."""
    env.pbx.sync()
    return env.pbx.find(since, direction, peer, first, contains)


def wait_pkts(env, since, direction=None, peer=None, first=None, contains=None, n=1, timeout=3.0, what=None):
    return env.pbx.wait(since, n, timeout, what, direction=direction, peer=peer, first=first, contains=contains)


def addr(port):
    return "127.0.0.1:%d" % port


def connect_call(env, caller, callee, ext, answer=True):
    """caller dials ext, callee (manual answer) answers; returns marks."""
    mc, me = caller.mark(), callee.mark()
    caller.call(ext)
    callee.expect(r"Incoming call for account", 5, me, "incoming call")
    callee.answer(180)  # pjsua does not ring by itself; real phones do
    caller.expect(r"Call \d+ state changed to EARLY", 5, mc, "caller EARLY (180)")
    if answer:
        callee.answer(200)
        caller.expect(r"Call \d+ state changed to CONFIRMED", 5, mc, "caller CONFIRMED")
        callee.expect(r"Call \d+ state changed to CONFIRMED", 5, me, "callee CONFIRMED")
    return mc, me


def hear(env, checks):
    """checks: [(ua, start, want, other)]: wait until each recorder has
    MEDIA_SECS of audio since `start`, then check the tones."""
    for ua, start, _, _ in checks:
        ua.wait_recorded(start, MEDIA_SECS)
    return [env.tone_check(ua, start, want, other) for ua, start, want, other in checks]


def media_both_ways(env, a, b):
    """Both phones play their tone into the call; check each hears the other."""
    a.play_into_calls()
    b.play_into_calls()
    ra, rb = a.rec_mark(), b.rec_mark()
    return hear(env, [(a, ra, TONE_B, TONE_A), (b, rb, TONE_A, TONE_B)])


def wait_disconnected(ua, since, reason=None, timeout=5):
    m = ua.expect(r"Call \d+ is DISCONNECTED \[reason=(\d+) \(([^)]*)\)\]", timeout, since, "DISCONNECTED")
    if reason is not None:
        check(int(m.group(1)) == reason, "%s: disconnected with %s %s, expected %d" % (ua.name, m.group(1), m.group(2), reason))
    return m


def idle(*uas):
    """Make sure no call is left over on these phones."""
    for ua in uas:
        ua.hangup_all()


# ---------------------------------------------------------------- tests


def t_register(env):
    p0 = env.pbx.log.mark()
    u101 = env.phone("u101", "101", 5091, play=os.path.join(env.out, "tone_a.wav"), rec=os.path.join(env.out, "rec101.wav"))
    u102 = env.phone("u102", "102", 5092, play=os.path.join(env.out, "tone_b.wav"), rec=os.path.join(env.out, "rec102.wav"))
    u103 = env.phone(
        "u103",
        "103",
        5093,
        auto_answer=200,
        play=os.path.join(env.out, "tone_b.wav"),
        rec=os.path.join(env.out, "rec103.wav"),
    )
    for ua in (u101, u102, u103):
        ua.wait_registered()
    for port in (5091, 5092, 5093):
        codes = [fl.split()[1] for _, _, fl, _ in pkts(env, p0, ">>>", addr(port), r"^SIP/2.0", r"CSeq: \d+ REGISTER")]
        check(codes[:2] == ["401", "200"], "port %d: REGISTER responses %s, expected 401 then 200" % (port, codes))
    st = env.pbx.status()
    for ext in ("101", "102", "103"):
        check(re.search(r"^%s\s+127\.0\.0\.1:50" % ext, st, re.M), "pbx status does not list %s:\n%s" % (ext, st))
    return "401->200 for 101,102,103; 'pbx status' ok"


def t_call_caller_hangup(env):
    a, b = env.uas["u101"], env.uas["u102"]
    p0 = env.pbx.log.mark()
    mc, me = connect_call(env, a, b, "102")
    inv = pkts(env, p0, ">>>", addr(5092), r"^INVITE ")
    check(inv, "INVITE not forwarded to 102")
    check("Record-Route: <sip:%s:%d;lr;pbx-dialog=" % (env.host, env.port) in inv[0][3], "no dialog Record-Route in forwarded INVITE")
    check(re.search(r"^INVITE sip:102@127\.0\.0\.1:5092", inv[0][2]), "R-URI not rewritten to contact: %s" % inv[0][2])
    ringing = pkts(env, p0, ">>>", addr(5091), r"^SIP/2.0 180")
    check(ringing, "180 Ringing not relayed to the caller")
    detail = media_both_ways(env, a, b)
    a.hangup()
    wait_disconnected(a, mc, 200)
    wait_disconnected(b, me, 200)
    bye = pkts(env, p0, ">>>", addr(5092), r"^BYE ")
    check(bye, "BYE did not go through the PBX")
    return "; ".join(detail)


def t_call_callee_hangup(env):
    a, b = env.uas["u101"], env.uas["u102"]
    p0 = env.pbx.log.mark()
    mc, me = connect_call(env, a, b, "102")
    b.hangup()
    wait_disconnected(b, me, 200)
    wait_disconnected(a, mc, 200)
    check(pkts(env, p0, ">>>", addr(5091), r"^BYE "), "callee's BYE not relayed to the caller")
    wait_pkts(env, p0, ">>>", addr(5092), r"^SIP/2.0 200", r"CSeq: \d+ BYE", what="200 for BYE relayed back")
    return "BYE 102 -> PBX -> 101"


def t_busy(env):
    a, b = env.uas["u101"], env.uas["u102"]
    p0 = env.pbx.log.mark()
    mc, me = connect_call(env, a, b, "102", answer=False)
    b.answer(486)
    wait_disconnected(a, mc, 486)
    t486 = time.time()
    wait_pkts(env, p0, ">>>", addr(5092), r"^ACK ", what="ACK for 486 forwarded to 102")
    time.sleep(max(0, t486 + RETX_WINDOW - time.time()))  # 102 would retransmit after T1
    n486 = pkts(env, p0, "<<<", addr(5092), r"^SIP/2.0 486")
    check(len(n486) == 1, "102 sent 486 %d times (ACK not delivered?)" % len(n486))
    return "486 relayed, ACK forwarded hop-by-hop, no retransmissions"


def t_not_registered(env):
    a = env.uas["u101"]
    mc = a.mark()
    a.call("104")
    wait_disconnected(a, mc, 480)
    return "480"


def t_unknown_extension(env):
    a = env.uas["u101"]
    p0 = env.pbx.log.mark()
    mc = a.mark()
    a.call("999")
    wait_disconnected(a, mc, 404)
    wait_pkts(env, p0, "<<<", addr(5091), r"^ACK ", what="caller's ACK for the 404")
    time.sleep(QUIET)
    incoming = pkts(env, p0, "<<<", addr(5091), r"^INVITE sip:999@")
    check(incoming, "no INVITE to the unknown extension")
    call_id = re.search(r"(?m)^Call-ID: (.+)$", incoming[0][3]).group(1)
    sent = pkts(env, p0, ">>>", contains=r"(?m)^Call-ID: " + re.escape(call_id) + r"$")
    check(len(sent) == 1, "PBX sent %d packets for the unknown call, expected just the 404: %s" % (len(sent), [s[2] for s in sent]))
    return "404, ACK absorbed"


def t_cancel(env):
    a, b = env.uas["u101"], env.uas["u102"]
    p0 = env.pbx.log.mark()
    mc, me = connect_call(env, a, b, "102", answer=False)
    a.hangup()
    wait_disconnected(b, me, 487)
    t487 = time.time()
    wait_disconnected(a, mc, 487)
    inv = pkts(env, p0, ">>>", addr(5092), r"^INVITE ")
    can = pkts(env, p0, ">>>", addr(5092), r"^CANCEL ")
    check(can, "CANCEL not forwarded")
    br = lambda t: re.search(r"branch=(z9hG4bK-pbx-[0-9a-f]+)", t).group(1)  # noqa: E731
    check(br(inv[0][3]) == br(can[0][3]), "CANCEL branch differs from INVITE branch")
    wait_pkts(env, p0, ">>>", addr(5092), r"^ACK ", what="ACK for 487 forwarded to 102")
    time.sleep(max(0, t487 + RETX_WINDOW - time.time()))
    n487 = pkts(env, p0, "<<<", addr(5092), r"^SIP/2.0 487")
    check(len(n487) == 1, "102 sent 487 %d times (ACK not delivered?)" % len(n487))
    return "CANCEL (same branch) -> 200 + 487 -> ACK"


def t_wrong_password(env):
    p0 = env.pbx.log.mark()
    ua = env.phone("u104bad", "104", 5096, password="wrong")
    try:
        ua.expect(r"registration failed, status=403|SIP registration failed, status=403", 5, 0, "403")
        time.sleep(RETX_WINDOW)  # a phone stuck in a retry loop would be back at once
        regs = pkts(env, p0, "<<<", addr(5096), r"^REGISTER ")
        check(len(regs) <= 2, "phone kept trying: %d REGISTERs" % len(regs))
        check(not env.pbx.status().count("127.0.0.1:5096"), "binding created despite wrong password")
        return "403 after %d REGISTERs, phone stopped" % len(regs)
    finally:
        env.retire("u104bad")


def t_hold_resume(env):
    a, b = env.uas["u101"], env.uas["u102"]
    p0 = env.pbx.log.mark()
    mc, me = connect_call(env, a, b, "102")
    m1, m2 = a.mark(), b.mark()
    a.send("H")
    a.expect(r"status is Local hold", 5, m1, "local hold")
    b.expect(r"status is Remote hold", 5, m2, "remote hold")
    check(pkts(env, p0, ">>>", addr(5092), r"^INVITE ", r"a=sendonly"), "hold re-INVITE (sendonly) not relayed")
    m1, m2 = a.mark(), b.mark()
    a.send("v")
    a.expect(r"status is Active", 5, m1, "resumed (caller)")
    b.expect(r"status is Active", 5, m2, "resumed (callee)")
    p1 = env.pbx.log.mark()
    b.send("U")
    wait_pkts(env, p1, ">>>", addr(5091), r"^UPDATE ", what="UPDATE from 102 relayed")
    wait_pkts(env, p1, ">>>", addr(5092), r"^SIP/2.0 200", r"CSeq: \d+ UPDATE", what="200 for UPDATE relayed")
    detail = media_both_ways(env, a, b)
    a.hangup()
    wait_disconnected(a, mc, 200)
    wait_disconnected(b, me, 200)
    return "hold/resume re-INVITEs, UPDATE; after resume: " + "; ".join(detail)


def t_message(env):
    a, b = env.uas["u101"], env.uas["u102"]
    p0 = env.pbx.log.mark()
    mb = b.mark()
    a.send("i", a.uri("102"), "hello from 101")
    b.expect(r"MESSAGE from .*101.*: hello from 101", 5, mb, "MESSAGE at 102")
    wait_pkts(env, p0, ">>>", addr(5091), r"^SIP/2.0 200", r"CSeq: \d+ MESSAGE", what="200 for MESSAGE relayed to 101")
    # and to an extension that is offline
    p1 = env.pbx.log.mark()
    a.send("i", a.uri("104"), "anyone?")
    wait_pkts(env, p1, ">>>", addr(5091), r"^SIP/2.0 480", r"CSeq: \d+ MESSAGE", what="480 for MESSAGE to offline 104")
    return "delivered + 200; offline -> 480"


def t_transfer(env):
    a, b, c = env.uas["u101"], env.uas["u102"], env.uas["u103"]
    p0 = env.pbx.log.mark()
    mc, me = connect_call(env, a, b, "102")
    first = a.expect(r"Call (\d+) state changed to CONFIRMED", 1, mc).group(1)
    mt = c.mark()
    b.send("x", b.uri("103"))
    b.expect(r"call transferred successfully", 8, me, "transfer success at 102")
    wait_disconnected(b, me)
    a.expect(r"is being transferred to", 5, mc, "REFER received by 101")
    a.expect(r"Call (?!%s )\d+ state changed to CONFIRMED" % first, 5, mc, "101's new call CONFIRMED")
    c.expect(r"Call \d+ state changed to CONFIRMED", 5, mt, "103 answered")
    check(pkts(env, p0, ">>>", addr(5091), r"^REFER "), "REFER not relayed 102 -> 101")
    check(pkts(env, p0, ">>>", addr(5092), r"^NOTIFY "), "NOTIFY not relayed 101 -> 102")
    check(pkts(env, p0, ">>>", addr(5093), r"^INVITE "), "new INVITE to 103 not forwarded")
    a.expect(r"Call %s is DISCONNECTED" % first, 5, mc, "101's call with 102 ended")
    a.play_into_calls()
    ra, rc = a.rec_mark(), c.rec_mark()
    detail = hear(env, [(a, ra, TONE_B, TONE_A), (c, rc, TONE_A, TONE_B)])
    m1 = a.mark()
    a.send("ha")
    wait_disconnected(c, mt, 200)
    wait_disconnected(a, m1)
    return "REFER/NOTIFY via PBX, 101<->103 media: " + "; ".join(detail)


def t_early_media_dtmf(env):
    """183 with SDP (early media), then DTMF via SIP INFO and RFC 2833."""
    a, b = env.uas["u101"], env.uas["u102"]
    p0 = env.pbx.log.mark()
    mc, me = a.mark(), b.mark()
    a.call("102")
    b.expect(r"Incoming call for account", 5, me, "incoming call")
    b.answer(183)
    a.expect(r"state changed to EARLY \(183", 5, mc, "caller EARLY (183)")
    a.expect(r"status is Active", 5, mc, "early media active")
    b.play_into_calls()
    ra = a.rec_mark()
    detail = hear(env, [(a, ra, TONE_B, TONE_A)])[0]
    b.answer(200)
    a.expect(r"Call \d+ state changed to CONFIRMED", 5, mc)
    m2 = b.mark()
    a.send("*", "123")
    for d in "123":
        b.expect(r"Incoming DTMF on call \d+: %s.*SIP INFO" % d, 5, m2, "INFO DTMF %s" % d)
    a.send("#", "45")
    for d in "45":
        b.expect(r"Incoming DTMF on call \d+: %s.*RFC2833" % d, 5, m2, "RFC2833 DTMF %s" % d)
    check(pkts(env, p0, ">>>", addr(5092), r"^INFO "), "INFO not relayed")
    a.hangup()
    wait_disconnected(b, me, 200)
    return "early media %s; DTMF INFO 123 + RFC2833 45 received" % detail


def t_attended_transfer(env):
    """102 talks to 101, consults 103, then joins them (REFER with Replaces)."""
    a, b, c = env.uas["u101"], env.uas["u102"], env.uas["u103"]
    p0 = env.pbx.log.mark()
    mc, me = connect_call(env, a, b, "102")
    first = a.expect(r"Call (\d+) state changed to CONFIRMED", 1, mc).group(1)
    b.send("H")
    b.expect(r"status is Local hold", 5, me, "102 holds 101")
    mt, m2 = c.mark(), b.mark()
    b.call("103")
    b.expect(r"Call \d+ state changed to CONFIRMED", 5, m2, "102 <-> 103 (consultation)")
    c.expect(r"Call \d+ state changed to CONFIRMED", 5, mt)
    m3 = b.mark()
    b.send("X")
    m = b.expect(r"^\s*(\d+)\s+\S*sip:101@", 3, m3, "call list for X")
    b.send(m.group(1))
    b.expect(r"call transferred successfully", 8, m3, "transfer success at 102")
    c.expect(r"Making call .*Replaces=", 5, mt, "103 got REFER with Replaces")
    a.expect(r"Call \d+ is DISCONNECTED", 5, mc, "101's call with 102 replaced")
    invs = pkts(env, p0, ">>>", addr(5091), r"^INVITE ", r"(?m)^Replaces:")
    check(invs, "INVITE with Replaces was not routed via the PBX to 101")
    a.expect(r"Call (?!%s )\d+ state changed to CONFIRMED" % first, 5, mc, "101's call with 103 up")
    a.play_into_calls()
    ra, rc = a.rec_mark(), c.rec_mark()
    detail = hear(env, [(a, ra, TONE_B, TONE_A), (c, rc, TONE_A, TONE_B)])
    m4 = c.mark()
    a.send("ha")
    c.expect(r"Call \d+ is DISCONNECTED", 5, m4, "103 hung up")
    return "INVITE/Replaces via PBX, 101<->103: " + "; ".join(detail)


def t_unauthenticated_caller(env):
    """A phone that never registered must answer a 407 challenge."""
    b = env.uas["u102"]
    p0 = env.pbx.log.mark()
    ua = env.phone("u105", "105", 5097, register=False, play=os.path.join(env.out, "tone_a.wav"), rec=os.path.join(env.out, "rec105.wav"))
    try:
        mc, me = connect_call(env, ua, b, "102")
        codes = [fl.split()[1] for _, _, fl, _ in pkts(env, p0, ">>>", addr(5097), r"^SIP/2.0", r"CSeq: \d+ INVITE")]
        check(codes and codes[0] == "407", "first INVITE response %s, expected 407" % codes[:1])
        inv = pkts(env, p0, ">>>", addr(5092), r"^INVITE ")
        check(inv and "Proxy-Authorization" not in inv[0][3], "credentials leaked to the callee")
        ua.hangup()
        wait_disconnected(b, me, 200)
        # and the callee hangs up on the unregistered caller (BYE to a contact
        # the PBX knows nothing about)
        mc, me = connect_call(env, ua, b, "102")
        b.hangup()
        wait_disconnected(ua, mc, 200)
        check(pkts(env, p0, ">>>", addr(5097), r"^BYE "), "BYE to the unregistered caller not relayed")
        bad = env.phone("u105bad", "105", 5098, password="nope", register=False)
        try:
            m = bad.mark()
            bad.call("102")
            wait_disconnected(bad, m, 403)
        finally:
            env.retire("u105bad")
        return "407 -> authenticated call ok, hangup either side; wrong password -> 403"
    finally:
        env.retire("u105")


def t_sipp_register(env):
    # The scenario repeats the CSeq itself. Otherwise SIPp can treat the
    # second identical 200 as a retransmission and keep sending REGISTERs.
    rc = env.sipp("register_compact.xml", 5094, extra=["-nr"], name="sipp_register")
    check(rc == 0, "sipp failed (rc=%s): %s" % (rc, sipp_error_text(env.out, "sipp_register")))
    check(re.search(r"^104\s+127\.0\.0\.1:5094", env.pbx.status(), re.M), "104 not registered")
    return "compact headers, no rport, repeated REGISTER CSeq"


def t_sipp_uas(env):
    a = env.uas["u101"]
    p = env.sipp("uas_104.xml", 5094, extra=["-mp", "6100", "-rtp_echo"], name="sipp_uas", background=True, timeout=40)
    try:
        wait_until(lambda: udp_bound("127.0.0.1", 5094), 5, "sipp UAS listening on 5094")
        mc = a.mark()
        a.call("104")
        a.expect(r"Call \d+ state changed to CONFIRMED", 5, mc, "101 CONFIRMED with sipp")
        a.play_into_calls()
        ra = a.rec_mark()
        detail = hear(env, [(a, ra, TONE_A, TONE_B)])[0]  # sipp echoes our own tone
        a.hangup()
        wait_disconnected(a, mc, 200)
        rc = p.wait(15)
        check(rc == 0, "sipp UAS failed (rc=%s): %s" % (rc, sipp_error_text(env.out, "sipp_uas")))
        return "INVITE checks ok, echo: " + detail
    finally:
        if p.poll() is None:
            p.kill()


def t_sipp_uac(env):
    b = env.uas["u102"]
    p0 = env.pbx.log.mark()
    me = b.mark()
    p = env.sipp("uac_compact.xml", 5094, extra=["-mp", "6200"], name="sipp_uac", background=True, timeout=40)
    try:
        b.expect(r"Incoming call for account", 5, me, "incoming call at 102")
        b.answer(180)
        b.answer(200)
        rc = p.wait(20)
        check(rc == 0, "sipp UAC failed (rc=%s): %s" % (rc, sipp_error_text(env.out, "sipp_uac")))
        wait_disconnected(b, me, 200)
        invs = pkts(env, p0, ">>>", addr(5092), r"^INVITE ")
        check(len(invs) == 2, "expected the INVITE retransmission to be forwarded too, got %d" % len(invs))
        br = [re.search(r"branch=(z9hG4bK-pbx-[0-9a-f]+)", t).group(1) for _, _, _, t in invs]
        check(br[0] == br[1], "retransmission forwarded with a different branch")
        n200 = pkts(env, p0, "<<<", addr(5092), r"^SIP/2.0 200", r"CSeq: 1 INVITE")
        return "compact+multi-Via ok, retransmission same branch, 483 for Max-Forwards 0 (%d x 200 from 102)" % len(n200)
    finally:
        if p.poll() is None:
            p.kill()


def t_sipp_cancel(env):
    b = env.uas["u102"]
    p0 = env.pbx.log.mark()
    me = b.mark()
    p = env.sipp("cancel_407.xml", 5095, extra=["-mp", "6300"], name="sipp_cancel", timeout=20, background=True)
    try:
        b.expect(r"Incoming call for account", 5, me, "incoming call at 102")
        b.answer(180)
        rc = p.wait(20)
    finally:
        if p.poll() is None:
            p.kill()
    check(rc == 0, "sipp failed (rc=%s): %s" % (rc, sipp_error_text(env.out, "sipp_cancel")))
    wait_disconnected(b, me, 487)
    acks = pkts(env, p0, ">>>", None, r"^ACK ")
    check(len(acks) == 1, "expected exactly one forwarded ACK (for the 487), got %d" % len(acks))
    return "407 ACK absorbed, CANCEL -> 487"


def t_sipp_misc(env):
    p0 = env.pbx.log.mark()
    rc = env.sipp("misc.xml", 5095, name="sipp_misc", timeout=20)
    check(rc == 0, "sipp failed (rc=%s): %s" % (rc, sipp_error_text(env.out, "sipp_misc")))
    fwd = [fl for _, p, fl, _ in pkts(env, p0, ">>>") if p != addr(5095)]
    check(not fwd, "PBX forwarded something: %s" % fwd)
    return "OPTIONS 200, SUBSCRIBE 489, 420, unknown number 407 -> 404, spoofed From 403, foreign REGISTER 403"


def t_sipp_load(env):
    """100 calls at 20 calls/s between two sipp instances (built-in uac/uas
    scenarios, which ignore Record-Route and send ACK/BYE to the PBX with
    the dialled number as R-URI)."""
    uri = "sip:%s:%d" % (env.host, env.port)
    for port, ext in ((5094, "104"), (5095, "105")):
        raw = RawUA(("127.0.0.1", port), (env.host, env.port))
        try:
            cid = "load-%s-%d" % (ext, os.getpid())
            r = raw.register(ext, 300, cseq=1, call_id=cid)
            auth = digest_header("Authorization", header(r, "WWW-Authenticate"), "REGISTER", uri, ext, PASSWORDS[ext])
            r = raw.register(ext, 300, cseq=2, call_id=cid, auth=auth)
            check(first_line(r).startswith("SIP/2.0 200"), "register %s: %s" % (ext, first_line(r)))
        finally:
            raw.close()
    uas = run_sipp(env.out, None, None, 5094, extra=["-sn", "uas", "-m", "100"], name="sipp_load_uas", background=True, timeout=60)
    try:
        wait_until(lambda: udp_bound("127.0.0.1", 5094), 5, "sipp UAS listening on 5094")
        t0 = time.time()
        rc = env.sipp(None, 5095, extra=["-sn", "uac", "-s", "104", "-r", "20", "-m", "100", "-l", "50"], name="sipp_load_uac", timeout=60)
        secs = time.time() - t0
        check(rc == 0, "sipp uac failed (rc=%s): %s" % (rc, sipp_error_text(env.out, "sipp_load_uac")))
        rc2 = uas.wait(20)
        check(rc2 == 0, "sipp uas failed (rc=%s): %s" % (rc2, sipp_error_text(env.out, "sipp_load_uas")))
    finally:
        if uas.poll() is None:
            uas.kill()
    cpu = env.pbx.cpu_ticks()
    raw = RawUA(("127.0.0.1", 5095), (env.host, env.port))
    try:  # drop 105's binding again
        cid = "load-105-%d" % os.getpid()
        r = raw.register("105", 0, cseq=3, call_id=cid)
        auth = digest_header("Authorization", header(r, "WWW-Authenticate"), "REGISTER", uri, "105", PASSWORDS["105"])
        r = raw.register("105", 0, cseq=4, call_id=cid, auth=auth)
        check(first_line(r).startswith("SIP/2.0 200"), "unregister 105: %s" % first_line(r))
    finally:
        raw.close()
    return "100/100 calls in %.1fs; PBX CPU so far %.2fs" % (secs, cpu / 100.0)


def t_multihome(env):
    """PBX listening on 0.0.0.0, phones using two of its addresses
    (127.0.0.2 and 127.0.0.3, like the LAN and voice-VLAN addresses of one
    host): each phone only ever hears from the address it registered to --
    replies, calls from the other phone, its BYEs and MESSAGEs -- as phones
    set to accept SIP from their server only require. Calls between the two
    get a double Record-Route."""
    port = 5080
    d = fresh_dir(os.path.join(env.out, "multihome"))
    conf = "listen = 0.0.0.0:%d\nrealm = pbx\n[extensions]\n101 = pw101\n102 = pw102\n" % port
    p = Pbx(env.bin, d, conf, name="pbx-multihome")
    p.start()
    names = []
    try:
        uas = {}
        for name, ext, sip_port, host in (("m101", "101", 5081, "127.0.0.2"), ("m102", "102", 5082, "127.0.0.3")):
            uas[ext] = env.phone(name, ext, sip_port, pbx_host=host, pbx_port=port)
            names.append(name)
        a, b = uas["101"], uas["102"]
        a.wait_registered()
        b.wait_registered()
        p0 = p.log.mark()
        for caller, callee, ext in ((a, b, "102"), (b, a, "101")):
            mc, me = connect_call(env, caller, callee, ext)
            callee.hangup()
            wait_disconnected(callee, me, 200)
            wait_disconnected(caller, mc, 200)
        mb = b.mark()
        a.send("i", a.uri("102"), "hello from 101")
        b.expect(r"MESSAGE from .*101.*: hello from 101", 5, mb, "MESSAGE at 102")
        p.sync()
        inv = p.find(p0, ">>>", addr(5082), r"^INVITE ")
        check(inv, "no INVITE to 102")
        rr = re.findall(r"(?m)^Record-Route: <sip:([0-9.]+):%d;" % port, inv[0][3])
        check(rr == ["127.0.0.3", "127.0.0.2"], "INVITE to 102: Record-Route %s, expected 127.0.0.3 then 127.0.0.2" % rr)
        via = re.search(r"(?m)^Via: SIP/2.0/UDP ([0-9.]+):%d;" % port, inv[0][3])
        check(via and via.group(1) == "127.0.0.3", "INVITE to 102: top Via %s" % (via and via.group(1)))
        res = []
        for name, host in (("m101", "127.0.0.2"), ("m102", "127.0.0.3")):
            with open(os.path.join(env.out, name + ".sip.log"), errors="replace") as f:
                rx = re.findall(r"RX \d+ bytes (Request msg \w+|Response msg \d+)/.* from UDP ([0-9.]+):%d:" % port, f.read())
            wrong = sorted({"%s from %s" % (what, ip) for what, ip in rx if ip != host})
            check(rx and not wrong, "%s (registered to %s) got %s" % (name, host, ", ".join(wrong) or "nothing"))
            res.append("%s: %d packets, all from %s" % (name, len(rx), host))
        return "; ".join(res) + "; double Record-Route"
    finally:
        for name in names:
            env.retire(name)
        p.stop()


def t_allow_filter(env):
    """`allow` CIDR list: packets from other networks are ignored."""
    import socket

    res = []
    for allow, answered in (("10.0.0.0/8, 192.168.0.0/16", False), ("127.0.0.1/32", True)):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.3", 0))
        port = probe.getsockname()[1]
        probe.close()
        d = fresh_dir(os.path.join(env.out, "allow"))
        p = Pbx(env.bin, d, "listen = 127.0.0.3:%d\nallow = %s\n[extensions]\n101 = x\n" % (port, allow), name="pbx-allow")
        p.start()
        raw = RawUA(("127.0.0.1", 0), ("127.0.0.3", port))
        try:
            local_port = raw.s.getsockname()[1]
            raw.send(
                "OPTIONS sip:127.0.0.3:%d SIP/2.0\nVia: SIP/2.0/UDP 127.0.0.1:%d;rport;branch=z9hG4bK-allow-%d\n"
                "From: <sip:101@127.0.0.3>;tag=a\nTo: <sip:127.0.0.3>\nCall-ID: allow-%d\nCSeq: 1 OPTIONS\n"
                "Max-Forwards: 70\n" % (port, local_port, os.getpid(), os.getpid())
            )
            r = raw.recv(1.0 if answered else QUIET)
        finally:
            raw.close()
            p.stop()
        check(bool(r) == answered, "allow=%s: %s" % (allow, first_line(r)))
        res.append("%s -> %s" % (allow, first_line(r) if r else "ignored"))
    return "; ".join(res)


def t_sipp_unregister(env):
    """Unregister sipp's 104 with a hand-made REGISTER (Contact: *)."""
    ua = RawUA(("127.0.0.1", 5094), (env.host, env.port))
    try:
        cid = "unreg-%d" % os.getpid()
        r = ua.register("104", 0, cseq=1, call_id=cid, contact="*")
        check(first_line(r).startswith("SIP/2.0 401"), "expected 401: %s" % first_line(r))
        uri = "sip:%s:%d" % (env.host, env.port)
        auth = digest_header("Authorization", header(r, "WWW-Authenticate"), "REGISTER", uri, "104", PASSWORDS["104"])
        r = ua.register("104", 0, auth=auth, cseq=2, call_id=cid, contact="*")
        check(first_line(r).startswith("SIP/2.0 200"), "expected 200: %s" % first_line(r))
        check(header(r, "Contact") is None, "200 still lists contacts")
    finally:
        ua.close()
    check(not re.search(r"^104\s+127", env.pbx.status(), re.M), "104 still registered")
    return "Contact: * / Expires: 0 -> 200, binding gone"


def t_multi_line(env):
    """One phone, two lines (104 and 105) registered from the same port, like
    the handsets of a DECT base: group 110 = 104 105 rings both, and one
    calling the group rings the other."""
    b = env.uas["u102"]
    p0 = env.pbx.log.mark()
    pbx = b.pbx  # host, or host:port with --port
    ua = env.phone(
        "u45",
        "104",
        5098,
        extra=[
            "--next-account",
            "--id=sip:105@%s" % pbx,
            "--registrar=sip:%s" % pbx,
            "--realm=*",
            "--username=105",
            "--password=%s" % PASSWORDS["105"],
        ],
    )
    try:
        ua.expect(r"sip:104@.*registration success", 5, 0, "104 registered")
        ua.expect(r"sip:105@.*registration success", 5, 0, "105 registered")
        mc, me = connect_call(env, ua, b, "102")  # from the current account, 105
        check(env.pbx.log.grep(r"call 105 -> 102", p0), "call was not from line 105")
        codes = [fl.split()[1] for _, _, fl, _ in pkts(env, p0, ">>>", addr(5098), r"^SIP/2.0", r"CSeq: \d+ INVITE")]
        check("407" not in codes, "second line was challenged: %s" % codes)
        ua.hangup()
        wait_disconnected(b, me, 200)
        for line, ext in (("1", "104"), ("2", "105")):
            mu, mb = ua.mark(), b.mark()
            b.call(ext)
            ua.expect(r"Incoming call for account %s" % line, 5, mu, "call to %s on line %s" % (ext, line))
            ua.answer(200)
            b.expect(r"state changed to CONFIRMED", 5, mb)
            b.hangup()
            wait_disconnected(ua, mu, 200)
        mu = ua.mark()
        ua.call("104")  # current account 105 calls its sibling on the same socket
        ua.expect(r"Incoming call for account 1", 5, mu, "105 -> 104 on one socket")
        ua.hangup_all()
        # group 110 = 104 105: an INVITE for each line. pjsua (one SIP stack
        # for both) rings on one and refuses the other as a merged request
        # (482, RFC 3261 8.2.2.2); a phone with a UA per line rings on both.
        p1, mu, mb = env.pbx.log.mark(), ua.mark(), b.mark()
        b.call("110")
        ua.expect(r"Incoming call for account", 5, mu, "group 110 rings the phone")
        wait_pkts(env, p1, "<<<", addr(5098), r"^SIP/2.0 [1-6]\d\d", r"CSeq: \d+ INVITE", n=2, what="both lines answered")
        invited = sorted(fl.split()[1] for _, _, fl, _ in pkts(env, p1, ">>>", addr(5098), r"^INVITE "))
        check([u.split(";")[0] for u in invited] == ["sip:104@127.0.0.1:5098", "sip:105@127.0.0.1:5098"], "group 110 INVITEs: %s" % invited)
        merged = len(pkts(env, p1, "<<<", addr(5098), r"^SIP/2.0 482"))
        b.hangup()
        wait_disconnected(b, mb)
        check(not pkts(env, p1, ">>>", addr(5092), r"^SIP/2.0 482"), "the caller got 482")
        ua.hangup_all()
        # line 105 calls the group: its sibling 104 rings, 105 itself doesn't
        p2, mu = env.pbx.log.mark(), ua.mark()
        ua.call("110")
        ua.expect(r"Incoming call for account 1", 5, mu, "105 -> group 110 rings 104")
        invited = [fl.split()[1] for _, _, fl, _ in pkts(env, p2, ">>>", addr(5098), r"^INVITE ")]
        check([u.split(";")[0] for u in invited] == ["sip:104@127.0.0.1:5098"], "105 -> 110 INVITEs: %s" % invited)
        ua.hangup_all()
        return "both lines registered from one port; calls to each line and between lines ok; group of both: " + (
            "INVITE to each, one refused as merged request (482)" if merged else "both rang"
        )
    finally:
        env.retire("u45")


def t_outbound_proxy_domain(env):
    """Phone configured with a SIP domain (a host name the PBX has never heard
    of) plus an outbound proxy, i.e. a preloaded Route."""
    b = env.uas["u102"]
    p0 = env.pbx.log.mark()
    ua = env.phone("u105d", "105", 5097, pbx_host="pbx.test", proxy="sip:%s:%d;lr" % (env.host, env.port))
    try:
        ua.wait_registered()
        reg = pkts(env, p0, "<<<", addr(5097), r"^REGISTER sip:pbx.test")
        check(reg and re.search(r"^Route:", reg[0][3], re.M), "REGISTER did not come with a Route to the proxy")
        mc, me = connect_call(env, ua, b, "102")
        inv = pkts(env, p0, ">>>", addr(5092), r"^INVITE ")
        check(inv and not re.search(r"^Route:", inv[-1][3], re.M), "preloaded Route not removed")
        ua.hangup()
        wait_disconnected(b, me, 200)
        mu, mb = ua.mark(), b.mark()
        b.call("105")
        ua.expect(r"Incoming call for account", 5, mu)
        ua.answer(200)
        b.expect(r"state changed to CONFIRMED", 5, mb)
        b.hangup()
        wait_disconnected(ua, mu, 200)
        return "REGISTER sip:pbx.test via Route; calls both ways"
    finally:
        env.retire("u105d")


def t_100rel(env):
    """Callee that requires reliable provisional responses (PRACK)."""
    a = env.uas["u101"]
    p0 = env.pbx.log.mark()
    ua = env.phone("u104rel", "104", 5100, extra=["--use-100rel"])
    try:
        ua.wait_registered()
        mc, me = connect_call(env, a, ua, "104")
        check(pkts(env, p0, ">>>", addr(5100), r"^PRACK "), "PRACK not relayed to the callee")
        check(pkts(env, p0, ">>>", addr(5091), r"^SIP/2.0 180", r"RSeq:"), "reliable 180 not relayed")
        a.hangup()
        wait_disconnected(ua, me, 200)
        return "reliable 180 -> PRACK -> 200, call ok"
    finally:
        env.retire("u104rel")


def t_unregister(env):
    c, a = env.uas["u103"], env.uas["u101"]
    m = c.mark()
    c.send("ru")
    c.expect(r"unregistration success|registration success, status=200 \(OK\), will re-register in 0", 5, m, "unregistration")
    check(not re.search(r"^103\s+127", env.pbx.status(), re.M), "103 still in 'pbx status'")
    mc = a.mark()
    a.call("103")
    wait_disconnected(a, mc, 480)
    m = c.mark()
    c.send("rr")
    c.wait_registered(m)
    mc, mt = a.mark(), c.mark()
    a.call("103")
    c.expect(r"Call \d+ state changed to CONFIRMED", 5, mt, "103 answered after re-register")
    a.expect(r"Call \d+ state changed to CONFIRMED", 5, mc)
    a.hangup()
    wait_disconnected(c, mt, 200)
    return "unregistered -> 480; re-registered -> call ok"


def t_restart(env):
    a, b = env.uas["u101"], env.uas["u102"]
    # a phone that caches the nonce (many hardware phones do; pjsua doesn't)
    raw = RawUA(("127.0.0.1", 5099), (env.host, env.port))
    uri = "sip:%s:%d" % (env.host, env.port)
    cid = "stale-%d" % os.getpid()
    r = raw.register("104", 300, cseq=1, call_id=cid)
    check(first_line(r).startswith("SIP/2.0 401"), "expected 401: %s" % first_line(r))
    chal = header(r, "WWW-Authenticate")
    r = raw.register("104", 300, cseq=2, call_id=cid, auth=digest_header("Authorization", chal, "REGISTER", uri, "104", PASSWORDS["104"]))
    check(first_line(r).startswith("SIP/2.0 200"), "expected 200: %s" % first_line(r))
    # a call that is up while the PBX restarts
    mc, me = connect_call(env, a, b, "102")
    env.pbx.stop()
    env.pbx.start()
    p0 = env.pbx.log.mark()
    wait_until(lambda: len(env.pbx.log.grep(r"still registered from .*\(restored\)")) >= 3, 3, "3 restored bindings")
    m1 = a.mark()
    b.send("v")  # re-INVITE through the new process
    a.expect(r"received updated media offer|status is Active", 5, m1, "re-INVITE after restart")
    a.hangup()
    wait_disconnected(a, mc, 200)
    wait_disconnected(b, me, 200)
    check(pkts(env, p0, ">>>", addr(5092), r"^BYE "), "BYE after restart not relayed")
    mc, me = connect_call(env, a, b, "102")
    detail = media_both_ways(env, a, b)
    b.hangup()
    wait_disconnected(a, mc, 200)
    # re-registration: the phone's cached nonce is from the old process
    m = a.mark()
    a.send("rr")
    a.wait_registered(m)
    codes = []
    for _, _, fl, t in pkts(env, p0, ">>>", addr(5091), r"^SIP/2.0", r"CSeq: \d+ REGISTER"):
        codes.append(fl.split()[1] + (" stale" if "stale=true" in t else ""))
    check(codes and codes[-1] == "200", "re-REGISTER responses %s" % codes)
    # old nonce, right password -> 401 stale=true (not 403), then 200
    try:
        r = raw.register("104", 300, cseq=3, call_id=cid, auth=digest_header("Authorization", chal, "REGISTER", uri, "104", PASSWORDS["104"], nc=2))
        check(first_line(r).startswith("SIP/2.0 401"), "old nonce: expected 401, got %s" % first_line(r))
        chal2 = header(r, "WWW-Authenticate")
        check("stale=true" in chal2, "old nonce: 401 without stale=true: %s" % chal2)
        r = raw.register("104", 300, cseq=4, call_id=cid, auth=digest_header("Authorization", chal2, "REGISTER", uri, "104", PASSWORDS["104"]))
        check(first_line(r).startswith("SIP/2.0 200"), "fresh nonce: expected 200: %s" % first_line(r))
        # an old nonce says nothing about the password: 401 stale=true for a
        # wrong one too (no password oracle); with a fresh nonce it is a 403
        r = raw.register("104", 300, cseq=5, call_id=cid, auth=digest_header("Authorization", chal, "REGISTER", uri, "104", "wrong", nc=3))
        check(first_line(r).startswith("SIP/2.0 401"), "old nonce + wrong password: %s" % first_line(r))
        check("stale=true" in header(r, "WWW-Authenticate"), "old nonce + wrong password: 401 without stale=true")
        r = raw.register("104", 300, cseq=6, call_id=cid, auth=digest_header("Authorization", chal2, "REGISTER", uri, "104", "wrong", nc=2))
        check(first_line(r).startswith("SIP/2.0 403"), "fresh nonce + wrong password: %s" % first_line(r))
        r = raw.register("104", 0, cseq=7, call_id=cid, auth=digest_header("Authorization", chal2, "REGISTER", uri, "104", PASSWORDS["104"], nc=3))
        check(first_line(r).startswith("SIP/2.0 200"), "unregister: %s" % first_line(r))
    finally:
        raw.close()
    return "call survived restart; new call without re-registering ok (%s); pjsua re-REGISTER: %s; cached old nonce -> 401 stale=true -> 200; wrong password: 401 stale (old nonce), 403 (fresh)" % (
        "; ".join(detail),
        " -> ".join(codes),
    )


def t_direct_contact_unregister(env):
    b = env.uas["u102"]
    ua = env.phone("u104direct", "104", 5110, proxy="sip:%s:%d;lr" % (env.host, env.port))
    try:
        ua.wait_registered()
        mc, me = ua.mark(), b.mark()
        p0 = env.pbx.log.mark()
        ua.send("m", "sip:102@127.0.0.1:5092")
        b.expect(r"Incoming call for account", 5, me)
        b.answer(180)
        ua.expect(r"state changed to EARLY", 5, mc)
        m = b.mark()
        b.send("ru")
        b.expect(r"unregistration success", 5, m)
        ua.hangup()
        wait_disconnected(ua, mc)
        wait_disconnected(b, me)
        check(pkts(env, p0, ">>>", addr(5092), r"^CANCEL "), "CANCEL lost after Contact unregistered")
        return "direct-Contact INVITE -> unregister -> CANCEL/487/ACK at the original phone"
    finally:
        m = b.mark()
        b.send("rr")
        b.wait_registered(m)
        env.retire("u104direct")


def t_restart_ringing(env):
    a, b = env.uas["u101"], env.uas["u102"]
    for answer in (True, False):
        mc, me = connect_call(env, a, b, "102", answer=False)
        env.pbx.stop()
        env.pbx.start()
        p0 = env.pbx.log.mark()
        if answer:
            b.answer(200)
            a.expect(r"state changed to CONFIRMED", 5, mc)
            b.expect(r"state changed to CONFIRMED", 5, me)
            a.hangup()
        else:
            a.hangup()
        wait_disconnected(a, mc)
        wait_disconnected(b, me)
        check(not env.pbx.log.grep(r"branch doesn't match", p0), "old transaction branch rejected after restart")
    return "restart between 180 and answer/cancellation: both transactions complete"


def t_dialog_unregister(env):
    a, b = env.uas["u101"], env.uas["u102"]
    for restart in (False, True):
        try:
            mc, me = connect_call(env, a, b, "102")
            for ua in (a, b):
                m = ua.mark()
                ua.send("ru")
                ua.expect(r"unregistration success", 5, m)
            if restart:
                env.pbx.stop()
                env.pbx.start()
            p0 = env.pbx.log.mark()
            a.hangup()
            wait_disconnected(a, mc, 200)
            wait_disconnected(b, me, 200)
            check(pkts(env, p0, ">>>", addr(5092), r"^BYE "), "BYE lost after both registrations removed")
        finally:
            for ua in (a, b):
                m = ua.mark()
                ua.send("rr")
                ua.wait_registered(m)
    return "BYE succeeds after both unregister, with and without a PBX restart"


def t_idle_cpu(env):
    """The PBX must not wake up while nothing happens: with every phone
    frozen (no keep-alives), not a single wakeup or CPU tick for 3 s."""
    import signal

    phones = [ua for ua in list(env.uas.values()) + env.retired if ua.proc.poll() is None]
    for ua in phones:  # freeze them: no keep-alives during the measurement
        os.kill(ua.proc.pid, signal.SIGSTOP)
    pid = env.pbx.proc.pid

    def ctxt():
        with open("/proc/%d/status" % pid) as f:
            for l in f:
                if l.startswith("voluntary_ctxt_switches"):
                    return int(l.split()[1])
        return 0

    try:
        time.sleep(0.05)  # packets already in flight
        t0, c0 = env.pbx.cpu_ticks(), ctxt()
        time.sleep(3)
        t1, c1 = env.pbx.cpu_ticks(), ctxt()
    finally:
        for ua in phones:
            os.kill(ua.proc.pid, signal.SIGCONT)
    check(c1 == c0 and t1 == t0, "PBX woke up %d times / used %d ticks in 3 s idle" % (c1 - c0, t1 - t0))
    return "0 wakeups, 0 CPU ticks in 3 s (phones frozen)"


TESTS = [
    ("register", t_register),
    ("call+media, caller hangs up", t_call_caller_hangup),
    ("callee hangs up", t_call_callee_hangup),
    ("busy (486)", t_busy),
    ("not registered (480)", t_not_registered),
    ("unknown extension (404)", t_unknown_extension),
    ("caller CANCEL while ringing", t_cancel),
    ("wrong password (403)", t_wrong_password),
    ("hold / resume", t_hold_resume),
    ("MESSAGE", t_message),
    ("blind transfer 101->102 => 103", t_transfer),
    ("attended transfer (Replaces)", t_attended_transfer),
    ("early media + DTMF", t_early_media_dtmf),
    ("unregistered caller (407)", t_unauthenticated_caller),
    ("sipp: REGISTER compact/no-rport", t_sipp_register),
    ("sipp: UAS 104 answers 101", t_sipp_uas, ["sipp: REGISTER compact/no-rport"]),
    ("sipp: UAC compact/multi-Via/retx", t_sipp_uac, ["sipp: REGISTER compact/no-rport"]),
    ("sipp: 407 + CANCEL", t_sipp_cancel),
    ("sipp: OPTIONS/489/420/404/403", t_sipp_misc),
    ("sipp: 100 calls @ 20/s", t_sipp_load),
    ("unregister 104 (Contact: *)", t_sipp_unregister),
    ("multi-line phone (104+105)", t_multi_line),
    ("outbound proxy + SIP domain", t_outbound_proxy_domain),
    ("100rel / PRACK", t_100rel),
    ("unregister / re-register 103", t_unregister),
    ("PBX restart, persisted bindings", t_restart),
    ("direct-Contact CANCEL after unregister", t_direct_contact_unregister),
    ("PBX restart while ringing", t_restart_ringing),
    ("dialog hangup after both unregister", t_dialog_unregister),
    ("phones on two addresses of the PBX", t_multihome),
    ("allow filter (CIDR)", t_allow_filter),
    ("idle CPU", t_idle_cpu),
]
GROUP_TESTS = groups.TESTS

# Only with --slow: real protocol timers / deliberate load. The timer logic
# itself is covered by `cargo test` with simulated time.
SLOW = {"sipp: 100 calls @ 20/s"} | groups.SLOW


def pbx_gone(pbx, last, failures):
    """A PBX that exits by itself has crashed, which fails the run even if
    every test passes. Reported once: stop() forgets the dead process."""
    status = pbx.died()
    if status is None:
        return False
    when = "during or after %r" % last if last else "before the first test"
    failures.append("%s exited by itself (status %s) %s" % (pbx.name, status, when))
    pbx.stop()
    return True


def run_block(suite, env, tests, wanted, uas, failures):
    pbx = env.pbx if tests is TESTS else env.g.pbx
    last = None
    try:
        for t in tests:
            name, fn = t[0], t[1]
            if name not in wanted:
                continue
            if pbx_gone(pbx, last, failures) and tests is not TESTS:
                return  # nothing restarts the group PBX
            if tests is TESTS and not pbx.alive():
                pbx.start()  # stopped by a test that failed, or gone (above)
            ok = suite.run(name, fn, env)
            last = name
            if not ok and fn in (t_register, groups.t_g_register):
                return
            dead = [ua.name for ua in uas() if ua.proc.poll() is not None]
            if dead:
                failures.append("%s exited unexpectedly" % ", ".join(dead))
                return
            try:
                idle(*uas())
            except Fail as e:
                failures.append(str(e))
                return
    finally:
        pbx_gone(pbx, last, failures)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=os.environ.get("PBX_TEST_HOST", "127.0.0.2"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("PBX_TEST_PORT", "5060")))
    ap.add_argument("--group-host", default=os.environ.get("PBX_TEST_GROUP_HOST", "127.0.0.4"))
    ap.add_argument("--only", help="comma-separated substrings of test names")
    ap.add_argument("--slow", action="store_true", help="also run the slow tests (protocol timers, load)")
    ap.add_argument("--serial", action="store_true", help="run the group block after the main block, not alongside")
    args = ap.parse_args(argv)
    tests = TESTS + GROUP_TESTS
    wanted = select_tests(ap, tests, args.only, skip_by_default=() if args.slow else SLOW)
    for t in tests:
        if t[0] in wanted and len(t) > 2:
            wanted.update(t[2])
    if wanted & {t[0] for t in TESTS}:
        wanted.add("register")
    if wanted & {t[0] for t in GROUP_TESTS}:
        wanted.add("group: register")
    env = Env(args)
    suite = Suite("loopback interop (pjsua 2.17, sipp 3.7%s)" % (", slow tests" if args.slow else ""))
    failures = []
    ok = False
    t0 = time.time()
    try:
        env.pbx.start()
        blocks = [
            (TESTS, lambda: list(env.uas.values())),
            (GROUP_TESTS, lambda: list(env.g.uas.values())),
        ]
        with ThreadPoolExecutor(max_workers=1 if args.serial else len(blocks)) as pool:
            futures = [pool.submit(run_block, suite, env, tests, wanted, uas, failures) for tests, uas in blocks]
            for future in futures:
                try:
                    future.result()
                except (Exception, SystemExit) as e:
                    traceback.print_exc()
                    failures.append("worker raised %r" % e)
        missing = wanted.difference(r[0] for r in suite.results)
        if missing:
            failures.append("tests not run: " + ", ".join(sorted(missing)))
        for f in failures:
            suite.results.append(("(harness)", False, f, 0))
        ok = suite.summary(time.time() - t0)
    finally:
        env.close()
    print("logs: %s" % env.out)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
