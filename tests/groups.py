"""Ring groups / several devices per extension (INVITE forking), with pjsua.

Runs against its own PBX instance (127.0.0.4:5060 by default) so `*` groups
only contain the phones started here:

    201        caller (plays 1000 Hz)
    202-204    group members, answered by the harness (tones 440/600/700)
    205        member that is always busy (--auto-answer 486)
    206        one extension registered from two pjsua instances
    207        member that registers and then freezes (SIGSTOP)
    208, 209   members that answer immediately (--auto-answer 200)
    210        member that answers immediately but is frozen until the
               caller has given up
    211        hand-made UDP phone (RawUA) that re-registers from elsewhere
               while a call to it rings
    212        second always-busy phone (--auto-answer 486)
    209 (raw)  hand-made caller placing 5 group calls at once

    [groups] 300 = 202 203 204, 301 = 205 202, 302 = 202 203 207,
             303 = 208 209, 304 = 202 210, 307 = 205 212, 399 = *
"""

import os
import re
import signal
import time

from harness import (
    MEDIA_SECS,
    quit_all,
    Fail,
    Pbx,
    Pjsua,
    RawUA,
    check,
    check_tone,
    digest_header,
    first_line,
    fresh_dir,
    header,
    wait_until,
    write_tone,
)

QUIET = 0.3  # "nothing else arrives" window on loopback
RETX_WINDOW = 0.65  # covers the first retransmission after T1 = 0.5 s

PASSWORDS = {str(e): "gpw%d" % e for e in range(201, 213)}
TONES = {"201": 1000, "202": 440, "203": 600, "204": 700, "206": 800, "208": 900, "209": 1100}
GROUPS = {"300": "202 203 204", "301": "205 202", "302": "202 203 207", "303": "208 209", "304": "202 210", "307": "205 212", "399": "*"}
PORTS = {"g201": 5201, "g202": 5202, "g203": 5203, "g204": 5204, "g205": 5205, "g206a": 5206,
         "g206b": 5216, "g207": 5207, "g208": 5208, "g209": 5209, "g210": 5210, "g212": 5212}  # fmt: skip

DISCONNECTED = r"Call (\d+) is DISCONNECTED \[reason=(\d+) \(([^)]*)\)\]"


class GroupEnv:
    def __init__(self, out, binary, host="127.0.0.4", port=5060):
        self.out = fresh_dir(os.path.join(out, "groups"))
        self.host, self.port = host, port
        for ext, f in TONES.items():
            write_tone(os.path.join(self.out, "tone%s.wav" % ext), f)
        conf = "listen = %s:%d\nrealm = pbx\n[extensions]\n" % (host, port)
        conf += "".join("%s = %s\n" % kv for kv in sorted(PASSWORDS.items()))
        conf += "[groups]\n" + "".join("%s = %s\n" % kv for kv in sorted(GROUPS.items()))
        self.pbx = Pbx(binary, self.out, conf, name="pbx-groups")
        self.uas = {}
        self.retired = []
        self.seg = 0

    def phone(self, name, ext, **kw):
        port = PORTS[name]
        if ext in TONES:
            kw.setdefault("play", os.path.join(self.out, "tone%s.wav" % ext))
            kw.setdefault("rec", os.path.join(self.out, "rec_%s.wav" % name))
        ua = Pjsua(
            name, self.out, ext, PASSWORDS[ext], port, 4000 + (port % 100) * 20 + (100 if port > 5210 else 0),
            pbx_host=self.host, pbx_port=self.port, bound_addr="127.0.0.1", **kw
        )  # fmt: skip
        self.uas[name] = ua
        ua.wait_registered(0, 5)
        return ua

    def drop(self, name):
        """Quit a phone without waiting for it (close() reaps it)."""
        ua = self.uas.pop(name, None)
        if ua:
            ua.send("q")
            self.retired.append(ua)

    def tone_check(self, ua, start, want, other):
        self.seg += 1
        path = os.path.join(self.out, "seg%02d_%s.wav" % (self.seg, ua.name))
        ua.rec_segment(start, path)
        return check_tone(path, want, other)

    def thaw(self):
        """All phones, SIGCONTed (a failed test may have left one stopped)."""
        for ua in self.uas.values():
            if ua.proc.poll() is None:
                try:
                    os.kill(ua.proc.pid, signal.SIGCONT)
                except ProcessLookupError:
                    pass
        return list(self.uas.values()) + self.retired


def addr(port):
    return "127.0.0.1:%d" % port


def pkts(g, since, direction=None, peer=None, first=None, contains=None):
    """PBX log packets so far (after a sync barrier, so nothing is missing
    that the PBX did before now)."""
    g.pbx.sync()
    return g.pbx.find(since, direction, peer, first, contains)


def wait_pkts(g, since, direction=None, peer=None, first=None, contains=None, n=1, timeout=3.0, what=None):
    return g.pbx.wait(since, n, timeout, what, direction=direction, peer=peer, first=first, contains=contains)


def ring(g, caller, number, members):
    """caller dials `number`; every member rings and answers 180."""
    marks = {m.name: m.mark() for m in members}
    mc = caller.mark()
    caller.call(number)
    for m in members:
        m.expect(r"Incoming call for account", 5, marks[m.name], "%s rings" % m.name)
        m.answer(180)
    caller.expect(r"state changed to EARLY", 5, mc, "caller EARLY")
    return mc, marks


def media(g, a, b):
    a.play_into_calls()
    b.play_into_calls()
    ra, rb = a.rec_mark(), b.rec_mark()
    a.wait_recorded(ra, MEDIA_SECS)
    b.wait_recorded(rb, MEDIA_SECS)
    return "%s; %s" % (
        g.tone_check(a, ra, TONES[b.ext], TONES[a.ext]),
        g.tone_check(b, rb, TONES[a.ext], TONES[b.ext]),
    )


def disconnected(ua, since, reason=None, timeout=6):
    m = ua.expect(DISCONNECTED, timeout, since, "DISCONNECTED")
    if reason is not None:
        check(int(m.group(2)) == reason, "%s: ended with %s %s, expected %d" % (ua.name, m.group(2), m.group(3), reason))
    return int(m.group(2))


def finals_once(g, since, phones, code_rx=r"[3-6]\d\d", t_final=None):
    """Every phone sent each of its final responses exactly once, i.e. our
    ACK got there (otherwise it would retransmit after T1=500 ms). Waits for
    the ACKs, then until RETX_WINDOW after `t_final` (default: now)."""
    t_final = t_final or time.time()
    for ph in phones:
        n = len(pkts(g, since, "<<<", addr(PORTS[ph.name]), r"^SIP/2.0 " + code_rx, r"CSeq: \d+ INVITE"))
        check(n, "%s sent no final response" % ph.name)
        wait_pkts(g, since, ">>>", addr(PORTS[ph.name]), r"^ACK ", n=n, what="ACKs to %s" % ph.name)
    time.sleep(max(0, t_final + RETX_WINDOW - time.time()))
    for ph in phones:
        finals = pkts(g, since, "<<<", addr(PORTS[ph.name]), r"^SIP/2.0 " + code_rx, r"CSeq: \d+ INVITE")
        keys = [re.search(r"(?m)^CSeq: .*$", t).group(0) + re.search(r"(?m)^Call-ID: .*$", t).group(0) for *_, t in finals]
        dups = len(keys) - len(set(keys))
        check(dups == 0, "%s retransmitted its final response %d time(s) (not ACKed?)" % (ph.name, dups))
        acks = pkts(g, since, ">>>", addr(PORTS[ph.name]), r"^ACK ")
        check(len(acks) >= len(finals), "%s: %d finals but only %d ACKs" % (ph.name, len(finals), len(acks)))


# ---------------------------------------------------------------- tests


def t_g_register(env):
    g = env.g
    g.pbx.start()
    g.phone("g201", "201")
    for n, e in (("g202", "202"), ("g203", "203"), ("g204", "204")):
        g.phone(n, e)
    g.phone("g205", "205", auto_answer=486)
    return "201-205 registered on %s:%d" % (g.host, g.port)


def t_g_first_answer(env):
    """Group of three: all ring, one answers, the other two get CANCEL."""
    g = env.g
    c, members = g.uas["g201"], [g.uas[n] for n in ("g202", "g203", "g204")]
    res = []
    for winner, hang in ((members[0], "caller"), (members[1], "callee")):
        p0 = g.pbx.log.mark()
        mc, marks = ring(g, c, "300", members)
        trying = pkts(g, p0, ">>>", addr(5201), r"^SIP/2.0 100")
        check(trying, "PBX did not send 100 Trying to the caller")
        winner.answer(200)
        c.expect(r"Call \d+ state changed to CONFIRMED", 5, mc, "caller CONFIRMED")
        winner.expect(r"state changed to CONFIRMED", 5, marks[winner.name])
        for m in members:
            if m is not winner:
                disconnected(m, marks[m.name], 487)
        t487 = time.time()
        for m in members:
            if m is not winner:
                can = pkts(g, p0, ">>>", addr(PORTS[m.name]), r"^CANCEL ")
                check(can, "no CANCEL to %s" % m.name)
                check(
                    re.search(r"(?m)^Reason: SIP;cause=200", can[0][3]),
                    "CANCEL to %s lacks 'Reason: SIP;cause=200' (call completed elsewhere)" % m.name,
                )
        check(not c.log.grep(r"is DISCONNECTED", mc), "caller's call ended")
        detail = media(g, c, winner)
        mm = winner.mark() if hang == "caller" else c.mark()
        (c if hang == "caller" else winner).hangup()
        disconnected(winner if hang == "caller" else c, mm, 200)
        finals_once(g, p0, [m for m in members if m is not winner], r"487", t487)
        res.append("%s answered (%s), others 487, %s hung up" % (winner.ext, detail, hang))
    # groups only take calls
    p1 = g.pbx.log.mark()
    c.send("i", c.uri("300"), "hello group")
    wait_pkts(g, p1, ">>>", addr(5201), r"^SIP/2.0 405", what="405 for MESSAGE to a group")
    return " | ".join(res) + " | MESSAGE -> 405"


def t_g_busy_member(env):
    """One member busy at once (auto 486), another answers later."""
    g = env.g
    c, busy, m = g.uas["g201"], g.uas["g205"], g.uas["g202"]
    p0 = g.pbx.log.mark()
    mb = busy.mark()
    mc, marks = ring(g, c, "301", [m])
    busy.expect(r"Answering call \d+: code=486", 5, mb, "205 busy")
    t486 = time.time()
    wait_pkts(g, p0, ">>>", addr(5205), r"^ACK ", what="ACK for 205's 486")
    time.sleep(QUIET)
    check(not c.log.grep(r"is DISCONNECTED", mc), "caller gave up after one member was busy")
    m.answer(200)
    c.expect(r"Call \d+ state changed to CONFIRMED", 5, mc, "caller CONFIRMED")
    detail = media(g, c, m)
    c.hangup()
    disconnected(m, marks[m.name], 200)
    finals_once(g, p0, [busy], r"486", t486)
    return "205 486 (ACKed), call kept ringing, 202 answered: " + detail


def t_g_all_reject(env):
    """All members reject -> caller gets the best final (486), all ACKed."""
    g = env.g
    c, members = g.uas["g201"], [g.uas[n] for n in ("g202", "g203", "g204")]
    p0 = g.pbx.log.mark()
    mc, marks = ring(g, c, "300", members)
    for m, code in zip(members, (603, 486, 480)):
        m.answer(code)
    disconnected(c, mc, 486)
    wait_pkts(g, p0, "<<<", addr(5201), r"^ACK ", what="caller's ACK for the 486")
    finals_once(g, p0, members, r"(603|486|480)")  # also covers T1 for the caller's 486
    to_caller = pkts(g, p0, ">>>", addr(5201), r"^SIP/2.0 486")
    check(len(to_caller) == 1, "PBX sent its 486 to the caller %d times (caller's ACK not absorbed?)" % len(to_caller))
    return "603/486/480 -> caller got 486 once, every final ACKed"


def t_g_caller_cancel(env):
    g = env.g
    c, members = g.uas["g201"], [g.uas[n] for n in ("g202", "g203", "g204")]
    p0 = g.pbx.log.mark()
    mc, marks = ring(g, c, "300", members)
    c.hangup()
    disconnected(c, mc, 487)
    for m in members:
        disconnected(m, marks[m.name], 487)
    wait_pkts(g, p0, "<<<", addr(5201), r"^ACK ", what="caller's ACK for the PBX's 487")
    finals_once(g, p0, members, r"487")
    check(pkts(g, p0, ">>>", addr(5201), r"^SIP/2.0 200", r"CSeq: \d+ CANCEL"), "no 200 for the caller's CANCEL")
    # the caller's 487 comes after the phones' 487s (so that a 2xx racing
    # the CANCEL could still have reached the caller), exactly once (ACKed)
    g.pbx.sync()
    seq = [(d, p, fl) for d, p, fl, _ in g.pbx.packets(p0)]
    to_caller = [i for i, (d, p, fl) in enumerate(seq) if d == ">>>" and p == addr(5201) and fl.startswith("SIP/2.0 487")]
    check(len(to_caller) == 1, "PBX sent 487 to the caller %d times" % len(to_caller))
    from_phones = [i for i, (d, p, fl) in enumerate(seq) if d == "<<<" and p != addr(5201) and fl.startswith("SIP/2.0 487")]
    check(len(from_phones) >= 3, "only %d phones answered the CANCEL with 487" % len(from_phones))
    check(max(from_phones) < to_caller[0], "caller got its 487 before all phones had confirmed the CANCEL")
    return "caller 487 once, after all three phones' 487s (all ACKed)"


def t_g_two_devices(env):
    """Extension 206 registered from two pjsua instances: both ring."""
    g = env.g
    c = g.uas["g201"]
    a = g.phone("g206a", "206")
    b = g.phone("g206b", "206")
    st = g.pbx.status()
    check(len(re.findall(r"^206\s", st, re.M)) == 2, "206 should have two bindings:\n%s" % st)
    res = []
    for winner, loser in ((b, a), (a, b)):
        mc, marks = ring(g, c, "206", [a, b])
        winner.answer(200)
        c.expect(r"Call \d+ state changed to CONFIRMED", 5, mc)
        disconnected(loser, marks[loser.name], 487)
        detail = media(g, c, winner)
        winner.hangup()
        disconnected(c, mc, 200)
        res.append("%s answered, %s stopped (%s)" % (winner.name, loser.name, detail))
    # declining on one device stops the other and is the caller's answer
    p0 = g.pbx.log.mark()
    mc, marks = ring(g, c, "206", [a, b])
    a.answer(603)
    disconnected(b, marks[b.name], 487)
    disconnected(c, mc, 603)
    can = pkts(g, p0, ">>>", addr(PORTS["g206b"]), r"^CANCEL ")
    check(can, "no CANCEL to g206b after g206a declined")
    check(re.search(r"(?m)^Reason: SIP;cause=603", can[0][3]), "CANCEL to g206b lacks 'Reason: SIP;cause=603'")
    finals_once(g, p0, [a, b], r"(603|487)")
    res.append("g206a declined: g206b cancelled (cause=603), caller got 603")
    # and either device can call out (trusted from both addresses)
    m = g.uas["g202"]
    for dev in (a, b):
        me, md = m.mark(), dev.mark()
        dev.call("202")
        m.expect(r"Incoming call for account", 5, me, "call from %s" % dev.name)
        m.answer(486)
        disconnected(dev, md, 486)
    return " | ".join(res) + " | both devices can call out"


def t_g_star_skips_caller(env):
    """Group `*` called from one of its members: everyone else rings, the
    caller's own device doesn't."""
    g = env.g
    c = g.uas["g201"]
    others = [g.uas[n] for n in ("g202", "g203", "g204", "g206a", "g206b")]
    p0 = g.pbx.log.mark()
    mc0 = c.mark()
    mc, marks = ring(g, c, "399", others)
    winner = g.uas["g203"]
    winner.answer(200)
    c.expect(r"Call \d+ state changed to CONFIRMED", 5, mc)
    for m in others:
        if m is not winner:
            disconnected(m, marks[m.name], 487)
    check(not pkts(g, p0, ">>>", addr(5201), r"^INVITE "), "the caller's own phone got an INVITE")
    check(not c.log.grep(r"Incoming call", mc0), "caller rang itself")
    invited = sorted({p for _, p, _, _ in pkts(g, p0, ">>>", None, r"^INVITE ")})
    c.hangup()
    disconnected(winner, marks[winner.name], 200)
    return "rang %s (205 busy), not 201; 203 answered" % ", ".join(i.split(":")[1] for i in invited)


def t_g_dead_member(env):
    """A registered member that is frozen: the others still work, a failed
    call ends ~4 s after the INVITE, and once the phone wakes up it gets the
    (deferred) CANCEL."""
    g = env.g
    c, m2, m3 = g.uas["g201"], g.uas["g202"], g.uas["g203"]
    dead = g.phone("g207", "207")
    os.kill(dead.proc.pid, signal.SIGSTOP)
    try:
        p0 = g.pbx.log.mark()
        mc, marks = ring(g, c, "302", [m2, m3])
        # the PBX retransmits the INVITE to the silent phone (T1 = 0.5 s)
        wait_pkts(g, p0, ">>>", addr(5207), r"^INVITE ", n=2, what="INVITE retransmission to the frozen phone")
        m2.answer(200)
        c.expect(r"Call \d+ state changed to CONFIRMED", 5, mc)
        disconnected(m3, marks[m3.name], 487)
        detail = media(g, c, m2)
        c.hangup()
        disconnected(m2, marks["g202"], 200)
        # now everyone alive rejects
        p1 = g.pbx.log.mark()
        t0 = time.time()
        mc, marks = ring(g, c, "302", [m2, m3])
        m2.answer(486)
        m3.answer(603)
        disconnected(c, mc, 486, timeout=10)
        took = time.time() - t0
        check(took < 6.5, "caller waited %.1fs for the final (dead phone not given up on?)" % took)
        finals_once(g, p1, [m2, m3], r"(486|603)")
    finally:
        md = dead.mark()
        os.kill(dead.proc.pid, signal.SIGCONT)
    # the frozen phone wakes up with the queued INVITEs: it answers 100,
    # gets the deferred CANCEL and must not be left ringing
    wait_until(lambda: len(dead.log.grep(DISCONNECTED, md)) >= 2, 8, "woken phone: both queued calls ended")
    time.sleep(QUIET)
    n = len(dead.log.grep(DISCONNECTED, md))
    incoming = len(dead.log.grep(r"Incoming call for account", md))
    check(incoming >= 1, "woken phone saw no INVITE")
    check(n >= incoming, "woken phone: %d incoming calls but only %d ended (left ringing)" % (incoming, n))
    g.drop("g207")
    return "%s; INVITE retransmitted to frozen phone; all-reject final after %.1fs; woken phone got %d CANCELs" % (
        detail,
        took,
        n,
    )


def t_g_simultaneous_answer(env):
    """Two members answer at once: the caller must end up with one call and
    no phone may be left in a call."""
    g = env.g
    c = g.uas["g201"]
    a = g.phone("g208", "208", auto_answer=200)
    b = g.phone("g209", "209", auto_answer=200)
    p0 = g.pbx.log.mark()
    mc, ma, mb = c.mark(), a.mark(), b.mark()
    c.call("303")
    c.expect(r"Call \d+ state changed to CONFIRMED", 5, mc, "caller CONFIRMED")
    a.expect(r"state changed to CONFIRMED|is DISCONNECTED", 5, ma)
    b.expect(r"state changed to CONFIRMED|is DISCONNECTED", 5, mb)
    # one of them gets hung up (BYE from the caller, or CANCEL if it was late)
    wait_until(
        lambda: a.log.grep(r"is DISCONNECTED", ma) or b.log.grep(r"is DISCONNECTED", mb), 5, "one of 208/209 hung up"
    )
    time.sleep(QUIET)
    oks = pkts(g, p0, ">>>", addr(5201), r"^SIP/2.0 200", r"CSeq: \d+ INVITE")
    tags = {re.search(r"(?m)^To: .*tag=([^;>\s]+)", t).group(1) for *_, t in oks}
    up = [u for u, m in ((a, ma), (b, mb)) if not u.log.grep(r"is DISCONNECTED", m)]
    confirmed_calls = len(c.log.grep(r"Call \d+ state changed to CONFIRMED", mc))
    check(len(up) == 1, "%d of 208/209 still in the call (expected exactly 1)" % len(up))
    check(confirmed_calls == 1, "caller has %d confirmed calls" % confirmed_calls)
    detail = media(g, c, up[0])
    mu = up[0].mark()
    c.hangup()
    disconnected(up[0], mu, 200)
    loser = b if up[0] is a else a
    how = "BYE" if pkts(g, p0, ">>>", addr(PORTS[loser.name]), r"^BYE ") else "CANCEL"
    return "%d different 2xx reached the caller; %s won, %s got %s; %s" % (len(tags), up[0].ext, loser.ext, how, detail)


def t_g_late_answer(env):
    """A member that is frozen while the caller gives up, then answers (2xx
    after the caller already got its final): the PBX must end that call
    (ACK+BYE or CANCEL), the caller must not get a call, nobody left hanging."""
    g = env.g
    c, m = g.uas["g201"], g.uas["g202"]
    late = g.phone("g210", "210", auto_answer=200)
    os.kill(late.proc.pid, signal.SIGSTOP)
    try:
        p0 = g.pbx.log.mark()
        t0 = time.time()
        mc, marks = ring(g, c, "304", [m])
        c.hangup()  # pjsua reports "487" locally at once; wait for the PBX's
        disconnected(m, marks["g202"], 487)
        wait_pkts(g, p0, ">>>", addr(5201), r"^SIP/2.0 487", timeout=8, what="the PBX's 487 to the caller")
        took = time.time() - t0
        check(took < 6.5, "caller waited %.1fs for its 487" % took)
        p487 = g.pbx.log.mark()
    finally:
        ml = late.mark()
        os.kill(late.proc.pid, signal.SIGCONT)
    late.expect(r"Incoming call for account|Incoming Request msg INVITE", 5, ml, "woken phone sees the INVITE")
    end = late.expect(DISCONNECTED, 8, ml, "woken phone's call ended")
    time.sleep(QUIET)
    check(not c.log.grep(r"state changed to CONFIRMED", mc), "caller got connected after hanging up")
    bye = pkts(g, p0, ">>>", addr(5210), r"^BYE ")
    can = pkts(g, p0, ">>>", addr(5210), r"^CANCEL ")
    ok2xx = pkts(g, p0, "<<<", addr(5210), r"^SIP/2.0 200", r"CSeq: \d+ INVITE")
    leaked = pkts(g, p487, ">>>", addr(5201), r"^SIP/2.0 200", r"CSeq: \d+ INVITE")
    check(not leaked, "the late 2xx was passed on to the caller after its 487")
    g.drop("g210")
    return "caller 487 after %.1fs; woken phone answered=%s, PBX sent it %s; its call ended (%s %s)" % (
        took,
        bool(ok2xx),
        "+".join(x for x, y in (("CANCEL", can), ("BYE", bye)) if y) or "nothing",
        end.group(2),
        end.group(3),
    )


def raw_reply(req, code, reason, tag=None):
    """A response to `req` (text) as a UAS would build it."""
    lines = req.split("\r\n")
    out = ["SIP/2.0 %d %s" % (code, reason)]
    for l in lines[1:]:
        name = l.split(":", 1)[0].strip().lower()
        if name in ("via", "v", "from", "f", "call-id", "i", "cseq", "record-route"):
            out.append(l)
        elif name in ("to", "t"):
            out.append(l + (";tag=%s" % tag if tag and "tag=" not in l else ""))
        elif l == "":
            break
    return "\r\n".join(out) + "\r\nContent-Length: 0\r\n\r\n"


def raw_register(g, port, ext, expires=300):
    ua = RawUA(("127.0.0.1", port), (g.host, g.port))
    uri = "sip:%s:%d" % (g.host, g.port)
    cid = "raw-%s-%d-%d-%d" % (ext, port, os.getpid(), time.monotonic_ns())
    r = ua.register(ext, expires, cseq=1, call_id=cid)
    chal = header(r, "WWW-Authenticate")
    check(chal, "no challenge: %s" % first_line(r))
    r = ua.register(ext, expires, cseq=2, call_id=cid, auth=digest_header("Authorization", chal, "REGISTER", uri, ext, PASSWORDS[ext]))
    check(first_line(r).startswith("SIP/2.0 200"), "register %s from %d: %s" % (ext, port, first_line(r)))
    return ua


def recv_request(ua, method, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        m = ua.recv(max(0.1, deadline - time.time()))
        if m and m.startswith(method + " "):
            return m
    raise Fail("no %s received at %s" % (method, ua.local))


def t_g_target_moves(env):
    """1-target call: the callee registers a second device while it rings.
    The caller's CANCEL (and the ACK for the 487) must still go to the
    device that got the INVITE, not start ringing the new one."""
    g = env.g
    c = g.uas["g201"]
    a = raw_register(g, 5221, "211")
    b = None
    try:
        mc = c.mark()
        c.call("211")
        inv = recv_request(a, "INVITE")
        a.send(raw_reply(inv, 180, "Ringing", "rawA"))
        c.expect(r"state changed to EARLY", 5, mc, "caller EARLY")
        b = raw_register(g, 5222, "211")  # second device appears
        st = g.pbx.status()
        check(len(re.findall(r"^211\s", st, re.M)) == 2, "211 should have two bindings now:\n%s" % st)
        c.hangup()
        can = recv_request(a, "CANCEL")
        a.send(raw_reply(can, 200, "OK", "rawA"))
        a.send(raw_reply(inv, 487, "Request Terminated", "rawA"))
        disconnected(c, mc, 487)
        ack = recv_request(a, "ACK")
        stray = b.recv(0.5)
        check(stray is None, "second device got %s" % first_line(stray))
        return "CANCEL and ACK went to the device that rang (%s / %s)" % (first_line(can).split()[0], first_line(ack).split()[0])
    finally:
        for ua, port in ((a, 5221), (b, 5222)):
            if ua:
                ua.close()
                raw_register(g, port, "211", 0).close()


def t_g_redial(env):
    """Redialling a group whose phones are all busy: every attempt must get
    486, also once more than 4 attempts fall within a fork's linger time."""
    g = env.g
    c = g.uas["g201"]
    g.phone("g212", "212", auto_answer=486)
    codes = []
    try:
        for _ in range(6):
            mc = c.mark()
            c.call("307")
            codes.append(disconnected(c, mc, None, timeout=8))
    finally:
        g.drop("g212")
    check(all(x == 486 for x in codes), "redial results %s (expected 486 each time)" % codes)
    return "6 redials in a row: %s" % " ".join(map(str, codes))


def t_g_parallel_limit(env):
    """One phone with 5 group calls ringing at once: 4 are accepted (100
    Trying), the 5th is refused (503); the 4 are then cancelled cleanly."""
    g = env.g
    members = [g.uas[n] for n in ("g202", "g203", "g204")]
    marks = {m.name: m.mark() for m in members}
    ua = raw_register(g, 5225, "209")
    calls = []
    try:
        for i in range(5):
            cid = "par-%d-%d" % (i, os.getpid())
            br = "z9hG4bK-par-%d-%d" % (i, os.getpid())
            inv = (
                "INVITE sip:300@%s SIP/2.0\nVia: SIP/2.0/UDP 127.0.0.1:5225;rport;branch=%s\n"
                "From: <sip:209@%s>;tag=p%d\nTo: <sip:300@%s>\nCall-ID: %s\nCSeq: 1 INVITE\n"
                "Contact: <sip:209@127.0.0.1:5225>\nMax-Forwards: 70\n" % (g.host, br, g.host, i, g.host, cid)
            )
            ua.send(inv)
            calls.append((cid, br, i))
        first = {}
        deadline = time.time() + 5
        while len(first) < 5 and time.time() < deadline:
            r = ua.recv(0.5)
            if r:
                cid = header(r, "Call-ID")
                first.setdefault(cid, int(first_line(r).split()[1]))
        got = [first.get(cid) for cid, _, _ in calls]
        check(got[:4] == [100] * 4, "first four calls got %s (expected 100 Trying)" % got[:4])
        check(got[4] == 503, "fifth parallel call got %s (expected 503)" % got[4])
        # cancel the four, ACK their 487s
        for cid, br, i in calls[:4]:
            ua.send(
                "CANCEL sip:300@%s SIP/2.0\nVia: SIP/2.0/UDP 127.0.0.1:5225;rport;branch=%s\n"
                "From: <sip:209@%s>;tag=p%d\nTo: <sip:300@%s>\nCall-ID: %s\nCSeq: 1 CANCEL\nMax-Forwards: 70\n"
                % (g.host, br, g.host, i, g.host, cid)
            )
        finals = {}
        deadline = time.time() + 10
        while len(finals) < 4 and time.time() < deadline:
            r = ua.recv(0.5)
            if r and header(r, "CSeq").endswith("INVITE") and int(first_line(r).split()[1]) >= 300:
                cid = header(r, "Call-ID")
                finals[cid] = int(first_line(r).split()[1])
                i = [c[2] for c in calls if c[0] == cid][0]
                br = [c[1] for c in calls if c[0] == cid][0]
                ua.send(
                    "ACK sip:300@%s SIP/2.0\nVia: SIP/2.0/UDP 127.0.0.1:5225;rport;branch=%s\n"
                    "From: <sip:209@%s>;tag=p%d\nTo: %s\nCall-ID: %s\nCSeq: 1 ACK\nMax-Forwards: 70\n"
                    % (g.host, br, g.host, i, header(r, "To"), cid)
                )
        check(sorted(finals.values()) == [487] * 4, "finals after CANCEL: %s" % finals)
        for m in members:
            wait_until(lambda: len(m.log.grep(DISCONNECTED, marks[m.name])) >= 4, 5, "%s: 4 calls ended" % m.name)
            n_in = len(m.log.grep(r"Incoming Request msg INVITE", marks[m.name]))
            n_end = len(m.log.grep(DISCONNECTED, marks[m.name]))
            check(n_in == 4 and n_end == 4, "%s: %d calls rang, %d ended" % (m.name, n_in, n_end))
    finally:
        ua.close()
        raw_register(g, 5225, "209", 0).close()
    return "4 x 100 Trying, 5th -> 503; the 4 cancelled -> 487 each, 3 phones x 4 calls all ended"


def t_g_idle(env):
    """After the group calls are over the PBX must stop waking up. A finished
    fork lingers 32 s (to absorb retransmissions), so wait until there has
    been no wakeup for longer than any fork timer can be away (33 s)."""
    g = env.g
    quit_all(list(g.uas.values()) + g.retired)  # no more keep-alives / traffic
    g.uas.clear()
    t_end = time.time()
    pid = g.pbx.proc.pid

    def ctxt():
        with open("/proc/%d/status" % pid) as f:
            for l in f:
                if l.startswith("voluntary_ctxt_switches"):
                    return int(l.split()[1])
        return 0

    need, limit = 33, 150
    wakeups = []
    last, quiet_from = ctxt(), time.time()
    while time.time() - t_end < limit:
        time.sleep(0.5)
        cur = ctxt()
        if cur != last:
            wakeups.append((round(time.time() - t_end, 1), cur - last))
            last, quiet_from = cur, time.time()
        elif time.time() - quiet_from >= need:
            check(len(wakeups) <= 20, "too many wakeups: %s" % wakeups)
            return "no wakeup for %ds; after the last call it woke at %s s" % (
                need,
                ", ".join("%.0f" % t for t, _ in wakeups) or "-",
            )
    raise Fail("PBX still waking up %ds after the last group call: %s" % (limit, wakeups[-10:]))


TESTS = [
    ("group: register", t_g_register),
    ("group: 3 ring, first answer wins", t_g_first_answer),
    ("group: busy member + later answer", t_g_busy_member),
    ("group: all reject -> best final", t_g_all_reject),
    ("group: caller CANCEL", t_g_caller_cancel),
    ("group: one ext on two devices", t_g_two_devices),
    ("group: * skips the caller", t_g_star_skips_caller, ["group: one ext on two devices"]),
    ("group: dead member", t_g_dead_member),
    ("group: simultaneous answers", t_g_simultaneous_answer),
    ("group: late answer after CANCEL", t_g_late_answer),
    ("1 target: CANCEL after re-register", t_g_target_moves),
    ("group: redial busy group 6x", t_g_redial),
    ("group: 5 parallel calls -> 503", t_g_parallel_limit),
    ("group: idle afterwards", t_g_idle),
]

# Run only with --slow: they wait for real protocol timers (the 4 s
# "dead phone" rule once more, the 32 s linger of finished forks).
SLOW = {"group: late answer after CANCEL", "group: idle afterwards"}
