#!/usr/bin/env python3
"""Interop with non-pjsip SIP stacks: baresip and linphonec in Debian
containers, plus pjsua on the host, all talking to the PBX running in a
container that is attached to two docker bridge networks.

    lan1 10.231.1.0/24: pbx .2, baresip 201 .11, linphone 202 .12,
                        pjsua 203 on the host (bridge gateway .1)
    lan2 10.231.2.0/24: pbx .2, baresip 211 .11,
                        pjsua 213 on the host (bridge gateway .1)

Usage: tests/docker_interop.py [--keep] [--only NAME,...]

Needs a working docker daemon. Only touches containers/networks named
pbxi-*. Builds the UA image from tests/docker/Dockerfile.ua on first use and
a static PBX binary into target/static. Logs: tests/out/docker/.
"""

import argparse
import os
import re
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import (
    HERE,
    MEDIA_SECS,
    REPO,
    Fail,
    LineLog,
    Pbx,
    Pjsua,
    PtyProc,
    Suite,
    check,
    check_tone,
    fresh_dir,
    quit_all,
    select_tests,
    wait_until,
    wait_wav_growth,
    wav_segment,
    write_tone,
)

IMAGE = "pbx-interop-ua:latest"
PBX_IMAGE = "alpine:3.22"
NETS = {
    "lan1": ("pbxi-lan1", os.environ.get("PBXI_NET1", "10.231.1")),
    "lan2": ("pbxi-lan2", os.environ.get("PBXI_NET2", "10.231.2")),
}
UID = "%d:%d" % (os.getuid(), os.getgid())
PASSWORDS = {"201": "pw201", "202": "pw202", "203": "pw203", "211": "pw211", "213": "pw213"}
TONES = {"201": 700, "202": 600, "203": 440, "211": 900, "213": 1100}
HOST_SIP_PORT = 5070  # pjsua on the host binds the bridge gateway IPs


def sh(*args, check_rc=True, capture=True):
    r = subprocess.run(list(args), capture_output=capture, text=True)
    if check_rc and r.returncode != 0:
        raise RuntimeError("%s failed: %s" % (" ".join(args), (r.stderr or "").strip()))
    return r.stdout if capture else ""


def ip(net, host):
    return "%s.%d" % (NETS[net][1], host)


# ---------------------------------------------------------------- infrastructure


def cleanup(remove_networks=True):
    names = sh("docker", "ps", "-a", "--format", "{{.Names}}").split()
    mine = [n for n in names if n.startswith("pbxi-")]
    if mine:
        sh("docker", "rm", "-f", *mine, check_rc=False)
    if remove_networks:
        for net, _ in NETS.values():
            sh("docker", "network", "rm", net, check_rc=False)


def setup_networks():
    existing = sh("docker", "network", "ls", "--format", "{{.Name}}").split()
    for net, prefix in NETS.values():
        if net not in existing:
            sh("docker", "network", "create", "--subnet", prefix + ".0/24", net)


def ensure_image():
    if not sh("docker", "images", "-q", IMAGE).strip():
        print("building %s (one-off, ~1 min)..." % IMAGE)
        sh("docker", "build", "-t", IMAGE, "-f", os.path.join(HERE, "docker", "Dockerfile.ua"), os.path.join(HERE, "docker"))


def static_pbx():
    b = os.environ.get("PBX_STATIC_BIN")
    if b:
        return b
    env = dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static")
    subprocess.run(["cargo", "build", "-q", "--target-dir", "target/static"], cwd=REPO, check=True, env=env)
    return os.path.join(REPO, "target", "static", "debug", "tiny-pbx")


class DockerPbx(Pbx):
    """The PBX in a container on both networks; log via `docker logs -f`."""

    NAME = "pbxi-pbx"

    def __init__(self, binary, workdir, conf_text):
        os.makedirs(workdir, exist_ok=True)
        Pbx.__init__(self, binary, workdir, conf_text, name="pbx")
        self.addr = (ip("lan1", 2), 5060)
        self.logproc = None

    def start(self):
        self.runs += 1
        sh("docker", "rm", "-f", self.NAME, check_rc=False)
        sh(
            "docker", "create", "--name", self.NAME, "--user", UID,
            "--network", NETS["lan1"][0], "--ip", ip("lan1", 2),
            "-v", "%s:/tiny-pbx:ro" % self.binary, "-v", "%s:/data" % self.workdir,
            "-e", "PBX_LOG=debug", PBX_IMAGE, "/tiny-pbx", "-c", "/data/tiny-pbx.conf",
        )  # fmt: skip
        sh("docker", "network", "connect", "--ip", ip("lan2", 2), NETS["lan2"][0], self.NAME)
        sh("docker", "start", self.NAME)
        self.logproc = subprocess.Popen(
            ["docker", "logs", "-f", self.NAME],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        self.log = LineLog(self.logproc.stdout, os.path.join(self.workdir, "pbx.%d.log" % self.runs))
        self.log.expect(r"listening on udp", 10, what="pbx startup")
        return self

    def stop(self):
        sh("docker", "rm", "-f", self.NAME, check_rc=False)
        if self.logproc:
            self.logproc.wait(5)
            self.logproc = None

    def alive(self):
        return "true" in sh("docker", "inspect", "-f", "{{.State.Running}}", self.NAME, check_rc=False)

    def status(self):
        return sh("docker", "exec", self.NAME, "/tiny-pbx", "-c", "/data/tiny-pbx.conf", "status", check_rc=False)


class Baresip(PtyProc):
    def __init__(self, name, out, ext, net, host, pbx_ip):
        self.ext, self.pbx_ip, self.ip = ext, pbx_ip, ip(net, host)
        self.dir = os.path.join(out, name)
        os.makedirs(self.dir, exist_ok=True)
        write_tone(os.path.join(self.dir, "tone.wav"), TONES[ext])
        with open(os.path.join(self.dir, "config"), "w") as f:
            f.write(
                "poll_method epoll\nsip_listen 0.0.0.0:5060\nsip_trans_def udp\n"
                "audio_player aubridge,nullsink\naudio_alert aubridge,nullsink\n"
                "audio_source aufile,/cfg/tone.wav\n"
                "module_path /usr/lib/baresip/modules\n"
                "module stdio.so\nmodule g711.so\nmodule aufile.so\nmodule aubridge.so\n"
                "module sndfile.so\nmodule_app account.so\nmodule_app menu.so\n"
                "snd_path /cfg\n"
            )
        with open(os.path.join(self.dir, "accounts"), "w") as f:
            f.write("<sip:%s@%s;transport=udp>;auth_pass=%s;regint=300\n" % (ext, pbx_ip, PASSWORDS[ext]))
        args = [
            "docker", "run", "--rm", "-it", "--user", UID, "--name", "pbxi-" + name,
            "--network", NETS[net][0], "--ip", self.ip, "-v", "%s:/cfg" % self.dir,
            IMAGE, "baresip", "-f", "/cfg",
        ]  # fmt: skip
        PtyProc.__init__(self, name, out, args, r"registered successfully", 20)

    def uri(self, ext):
        return "sip:%s@%s" % (ext, self.pbx_ip)

    def dial(self, ext):
        self.send("/dial " + self.uri(ext))

    def accept(self):
        self.send("/accept")

    def hangup(self):
        self.send("/hangup")

    def wait_incoming(self, since, timeout=8):
        return self.expect(r"Incoming call from", timeout, since, "incoming call")

    def wait_ended(self, since, timeout=8):
        return self.expect(r"terminated \(duration|session closed", timeout, since, "call ended")

    def wait_connected(self, since, timeout=8):
        m = self.expect(r"Call established", timeout, since, "call established")
        # sndfile dumps what this call decodes into a new file
        d = self.expect(r"sndfile: dumping decode audio to /cfg/(\S+)", 3, since, "sndfile dump")
        self.rec = os.path.join(self.dir, d.group(1))
        return m

    def media_mark(self):
        wait_until(lambda: os.path.exists(self.rec), 3, "%s: %s" % (self.name, self.rec))
        return os.path.getsize(self.rec)

    def wait_media(self, mark, secs=MEDIA_SECS):
        wait_wav_growth(self.rec, mark, secs)

    def heard(self, mark, want, other):
        seg = wav_segment(self.rec, mark, self.rec + ".seg%d.wav" % mark)
        return check_tone(seg, want, other).split(": ", 1)[1]


class Linphone(PtyProc):
    def __init__(self, name, out, ext, net, host, pbx_ip):
        self.ext, self.pbx_ip, self.ip = ext, pbx_ip, ip(net, host)
        self.dir = os.path.join(out, name)
        self.ncall = 0
        os.makedirs(os.path.join(self.dir, ".local", "share", "linphone"), exist_ok=True)
        write_tone(os.path.join(self.dir, "tone.wav"), TONES[ext])
        with open(os.path.join(self.dir, "linphonerc"), "w") as f:
            f.write(
                "[sip]\nsip_port=5060\nsip_tcp_port=0\nsip_tls_port=0\nauto_net_state_mon=0\n"
                "register_only_when_network_is_up=0\nregister_only_when_upnp_is_ok=0\n"
                "ipv6_enabled=0\n\n[rtp]\naudio_rtp_port=7078\n\n[sound]\nechocancellation=0\n\n"
                "[video]\ncapture=0\ndisplay=0\nautomatically_initiate=0\nautomatically_accept=0\n"
            )
        args = [
            "docker", "run", "--rm", "-it", "--user", UID, "-e", "HOME=/cfg", "--name", "pbxi-" + name,
            "--network", NETS[net][0], "--ip", self.ip, "-v", "%s:/cfg" % self.dir,
            IMAGE, "linphonec", "-d", "5", "-l", "/cfg/linphone.log", "-c", "/cfg/linphonerc",
        ]  # fmt: skip
        PtyProc.__init__(self, name, out, args, r"video is disabled in linphonec|linphonec>", 20)
        self.send("soundcard use files", "play /cfg/tone.wav")
        self.send("register sip:%s@%s sip:%s %s" % (ext, pbx_ip, pbx_ip, PASSWORDS[ext]))
        deadline = time.time() + 10
        while True:
            m = self.mark()
            self.send("status register")
            try:
                self.expect(r"registered, identity=|registered=1", 1, m)
                break
            except Fail:
                if time.time() > deadline:
                    raise Fail("%s: not registered" % name)

    def uri(self, ext):
        return "sip:%s@%s" % (ext, self.pbx_ip)

    def new_recording(self):
        # only while a call is up: "record" on a ringing call crashes linphonec 5.1
        self.ncall += 1
        self.rec = "rec%02d.wav" % self.ncall
        self.send("play /cfg/tone.wav", "record /cfg/" + self.rec)

    def media_mark(self):
        path = os.path.join(self.dir, self.rec)
        wait_until(lambda: os.path.exists(path), 3, "%s: %s" % (self.name, path))
        return os.path.getsize(path)

    def wait_media(self, mark, secs=MEDIA_SECS):
        # linphonec buffers its recording (written in ~5 s chunks, and when
        # the call ends), so there is nothing to watch: just talk long enough
        time.sleep(secs + 0.2)

    def heard(self, mark, want, other):
        """Call after the call ended (that flushes the recording)."""
        path = os.path.join(self.dir, self.rec)
        wait_wav_growth(path, mark, MEDIA_SECS, timeout=3)
        seg = wav_segment(path, mark, path + ".seg%d.wav" % mark)
        return check_tone(seg, want, other).split(": ", 1)[1]

    def dial(self, ext):
        self.send("call " + self.uri(ext))

    def accept(self):
        self.send("answer")

    def hangup(self):
        self.send("terminate")

    def wait_incoming(self, since, timeout=8):
        return self.expect(r"Receiving new incoming call from", timeout, since, "incoming call")

    def wait_ringing(self, since, timeout=8):
        """As caller: the callee's 180 arrived (linphone logs it in its log file only)."""
        return self.expect(r"Call \d+ to .* (in progress|ringing)", timeout, since, "call in progress")

    def wait_connected(self, since, timeout=8):
        m = self.expect(r"Call \d+ with .* connected", timeout, since, "call connected")
        self.new_recording()
        return m

    def wait_ended(self, since, timeout=8):
        return self.expect(r"Call \d+ with .* (ended|error)|[Cc]all (declined|terminated)|busy", timeout, since, "call ended")


class HostPjsua(Pjsua):
    def __init__(self, name, out, ext, net, pbx_ip):
        self.dir = out
        self.ip = ip(net, 1)
        write_tone(os.path.join(out, name + "_tone.wav"), TONES[ext])
        Pjsua.__init__(
            self,
            name,
            out,
            ext,
            PASSWORDS[ext],
            HOST_SIP_PORT,
            8000 if net == "lan1" else 8100,
            pbx_host=pbx_ip,
            bound_addr=ip(net, 1),
            play=os.path.join(out, name + "_tone.wav"),
            rec=os.path.join(out, name + "_rec.wav"),
        )
        self.wait_registered(0, 8)
        self.seg = 0

    def dial(self, ext):
        self.call(ext)

    def accept(self):
        self.answer(200)

    def wait_incoming(self, since, timeout=8):
        self.expect(r"Incoming call for account", timeout, since, "incoming call")
        self.answer(180)

    def wait_connected(self, since, timeout=8):
        m = self.expect(r"Call \d+ state changed to CONFIRMED", timeout, since, "CONFIRMED")
        self.play_into_calls()
        return m

    def wait_ended(self, since, timeout=8):
        return self.expect(r"is DISCONNECTED", timeout, since, "DISCONNECTED")

    def media_mark(self):
        return self.rec_mark()

    def wait_media(self, mark, secs=MEDIA_SECS):
        self.wait_recorded(mark, secs)

    def heard(self, mark, want, other):
        self.seg += 1
        seg = self.rec_segment(mark, os.path.join(self.dir, "%s_seg%02d.wav" % (self.name, self.seg)))
        return check_tone(seg, want, other).split(": ", 1)[1]


# ---------------------------------------------------------------- tests


class Env:
    def __init__(self):
        self.out = fresh_dir(os.path.join(HERE, "out", "docker"))
        self.pbx_ip = ip("lan1", 2)
        self.pbx_ip2 = ip("lan2", 2)
        conf = "listen = 0.0.0.0:5060\nrealm = pbx\n[extensions]\n" + "".join(
            "%s = %s\n" % kv for kv in sorted(PASSWORDS.items())
        )
        conf += "[groups]\n250 = 201 202 203\n"
        self.pbx = DockerPbx(static_pbx(), os.path.join(self.out, "pbx"), conf)
        self.ua = {}

    def close(self):
        pj = [u for u in self.ua.values() if isinstance(u, Pjsua)]
        others = [u for u in self.ua.values() if not isinstance(u, Pjsua)]
        for u in others:
            try:
                u.send("/quit" if isinstance(u, Baresip) else "quit")
            except OSError:
                pass
        quit_all(pj)
        for u in others:
            u.stop()
        self.pbx.stop()


def pkts(env, since, direction=None, peer=None, first=None, contains=None):
    """PBX log packets (`peer` is an IP); after a sync barrier."""
    env.pbx.sync()
    return env.pbx.find(since, direction, peer, first, contains)


def talk(a, b):
    """Let both sides record MEDIA_SECS of each other from now on."""
    ma, mb = a.media_mark(), b.media_mark()
    a.wait_media(ma)
    b.wait_media(mb)
    return ma, mb


def heard_both(a, b, ma, mb):
    """Each side's recording since its mark contains the other's tone
    (linphone's recording is only complete once the call has ended)."""
    return "%s heard %s; %s heard %s" % (
        a.ext,
        a.heard(ma, TONES[b.ext], TONES[a.ext]),
        b.ext,
        b.heard(mb, TONES[a.ext], TONES[b.ext]),
    )


def call(env, caller, callee, hang="caller", media=True):
    """caller dials callee's extension, callee answers, both talk, one hangs up.
    Returns a detail string with what each side heard."""
    mc, me = caller.mark(), callee.mark()
    caller.dial(callee.ext)
    callee.wait_incoming(me)
    callee.accept()
    caller.wait_connected(mc)
    callee.wait_connected(me)
    marks = talk(caller, callee) if media else None
    mc2, me2 = caller.mark(), callee.mark()
    (caller if hang == "caller" else callee).hangup()
    caller.wait_ended(mc2)
    callee.wait_ended(me2)
    return heard_both(caller, callee, *marks) if media else ""


def t_register(env):
    ua = env.ua
    makers = {
        "bs201": lambda: Baresip("bs201", env.out, "201", "lan1", 11, env.pbx_ip),
        "lp202": lambda: Linphone("lp202", env.out, "202", "lan1", 12, env.pbx_ip),
        "pj203": lambda: HostPjsua("pj203", env.out, "203", "lan1", env.pbx_ip),
        "bs211": lambda: Baresip("bs211", env.out, "211", "lan2", 11, env.pbx_ip2),
        "pj213": lambda: HostPjsua("pj213", env.out, "213", "lan2", env.pbx_ip2),
    }
    errors = []

    def start(name):
        try:
            ua[name] = makers[name]()
        except Exception as e:  # reported below
            errors.append("%s: %s" % (name, e))

    threads = [threading.Thread(target=start, args=(n,)) for n in makers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check(not errors, "; ".join(errors))
    st = env.pbx.status()
    for u in ua.values():
        registered = re.search(r"^%s\s+%s:" % (u.ext, re.escape(u.ip)), st, re.M)
        check(registered, "%s (%s) missing from pbx status:\n%s" % (u.ext, u.ip, st))
    agents = re.findall(r"^\d+\s+\S+\s+\S+\s+(.*)$", st, re.M)
    return "registered: " + ", ".join(sorted(set(a.split(" (")[0] for a in agents)))


def t_pair(a, b, hang):
    def t(env):
        return call(env, env.ua[a], env.ua[b], hang)

    return t


def t_busy(env):
    pj, bs = env.ua["pj203"], env.ua["bs201"]
    mc, me = pj.mark(), bs.mark()
    pj.dial("201")
    bs.wait_incoming(me)
    bs.hangup()  # reject
    m = pj.expect(r"is DISCONNECTED \[reason=(\d+)", 8, mc)
    check(m.group(1).startswith("4") or m.group(1).startswith("6"), "baresip reject gave %s" % m.group(1))
    lp = env.ua["lp202"]
    mc, me = pj.mark(), lp.mark()
    pj.dial("202")
    lp.wait_incoming(me)
    lp.send("terminate")
    m2 = pj.expect(r"is DISCONNECTED \[reason=(\d+)", 8, mc)
    return "baresip reject -> %s, linphone reject -> %s" % (m.group(1), m2.group(1))


def t_cancel(env):
    lp, bs = env.ua["lp202"], env.ua["bs201"]
    p0 = env.pbx.log.mark()
    mc, me = lp.mark(), bs.mark()
    lp.dial("201")
    bs.wait_incoming(me)
    lp.wait_ringing(mc)
    lp.hangup()
    bs.wait_ended(me)
    lp.wait_ended(mc)
    check(pkts(env, p0, ">>>", bs.ip, r"^CANCEL "), "CANCEL not forwarded to baresip")
    check(pkts(env, p0, ">>>", lp.ip, r"^SIP/2.0 487"), "487 not relayed to linphone")
    return "linphone CANCEL -> baresip 487"


def t_hold(env):
    lp, pj = env.ua["lp202"], env.ua["pj203"]
    mc, me = lp.mark(), pj.mark()
    lp.dial("203")
    pj.wait_incoming(me)
    pj.accept()
    lp.wait_connected(mc)
    pj.wait_connected(me)
    m, ml = pj.mark(), lp.mark()
    lp.send("pause")
    pj.expect(r"status is Remote hold|status is Inactive", 8, m, "remote hold at pjsua")
    lp.expect(r"is now paused", 8, ml, "linphone: call paused")
    m = pj.mark()
    lp.send("resume")
    pj.expect(r"status is Active", 8, m, "resumed at pjsua")
    # (linphonec stops recording on pause, and `record` again crashes it, so
    # only pjsua's direction is checked after the resume)
    mk = pj.media_mark()
    pj.wait_media(mk)
    detail = pj.heard(mk, TONES["202"], TONES["203"])
    mm = lp.mark()
    pj.hangup()
    lp.wait_ended(mm)
    return "linphone pause/resume; after resume pjsua heard " + detail


def t_transfer(env):
    """pjsua 203 calls linphone 202; linphone blind-transfers 203 to baresip 201."""
    lp, pj, bs = env.ua["lp202"], env.ua["pj203"], env.ua["bs201"]
    p0 = env.pbx.log.mark()
    mc, me, mb = pj.mark(), lp.mark(), bs.mark()
    pj.dial("202")
    lp.wait_incoming(me)
    lp.accept()
    pj.wait_connected(mc)
    lp.wait_connected(me)
    m = re.search(r"Call (\d+) with", lp.expect(r"Call \d+ with .* connected", 1, me).group(0))
    lp.send("transfer %s %s" % (m.group(1), lp.uri("201")))
    bs.wait_incoming(mb)
    bs.accept()
    bs.wait_connected(mb)
    first = pj.expect(r"Call (\d+) state changed to CONFIRMED", 1, mc).group(1)
    pj.expect(r"Call (?!%s )\d+ state changed to CONFIRMED" % first, 8, mc, "203's new call to 201")
    lp.wait_ended(me)
    pj.expect(r"Call %s is DISCONNECTED" % first, 8, mc, "203's call with 202 ended")
    pj.play_into_calls()
    check(pkts(env, p0, ">>>", pj.ip, r"^REFER "), "REFER not relayed to pjsua")
    detail = heard_both(pj, bs, *talk(pj, bs))
    mb2 = bs.mark()
    pj.send("ha")
    bs.wait_ended(mb2)
    return "REFER from linphone; 203<->201 media: " + detail


def t_message(env):
    lp, pj = env.ua["lp202"], env.ua["pj203"]
    m = pj.mark()
    lp.send("chat %s hello-from-linphone" % lp.uri("203"))
    pj.expect(r"MESSAGE from .*202.*hello-from-linphone", 8, m, "MESSAGE at pjsua")
    m = lp.mark()
    pj.send("i", pj.uri("202"), "hello-from-pjsua")
    lp.expect(r"hello-from-pjsua", 8, m, "MESSAGE at linphone")
    return "linphone <-> pjsua MESSAGE both ways"


def rr_list(text):
    return re.findall(r"^Record-Route: <sip:([0-9.]+):\d+;lr(?:;[^>]*)?>", text, re.M)


def t_multi_if_signalling(env):
    """baresip on lan1 calls baresip on lan2: double Record-Route, BYE both ways."""
    a, b = env.ua["bs201"], env.ua["bs211"]
    p0 = env.pbx.log.mark()
    mc, me = a.mark(), b.mark()
    a.dial("211")
    b.wait_incoming(me)
    b.accept()
    a.wait_connected(mc)
    b.wait_connected(me)
    inv = pkts(env, p0, ">>>", b.ip, r"^INVITE ")
    check(inv, "INVITE not forwarded to lan2")
    rr = rr_list(inv[0][3])
    check(rr == [env.pbx_ip2, env.pbx_ip], "Record-Route towards lan2 phone is %s, expected [%s, %s]" % (rr, env.pbx_ip2, env.pbx_ip))
    via = re.search(r"^Via: SIP/2.0/UDP ([0-9.]+):", inv[0][3], re.M).group(1)
    check(via == env.pbx_ip2, "top Via towards lan2 is %s" % via)
    ok200 = pkts(env, p0, ">>>", a.ip, r"^SIP/2.0 200", r"CSeq: \d+ INVITE")
    check(ok200 and rr_list(ok200[0][3]) == rr, "200 OK to caller lost the Record-Routes")
    # Media between two docker bridges is normally blocked by docker's
    # isolation rules (the PBX does not relay RTP): listen for a while and
    # report what got through, don't fail.
    marks = [(ua, peer, ua.media_mark()) for ua, peer in ((a, b), (b, a))]
    time.sleep(MEDIA_SECS + 0.3)
    heard = []
    for ua, peer, mk in marks:
        try:
            ua.heard(mk, TONES[peer.ext], TONES[ua.ext])
            heard.append("%s heard %dHz" % (ua.ext, TONES[peer.ext]))
        except Fail:
            heard.append("%s no audio" % ua.ext)
    p1 = env.pbx.log.mark()
    mb = a.mark()
    b.hangup()  # BYE from lan2 to lan1
    a.wait_ended(mb)
    bye = pkts(env, p1, "<<<", b.ip, r"^BYE ")
    check(bye, "no BYE from the lan2 phone")
    routes = re.findall(r"^Route: <sip:([0-9.]+):\d+;lr(?:;[^>]*)?>", bye[0][3], re.M)
    check(routes == [env.pbx_ip2, env.pbx_ip], "lan2 phone's BYE Route set %s" % routes)
    check(pkts(env, p1, ">>>", a.ip, r"^BYE "), "BYE not relayed to lan1")
    return "RR [%s, %s] / Route set ok, BYE lan2->lan1 ok; media: %s (docker blocks inter-bridge traffic)" % (
        env.pbx_ip2,
        env.pbx_ip,
        ", ".join(heard),
    )


def t_multi_if_media(env):
    """pjsua on the host's lan2 address <-> baresip on lan1: double RR + media."""
    pj, bs = env.ua["pj213"], env.ua["bs201"]
    p0 = env.pbx.log.mark()
    d1 = call(env, pj, bs, hang="callee")
    inv = pkts(env, p0, ">>>", bs.ip, r"^INVITE ")
    check(rr_list(inv[0][3]) == [env.pbx_ip, env.pbx_ip2], "RR towards lan1: %s" % rr_list(inv[0][3]))
    p1 = env.pbx.log.mark()
    d2 = call(env, bs, pj, hang="caller")
    inv = pkts(env, p1, ">>>", pj.ip, r"^INVITE ")
    check(rr_list(inv[0][3]) == [env.pbx_ip2, env.pbx_ip], "RR towards lan2: %s" % rr_list(inv[0][3]))
    return "213->201 (%s); 201->213 (%s)" % (d1, d2)


def t_group(env):
    """Ring group 250 = baresip 201 + linphone 202 + pjsua 203, called from
    pjsua 213 on the other network: all ring, one answers, the rest are
    cancelled; media with the one that answered."""
    c = env.ua["pj213"]
    members = [env.ua["bs201"], env.ua["lp202"], env.ua["pj203"]]
    res = []
    for winner in (env.ua["lp202"], env.ua["bs201"], env.ua["pj203"]):
        p0 = env.pbx.log.mark()
        mc = c.mark()
        marks = {m.name: m.mark() for m in members}
        c.dial("250")
        for m in members:
            m.wait_incoming(marks[m.name])
        winner.accept()
        c.wait_connected(mc)
        winner.wait_connected(marks[winner.name])
        for m in members:
            if m is not winner:
                m.wait_ended(marks[m.name])
                check(pkts(env, p0, ">>>", m.ip, r"^CANCEL "), "no CANCEL to %s" % m.name)
        marks = talk(c, winner)
        mc2, mw = c.mark(), winner.mark()
        c.hangup()
        c.wait_ended(mc2)
        winner.wait_ended(mw)
        res.append("%s answered (%s)" % (winner.name, heard_both(c, winner, *marks)))
    return "; ".join(res) + "; the other two were cancelled each time"


TESTS = [
    ("register baresip/linphone/pjsua", t_register),
    ("baresip -> linphone", t_pair("bs201", "lp202", "caller")),
    ("linphone -> baresip", t_pair("lp202", "bs201", "callee")),
    ("pjsua -> baresip", t_pair("pj203", "bs201", "caller")),
    ("baresip -> pjsua", t_pair("bs201", "pj203", "callee")),
    ("pjsua -> linphone", t_pair("pj203", "lp202", "callee")),
    ("linphone -> pjsua", t_pair("lp202", "pj203", "caller")),
    ("reject (baresip, linphone)", t_busy),
    ("linphone CANCEL", t_cancel),
    ("linphone hold/resume", t_hold),
    ("linphone blind transfer", t_transfer),
    ("MESSAGE linphone <-> pjsua", t_message),
    ("2 interfaces: signalling", t_multi_if_signalling),
    ("2 interfaces: media via host", t_multi_if_media),
    ("ring group: baresip+linphone+pjsua", t_group),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", action="store_true", help="keep the docker networks afterwards")
    ap.add_argument("--only", help="comma-separated substrings of test names")
    args = ap.parse_args(argv)
    wanted = select_tests(ap, TESTS, args.only)
    ensure_image()
    cleanup(remove_networks=False)
    setup_networks()
    env = Env()
    suite = Suite("docker interop (baresip 1.0, linphonec 5.1, pjsua 2.17)")
    ok = False
    t0 = time.time()
    try:
        env.pbx.start()
        for name, fn in TESTS:
            if name not in wanted and fn is not t_register:
                continue
            ok_ = suite.run(name, fn, env)
            if not ok_ and fn is t_register:
                break
            if not ok_:  # clean up whatever the failed test left behind
                for u in env.ua.values():
                    if isinstance(u, Pjsua):
                        u.hangup_all()
                    elif isinstance(u, Baresip):
                        u.send("/hangup")
                    else:
                        u.send("terminate all")
                time.sleep(1)
            for u in env.ua.values():
                if u.proc.poll() is not None:
                    raise Fail("%s exited" % u.name)
        if not env.pbx.alive():  # a crash that no test noticed
            suite.results.append(("(harness)", False, "the PBX container exited by itself", 0))
        ok = suite.summary(time.time() - t0)
    finally:
        env.close()
        cleanup(remove_networks=not args.keep)
    print("logs: %s" % env.out)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
