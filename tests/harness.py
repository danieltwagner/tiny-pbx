"""Shared helpers for the interop tests: run the PBX, drive pjsua over its
stdin CLI, run sipp scenarios, analyse recorded WAV files, report results.

Only the Python standard library is used.
"""

import math
import os
import pty
import re
import shutil
import struct
import subprocess
import sys
import termios
import threading
import time
import traceback
import wave

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


class Fail(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Fail(msg)


# ------------------------------------------------------------------ results


def select_tests(parser, tests, only, skip_by_default=()):
    """Resolve every --only term before starting processes or touching test networks."""
    names = {test[0] for test in tests}
    if only is None:
        return names.difference(skip_by_default)
    wanted = set()
    for term in map(str.strip, only.split(",")):
        matches = {name for name in names if term and term in name}
        if not matches:
            parser.error("--only: no test matches %r" % term)
        wanted.update(matches)
    return wanted


class Suite:
    def __init__(self, name):
        self.name = name
        self.results = []  # (name, ok, detail, secs)

    lock = threading.Lock()

    def run(self, name, fn, *a, **kw):
        t0 = time.time()
        try:
            detail = fn(*a, **kw) or ""
            ok = True
        except Fail as e:
            ok, detail = False, str(e)
        except Exception as e:  # harness bug or UA crash: still a FAIL
            ok, detail = False, "%s: %s" % (type(e).__name__, e)
            traceback.print_exc()
        secs = time.time() - t0
        with self.lock:
            self.results.append((name, ok, detail, secs))
            print("%-34s %s  (%.1fs)%s" % (name, "PASS" if ok else "FAIL", secs, "  " + detail if detail else ""))
            sys.stdout.flush()
        return ok

    def summary(self, wall=None):
        failed = [r for r in self.results if not r[1]]
        print()
        print("=" * 72)
        print(
            "%s: %d tests, %d passed, %d failed%s"
            % (
                self.name,
                len(self.results),
                len(self.results) - len(failed),
                len(failed),
                " in %.0fs" % wall if wall is not None else "",
            )
        )
        for name, _, detail, _ in failed:
            print("  FAIL %s: %s" % (name, detail))
        return not failed


# ------------------------------------------------------------------ processes


class LineLog:
    """Collects the lines a child process prints, with a cursor for expect()."""

    def __init__(self, stream, path):
        self.lines = []
        self.cv = threading.Condition()
        self.f = open(path, "w", buffering=1)
        self.closed = False
        t = threading.Thread(target=self._read, args=(stream,), daemon=True)
        t.start()

    def _read(self, stream):
        while True:
            try:
                raw = stream.readline()
            except OSError:  # pty closed (EIO)
                break
            if not raw:
                break
            line = raw.rstrip("\r\n")
            self.f.write(line + "\n")
            with self.cv:
                self.lines.append(line)
                self.cv.notify_all()
        with self.cv:
            self.closed = True
            self.cv.notify_all()
        self.f.close()

    def mark(self):
        with self.cv:
            return len(self.lines)

    def expect(self, pattern, timeout=5.0, since=0, what=None):
        """Wait for a line matching `pattern` (at or after index `since`).
        Returns (match, index_after)."""
        rx = re.compile(pattern)
        deadline = time.time() + timeout
        i = since
        with self.cv:
            while True:
                while i < len(self.lines):
                    m = rx.search(self.lines[i])
                    i += 1
                    if m:
                        return m, i
                left = deadline - time.time()
                if left <= 0 or self.closed:
                    raise Fail("timeout waiting for %s" % (what or repr(pattern)))
                self.cv.wait(left)

    def grep(self, pattern, since=0):
        rx = re.compile(pattern)
        with self.cv:
            return [l for l in self.lines[since:] if rx.search(l)]


def wait_until(fn, timeout, what):
    """Poll fn() until it returns something truthy."""
    deadline = time.time() + timeout
    while True:
        v = fn()
        if v:
            return v
        if time.time() > deadline:
            raise Fail("timeout waiting for %s" % what)
        time.sleep(0.02)


def udp_bound(ip, port):
    """Is some process bound to UDP ip:port (IPv4)?"""
    want = "%08X:%04X" % (int.from_bytes(bytes(map(int, ip.split("."))), "little"), port)
    with open("/proc/net/udp") as f:
        return any(l.split()[1] == want for l in list(f)[1:])


class Pbx:
    """The PBX under test, running on the host with PBX_LOG=debug."""

    def __init__(self, binary, workdir, conf_text, name="pbx"):
        self.binary = binary
        self.workdir = workdir
        self.conf = os.path.join(workdir, "tiny-pbx.conf")
        self.name = name
        with open(self.conf, "w") as f:
            f.write(conf_text)
        self.proc = None
        self.log = None
        self.runs = 0
        m = re.search(r"(?m)^listen = ([0-9.]+):(\d+)", conf_text)
        self.addr = (m.group(1), int(m.group(2))) if m else None
        self._sync_sock = None
        self._sync_n = 0

    def start(self):
        self.runs += 1
        env = dict(os.environ, PBX_LOG="debug")
        self.proc = subprocess.Popen(
            [self.binary, "-c", self.conf],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            errors="replace",
            env=env,
        )
        with open(os.path.join(self.workdir, "pbx.pid"), "w") as f:
            f.write(str(self.proc.pid))
        self.log = LineLog(
            self.proc.stdout, os.path.join(self.workdir, "%s.%d.log" % (self.name, self.runs))
        )
        self.log.expect(r"listening on udp", 5, what="pbx startup")
        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def died(self):
        """Exit status if the PBX went away by itself, e.g. crashed (None: it
        is running, was never started, or stop() stopped it)."""
        return self.proc.poll() if self.proc is not None else None

    def cpu_ticks(self):
        """utime+stime of the PBX process, in clock ticks (1/100 s)."""
        with open("/proc/%d/stat" % self.proc.pid) as f:
            parts = f.read().rsplit(")", 1)[1].split()
        return int(parts[11]) + int(parts[12])

    def sync(self, timeout=3.0):
        """Barrier: make sure everything the PBX logged so far has been read.
        Sends a marker OPTIONS (ignored by packets()) and waits for it."""
        import socket

        if self._sync_sock is None:
            self._sync_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sync_sock.bind(("0.0.0.0", 0))
        self._sync_n += 1
        tag = "pbxsync-%d-%d" % (os.getpid(), self._sync_n)
        host = "%s:%d" % self.addr
        msg = (
            "OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:9;rport;branch=z9hG4bK-%s\r\n"
            "From: <sip:sync@%s>;tag=s\r\nTo: <sip:%s>\r\nCall-ID: %s\r\nCSeq: 1 OPTIONS\r\n"
            "Max-Forwards: 70\r\nContent-Length: 0\r\n\r\n" % (host, tag, host, host, tag)
        )
        m = self.log.mark()
        self._sync_sock.sendto(msg.encode(), self.addr)
        # The marker is logged twice: as received and in the PBX's 200. Wait
        # for both, or packets() may see the first lines of that 200 without
        # the Call-ID that marks it, and report it as a packet of the test.
        for what in ("PBX log sync", "PBX log sync (reply)"):
            _, m = self.log.expect(r"Call-ID: %s" % tag, timeout, m, what=what)

    def find(self, since=0, direction=None, peer=None, first=None, contains=None):
        """Packets in the debug log since line `since` matching the filters
        (`peer`: "ip:port", or just "ip" for any port; `first`/`contains`:
        regexes on the first line / the whole message)."""
        out = []
        for d, p, fl, text in self.packets(since):
            if direction and d != direction:
                continue
            if peer and p != peer and not (":" not in peer and p.startswith(peer + ":")):
                continue
            if first and not re.search(first, fl):
                continue
            if contains and not re.search(contains, text):
                continue
            out.append((d, p, fl, text))
        return out

    def wait(self, since=0, n=1, timeout=3.0, what=None, **filters):
        """Wait until at least `n` packets match (see find())."""
        deadline = time.time() + timeout
        while True:
            got = self.find(since, **filters)
            if len(got) >= n:
                return got
            if time.time() > deadline:
                raise Fail("PBX log: timeout waiting for %s (%d of %d)" % (what or filters, len(got), n))
            time.sleep(0.02)

    def status(self):
        return subprocess.run(
            [self.binary, "-c", self.conf, "status"], capture_output=True, text=True
        ).stdout

    # --- debug log helpers: "<<< N bytes from A" / ">>> N bytes to A" blocks
    # (followed by " to L" / " from L", our address, on a wildcard listen)
    def packets(self, since=0):
        """Parse the debug log into (direction, peer, first_line, text) tuples."""
        out = []
        with self.log.cv:
            lines = self.log.lines[since:]
        cur = None
        for l in lines:
            m = re.match(r"^\S+ \S+ DEBUG (<<<|>>>) \d+ bytes (?:from|to) (\S+)(?: (?:to|from) \S+)?$", l)
            if m:
                if cur:
                    out.append(cur)
                cur = [m.group(1), m.group(2), None, []]
                continue
            if re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d (INFO |WARN |ERROR|DEBUG) ", l):
                if cur:
                    out.append(cur)
                cur = None
                continue
            if cur is not None:
                if cur[2] is None:
                    cur[2] = l.strip()
                cur[3].append(l)
        if cur:
            out.append(cur)
        res = [(d, p, fl or "", "\n".join(t)) for d, p, fl, t in out]
        return [r for r in res if "Call-ID: pbxsync-" not in r[3]]


class PtyProc:
    """A child process on a pty (so it line-buffers), driven via its stdin."""

    def __init__(self, name, workdir, args, ready=None, ready_timeout=10.0):
        self.name = name
        master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        self.proc = subprocess.Popen(
            args, stdin=slave, stdout=slave, stderr=slave, close_fds=True, start_new_session=True
        )
        os.close(slave)
        self.master = master
        self.tty = os.fdopen(master, "r", errors="replace")
        with open(os.path.join(workdir, name + ".pid"), "w") as f:
            f.write(str(self.proc.pid))
        self.log = LineLog(self.tty, os.path.join(workdir, name + ".out.log"))
        if ready:
            self.log.expect(ready, ready_timeout, what="%s startup" % name)

    # Lines are queued in the pty and read one per prompt, so no pacing is needed.
    def send(self, *lines):
        for l in lines:
            os.write(self.master, (l + "\n").encode())

    def mark(self):
        return self.log.mark()

    def expect(self, pattern, timeout=5.0, since=0, what=None):
        m, _ = self.log.expect(pattern, timeout, since, what="%s: %s" % (self.name, what or pattern))
        return m

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        try:
            self.proc.wait(3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class Pjsua(PtyProc):
    """A pjsua instance driven over its stdin menu interface."""

    def __init__(
        self,
        name,
        workdir,
        ext,
        password,
        sip_port,
        rtp_port,
        pbx_host="127.0.0.1",
        pbx_port=5060,
        register=True,
        auto_answer=None,
        play=None,
        rec=None,
        bound_addr=None,
        proxy=None,
        extra=(),
        cmd=("pjsua",),
        pcmu_only=True,
    ):
        self.name = name
        self.ext = ext
        self.pbx = "%s:%d" % (pbx_host, pbx_port) if pbx_port != 5060 else pbx_host
        self.rec = rec
        args = list(cmd) + [
            "--null-audio",
            "--no-tones",  # no local ring/ringback tones (440/480/640/800 Hz) in the recordings
            "--no-tcp",
            "--no-color",
            "--no-vad",
            "--local-port=%d" % sip_port,
            "--rtp-port=%d" % rtp_port,
            "--id=sip:%s@%s" % (ext, self.pbx),
            "--realm=*",
            "--username=%s" % ext,
            "--password=%s" % password,
            "--log-level=5",
            "--log-file=%s" % os.path.join(workdir, name + ".sip.log"),
            "--app-log-level=4",
            "--max-calls=4",
            "--duration=120",
        ]
        if pcmu_only:
            # G.711 like desk phones. With speex (pjsua's default), pjsua 2.17
            # garbles a stream whose source is connected right as the call
            # starts or after a forked 2xx (RTP on the wire is fine) -- a
            # pjsua quirk that only made the media checks wait longer.
            args += ["--dis-codec=" + c for c in ("speex", "iLBC", "GSM", "G722", "opus", "PCMA")]
        self.registers = register
        if register:
            args.append("--registrar=sip:%s" % self.pbx)
        if proxy:
            args.append("--proxy=%s" % proxy)
        if bound_addr:
            args += ["--bound-addr=%s" % bound_addr, "--ip-addr=%s" % bound_addr]
        if auto_answer:
            args.append("--auto-answer=%d" % auto_answer)
        if play:
            args += ["--play-file=%s" % play]
            if auto_answer:
                args.append("--auto-play")
        if rec:
            args += ["--rec-file=%s" % rec, "--auto-rec"]
        args += list(extra)
        PtyProc.__init__(self, name, workdir, args, r"Ready: Success|main\.c.*Ready")

    def uri(self, ext):
        return "sip:%s@%s" % (ext, self.pbx)

    def wait_registered(self, since=0, timeout=5.0):
        return self.expect(r"registration success, status=200", timeout, since, "registration")

    def call(self, ext):
        self.send("m", self.uri(ext))

    def hangup(self):
        self.send("h")

    def answer(self, code):
        self.send("a", str(code))

    def conf_ports(self):
        m = self.mark()
        self.send("cl")
        _, i = self.log.expect(r"Conference ports:", 3, m, what="%s: conference port list" % self.name)
        _, j = self.log.expect(r"^\s*$", 3, i, what="%s: end of port list" % self.name)
        ports = {}
        for l in self.log.lines[i:j]:
            mm = re.search(r"Port #(\d+)\[[^\]]*\]\s+(.*?)\s+transmitting to:", l)
            if mm:
                ports[int(mm.group(1))] = mm.group(2)
        return ports

    def play_into_calls(self, file_port=1):
        """Connect the --play-file player to every call's conference slot."""
        ports = self.conf_ports()
        slots = [p for p, n in ports.items() if n.startswith("sip:") or "@" in n]
        check(slots, "%s: no call in conference port list" % self.name)
        for s in slots:
            self.send("cc", str(file_port), str(s))
        return slots

    def rec_mark(self):
        """Current size of the --rec-file (it grows while a call is up)."""
        try:
            return os.path.getsize(self.rec)
        except OSError:
            return 0

    def wait_recorded(self, start, secs=1.0, timeout=5.0):
        """Wait until `secs` of audio were recorded since rec_mark() `start`
        (the conference bridge runs at 16 kHz, 16-bit mono)."""
        need = start + int(secs * 32000)
        deadline = time.time() + timeout
        while self.rec_mark() < need:
            check(time.time() < deadline, "%s: recorder stalled" % self.name)
            time.sleep(0.02)

    def rec_segment(self, start, path):
        """Write what was recorded since rec_mark() `start` to a WAV file."""
        return wav_segment(self.rec, start, path)

    def hangup_all(self, timeout=3.0):
        """`ha`, then wait until every call it hung up is DISCONNECTED."""
        m = self.mark()
        self.send("ha")
        mm, i = self.log.expect(r"Hangup all calls|No current call", timeout, m, what="%s: ha" % self.name)
        if mm.group(0).startswith("Hangup"):
            time.sleep(0.05)
            ids = {x for l in self.log.lines[i:] for x in re.findall(r"Call (\d+) hanging up", l)}
            for cid in ids:
                self.log.expect(r"Call %s is DISCONNECTED" % cid, timeout, m, what="%s: call %s ended" % (self.name, cid))

    def retire(self, timeout=3.0):
        """Quit without waiting for the process to exit (pjsua lingers ~1 s
        after unregistering); only wait until the unregistration is done."""
        m = self.mark()
        try:
            self.send("q")
        except OSError:
            return
        if self.registers and self.proc.poll() is None:
            try:
                self.expect(r"unregistration success|unregistration failed|PJSUA destroyed", timeout, m, "unregistration")
            except Fail:
                pass


def run_sipp(workdir, scenario, remote, local_port, extra=(), timeout=30, name=None, background=False):
    """Run a sipp scenario (file, or None to pass -sn in `extra`). Returns the
    exit code, or the Popen when background=True. One call unless `extra`
    overrides -m."""
    name = name or os.path.splitext(os.path.basename(scenario))[0]
    args = ["sipp"] + ([remote] if remote else []) + (["-sf", scenario] if scenario else [])
    if not any(a == "-m" for a in extra):
        args += ["-m", "1"]
    args += [
        "-i",
        "127.0.0.1",
        "-p",
        str(local_port),
        "-nostdin",
        "-nd",
        "-timeout",
        "%ds" % timeout,
        "-timeout_error",
        "-max_recv_loops",
        "1000",
        "-trace_msg",
        "-message_file",
        os.path.join(workdir, name + ".msg.log"),
        "-trace_err",
        "-error_file",
        os.path.join(workdir, name + ".err.log"),
        "-trace_screen",
        "-screen_file",
        os.path.join(workdir, name + ".screen.log"),
    ] + list(extra)
    logf = open(os.path.join(workdir, name + ".out.log"), "w")
    p = subprocess.Popen(args, stdout=logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=workdir)
    with open(os.path.join(workdir, name + ".pid"), "w") as f:
        f.write(str(p.pid))
    if background:
        return p
    try:
        rc = p.wait(timeout + 10)
    except subprocess.TimeoutExpired:
        p.kill()
        rc = -9
    return rc


def sipp_error_text(workdir, name):
    out = []
    for suffix in (".err.log", ".out.log"):
        try:
            with open(os.path.join(workdir, name + suffix), errors="replace") as f:
                out.append(f.read()[-600:])
        except FileNotFoundError:
            pass
    return " | ".join(s.strip().replace("\n", " ") for s in out if s.strip())


# ------------------------------------------------------------------ audio


def write_tone(path, freq, secs=10, rate=8000, amp=8000):
    """A sine tone; whole-Hz tones repeat seamlessly every second (players loop)."""
    one = struct.pack("<%dh" % rate, *(int(amp * math.sin(2 * math.pi * freq * i / rate)) for i in range(rate)))
    w = wave.open(path, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(rate)
    w.writeframes(one * secs)
    w.close()


def quit_all(uas):
    """Quit several pjsua instances at once (each takes ~1 s to unregister
    and close its sound device)."""
    uas = list(uas)
    for ua in uas:
        if ua.proc.poll() is None:
            try:
                ua.send("q")
            except OSError:
                pass
    # Let them all finish unregistering before stop() resorts to SIGTERM.
    deadline = time.time() + 5
    for ua in uas:
        try:
            ua.proc.wait(max(0.0, deadline - time.time()))
        except subprocess.TimeoutExpired:
            pass
        ua.stop()


def analyse_wav(path, freqs, skip=0.0):
    """Return (seconds, rms, {freq: magnitude}) of a mono 16-bit WAV."""
    w = wave.open(path)
    rate, n, ch = w.getframerate(), w.getnframes(), w.getnchannels()
    raw = w.readframes(n)
    w.close()
    data = struct.unpack("<%dh" % (len(raw) // 2), raw)[::ch]
    data = data[int(skip * rate) :]
    if not data:
        return 0.0, 0.0, {f: 0.0 for f in freqs}
    rms = math.sqrt(sum(x * x for x in data) / len(data))
    mags = {}
    for f in freqs:
        k = 2 * math.cos(2 * math.pi * f / rate)
        s1 = s2 = 0.0
        for x in data:
            s1, s2 = x + k * s1 - s2, s1
        mags[f] = math.sqrt(max(0.0, s1 * s1 + s2 * s2 - k * s1 * s2)) / len(data)
    return len(data) / rate, rms, mags


def wav_info(path):
    """(rate, channels, data offset) of a 16-bit PCM WAV that may still be
    being written (its header sizes are not trusted)."""
    with open(path, "rb") as f:
        head = f.read(4096)
    i, d = head.find(b"fmt "), head.find(b"data")
    check(i >= 0 and d >= 0, "%s: not a WAV file (yet)" % path)
    ch, rate = struct.unpack("<HI", head[i + 10 : i + 16])
    return rate, ch, d + 8


def wav_segment(src, start, path):
    """Copy the audio of a growing WAV file from byte offset `start` (e.g. its
    size at some earlier moment) to a new mono WAV `path`."""
    rate, ch, hdr = wav_info(src)
    frame = 2 * ch
    start = max(start, hdr)
    start -= (start - hdr) % frame
    with open(src, "rb") as f:
        f.seek(start)
        pcm = f.read()
    pcm = pcm[: len(pcm) - len(pcm) % frame]
    if ch > 1:
        samples = struct.unpack("<%dh" % (len(pcm) // 2), pcm)[::ch]
        pcm = struct.pack("<%dh" % len(samples), *samples)
    w = wave.open(path, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(rate)
    w.writeframes(pcm)
    w.close()
    return path


def wait_wav_growth(src, start, secs, timeout=5.0):
    """Wait until `secs` of audio were appended to WAV `src` after offset `start`."""
    deadline = time.time() + timeout
    while True:
        try:
            rate, ch, hdr = wav_info(src)
            if os.path.getsize(src) >= max(start, hdr) + int(secs * rate) * 2 * ch:
                return
        except (OSError, Fail):
            pass
        check(time.time() < deadline, "%s: recording stalled" % os.path.basename(src))
        time.sleep(0.02)


# Seconds of audio each media check records, and how much of its start is
# skipped (jitter buffer fill, the tone being switched on).
MEDIA_SECS = 1.0
MEDIA_SKIP = 0.25


def check_tone(path, want, other, min_rms=300):
    """The recording must contain tone `want` (and clearly not tone `other`)."""
    check(os.path.exists(path), "no recording %s" % os.path.basename(path))
    secs, rms, mags = analyse_wav(path, [want, other], skip=MEDIA_SKIP)
    check(secs > 0.5, "%s: recording too short (%.1fs)" % (os.path.basename(path), secs))
    check(rms > min_rms, "%s: silent (rms %.0f)" % (os.path.basename(path), rms))
    check(
        mags[want] > 5 * max(mags[other], 1.0),
        "%s: %d Hz not dominant (%s)" % (os.path.basename(path), want, mags),
    )
    return "%s: %dHz rms=%.0f" % (os.path.basename(path), want, rms)


def find_bin():
    b = os.environ.get("PBX_BIN")
    if b:
        return b
    subprocess.run(["cargo", "build", "-q"], cwd=REPO, check=True)
    return os.path.join(REPO, "target", "debug", "tiny-pbx")


def fresh_dir(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.makedirs(path)
    return path


# ------------------------------------------------------------------ raw SIP


def md5(s):
    import hashlib

    return hashlib.md5(s.encode()).hexdigest()


def digest_header(name, challenge, method, uri, user, password, nc=1, cnonce="0a4f113b"):
    """Build an Authorization / Proxy-Authorization header for a challenge."""
    realm = re.search(r'realm="([^"]*)"', challenge).group(1)
    nonce = re.search(r'nonce="([^"]*)"', challenge).group(1)
    ha1 = md5("%s:%s:%s" % (user, realm, password))
    ha2 = md5("%s:%s" % (method, uri))
    resp = md5("%s:%s:%08x:%s:auth:%s" % (ha1, nonce, nc, cnonce, ha2))
    return (
        '%s: Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", '
        'algorithm=MD5, qop=auth, nc=%08x, cnonce="%s"' % (name, user, realm, nonce, uri, resp, nc, cnonce)
    )


class RawUA:
    """A hand-made UDP SIP endpoint for protocol corner cases."""

    def __init__(self, local, remote):
        import socket

        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(local)
        self.local = local
        self.remote = remote
        self.n = 0

    def send(self, text):
        if "Content-Length" not in text:
            text = text.rstrip("\r\n") + "\r\nContent-Length: 0\r\n\r\n"
        self.s.sendto(text.replace("\r\n", "\n").replace("\n", "\r\n").encode(), self.remote)

    def recv(self, timeout=3.0):
        import socket

        self.s.settimeout(timeout)
        try:
            data, _ = self.s.recvfrom(65536)
        except socket.timeout:
            return None
        return data.decode(errors="replace")

    def register(self, ext, expires=300, auth=None, cseq=1, call_id=None, contact=None):
        self.n += 1
        ruri = "sip:%s:%d" % self.remote
        contact = contact or "<sip:%s@%s:%d>" % (ext, self.local[0], self.local[1])
        msg = (
            "REGISTER %s SIP/2.0\n"
            "Via: SIP/2.0/UDP %s:%d;rport;branch=z9hG4bK-raw-%d-%d\n"
            "From: <sip:%s@%s>;tag=raw%d\nTo: <sip:%s@%s>\n"
            "Call-ID: %s\nCSeq: %d REGISTER\nContact: %s\nExpires: %d\nMax-Forwards: 70\n"
            % (
                ruri,
                self.local[0],
                self.local[1],
                os.getpid(),
                self.n,
                ext,
                self.remote[0],
                os.getpid(),
                ext,
                self.remote[0],
                call_id or "raw-reg-%s-%d" % (ext, os.getpid()),
                cseq,
                contact,
                expires,
            )
        )
        if auth:
            msg += auth + "\n"
        self.send(msg)
        return self.recv()

    def close(self):
        self.s.close()


def first_line(msg):
    return msg.splitlines()[0] if msg else "(no response)"


def header(msg, name):
    for l in (msg or "").splitlines():
        if l.lower().startswith(name.lower() + ":"):
            return l.split(":", 1)[1].strip()
    return None
