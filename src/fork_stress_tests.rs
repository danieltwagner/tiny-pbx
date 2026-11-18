//! Randomized fork stress tests: a caller and 2-4 phones with packet loss,
//! frozen phones, ignored CANCELs, answers and rejections, in simulated time.
//! Responses after fork expiry are dropped, just as in the proxy; only phones
//! that respond while state exists can expect cleanup.
//!
//! Defaults use fixed seeds 1..=2000 at 10% loss (fast enough for cargo test).
//! SIM_SEEDS, SIM_LOSS (percent), and SIM_WAKE (max frozen seconds; default
//! alternates 20 / 100) scale the run. SIM_SEED=n runs one seed and prints its
//! message log with --nocapture, without treating success as failure.
//! Heavy loss can legitimately lose every final response to the caller.

use super::*;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Ph {
    Idle,
    Ringing,
    Final(u16),
    Answered,
    Hungup,
}

struct Phone {
    st: Ph,
    awake_at: Instant,
    inbox: Vec<Message>,
    last: Option<Message>,
    acked: bool,
    final_at: Option<Instant>,
    retx: Option<(Instant, Duration)>,
    ignores_cancel: bool,
    got_bye: bool,
    first_resp: u16,
}

/// `same_ext`: all phones are devices of one extension (a 6xx is
/// final for the call), else each is a group member of its own.
fn nfork(now: Instant, n: usize, same_ext: bool) -> Fork {
    let caller = invite("sip:100@pbx", "127.0.0.1:5101;branch=z9hG4bK-caller");
    let key = key_of(&caller).unwrap();
    let targets = (0..n)
        .map(|i| {
            let dst: SocketAddr = format!("127.0.0.1:{}", 5102 + i).parse().unwrap();
            let branch = branch_id();
            let mut m = caller.clone();
            m.set_uri(format!("sip:{}@127.0.0.1:{}", 102 + i, 5102 + i));
            m.insert_top("Via", format!("SIP/2.0/UDP 127.0.0.1:5060;branch={branch}"), true);
            Target {
                branch,
                invite: m,
                dst,
                local: Some(phone_local(i)),
                ext: if same_ext {
                    "102".into()
                } else {
                    format!("{}", 102 + i)
                },
                who: format!("phone{i}"),
            }
        })
        .collect();
    Fork::new(
        key,
        caller,
        "127.0.0.1:5101".parse().unwrap(),
        "127.0.0.1".parse().unwrap(),
        Some(CALLER_LOCAL.parse().unwrap()),
        "local".into(),
        "sim".into(),
        targets,
        now,
    )
    .0
}

#[derive(Default, Debug)]
struct CallerView {
    finals: Vec<u16>,
    oks: usize,
    prov_after_final: bool,
    /// Event order (log index) of the caller's CANCEL, and of the first
    /// final response the PBX sent it (even if lost).
    canceled_at: Option<usize>,
    final_sent_at: Option<usize>,
    need_ack: Option<Message>,
    /// A 6xx the fork received while nothing final had gone out.
    declined: Option<u16>,
}

struct World {
    origin: Instant,
    now: Instant,
    /// Messages sent by the PBX, delivered in order (one batch is on
    /// the wire before anybody answers any of it).
    queue: std::collections::VecDeque<Out>,
    delivering: bool,
    f: Fork,
    gone: bool,
    phones: Vec<Phone>,
    cv: CallerView,
    log: Vec<String>,
    r: Rng,
    loss: u64,
    lossy: bool,
    finished_at: Option<Instant>,
}

impl World {
    fn t(&self) -> f64 {
        (self.now - self.origin).as_secs_f64()
    }

    fn phone_says(&mut self, i: usize, m: Message) {
        let lost = self.lossy && self.r.chance(self.loss);
        self.log.push(format!(
            "{:>8.3}s phone{} -> PBX {} {}{}{}",
            self.t(),
            i,
            m.code(),
            m.cseq().map(|c| c.1).unwrap_or_default(),
            if lost { " (LOST)" } else { "" },
            if self.gone { " (fork gone)" } else { "" }
        ));
        if lost {
            return;
        }
        let b = m.top_via().unwrap().branch().unwrap().to_string();
        let now = self.now;
        if self.gone {
            // Pbx::on_response drops unmatched fork branches. No CANCEL,
            // ACK, BYE, or forwarding can be fabricated without the fork.
            return;
        }
        let open = matches!(self.f.server, Server::Proceeding) && !self.f.answered && !self.f.canceled;
        if m.code() >= 600 && open {
            self.cv.declined.get_or_insert(m.code());
        }
        let outs = if let Some(j) = self.f.branch_index(&b) {
            self.f.on_response(j, m, now)
        } else if let Some(j) = self.f.hangup_branch_index(&b) {
            self.f.on_hangup_response(j, &m, now)
        } else {
            vec![]
        };
        self.deliver(outs);
    }

    fn caller_req(&mut self, m: Message) {
        self.log
            .push(format!("{:>8.3}s caller -> PBX {}", self.t(), m.method()));
        if self.gone {
            return;
        }
        let c = self.f.caller;
        let now = self.now;
        let outs = self.f.on_caller(&m, c, now);
        self.deliver(outs);
    }

    fn deliver(&mut self, outs: Vec<Out>) {
        assert!(!self.gone || outs.is_empty(), "traffic after fork was reaped");
        let caller: SocketAddr = "127.0.0.1:5101".parse().unwrap();
        self.queue.extend(outs);
        if self.delivering {
            return;
        }
        self.delivering = true;
        while let Some(o) = self.queue.pop_front() {
            let what = if o.msg.is_request() {
                o.msg.method().to_string()
            } else {
                format!(
                    "{} {}",
                    o.msg.code(),
                    o.msg.cseq().map(|c| c.1).unwrap_or_default()
                )
            };
            let lost = self.lossy && self.r.chance(self.loss);
            let to = match o.dst == caller {
                true => "caller".to_string(),
                false => format!("phone{}", o.dst.port() - 5102),
            };
            let lost_s = if lost { " (LOST)" } else { "" };
            let invite_final = o.msg.code() >= 200 && o.msg.cseq().is_some_and(|c| c.1 == "INVITE");
            if o.dst == caller && invite_final {
                self.cv.final_sent_at.get_or_insert(self.log.len());
            }
            self.log
                .push(format!("{:>8.3}s PBX -> {} {}{}", self.t(), to, what, lost_s));
            let want = match o.dst == caller {
                true => CALLER_LOCAL.parse().unwrap(),
                false => phone_local((o.dst.port() - 5102) as usize),
            };
            assert_eq!(o.src, Some(want), "{} to {} from the wrong address", what, to);
            if lost {
                continue;
            }
            if o.dst == caller {
                let m = o.msg;
                let c = m.code();
                let meth = m.cseq().map(|c| c.1).unwrap_or_default();
                if meth == "CANCEL" {
                } else if (101..200).contains(&c) {
                    if !self.cv.finals.is_empty() || self.cv.oks > 0 {
                        self.cv.prov_after_final = true;
                    }
                } else if (200..300).contains(&c) {
                    self.cv.oks += 1;
                } else if c >= 300 {
                    self.cv.finals.push(c);
                    self.cv.need_ack = Some(m);
                }
            } else {
                let i = (o.dst.port() - 5102) as usize;
                self.phones[i].inbox.push(o.msg);
                self.phone_process(i);
            }
        }
        self.delivering = false;
    }

    fn phone_send_final(&mut self, i: usize, code: u16) {
        let resp = response(&self.f, i, code);
        let p = &mut self.phones[i];
        p.st = if code == 200 {
            Ph::Answered
        } else {
            Ph::Final(code)
        };
        p.last = Some(resp.clone());
        p.final_at = Some(self.now);
        p.retx = Some((self.now + T1, T1));
        self.phone_says(i, resp);
    }

    fn phone_process(&mut self, i: usize) {
        if self.now < self.phones[i].awake_at {
            return;
        }
        let inbox = std::mem::take(&mut self.phones[i].inbox);
        for m in inbox {
            match m.method() {
                "INVITE" => match self.phones[i].st {
                    Ph::Idle => {
                        let code = self.phones[i].first_resp;
                        if code >= 200 {
                            self.phone_send_final(i, code);
                        } else {
                            let resp = response(&self.f, i, code);
                            self.phones[i].st = Ph::Ringing;
                            self.phones[i].last = Some(resp.clone());
                            self.phone_says(i, resp);
                        }
                    }
                    _ => {
                        if let Some(l) = self.phones[i].last.clone() {
                            self.phone_says(i, l);
                        }
                    }
                },
                "CANCEL" => {
                    if self.phones[i].ignores_cancel {
                        continue;
                    }
                    self.phone_says(i, m.make_response(200, "OK", Some("phone")));
                    if self.phones[i].st == Ph::Ringing {
                        self.phone_send_final(i, 487);
                    }
                }
                "ACK" => self.phones[i].acked = true,
                "BYE" => {
                    self.phones[i].got_bye = true;
                    self.phones[i].st = Ph::Hungup;
                    self.phones[i].retx = None;
                    self.phone_says(i, m.make_response(200, "OK", Some("phone")));
                }
                _ => {}
            }
        }
    }

    /// next event: fork deadline, phone wake or phone retransmission
    fn next_event(&self) -> Instant {
        let mut d = match self.gone {
            true => self.now + Duration::from_secs(100_000),
            false => self.f.next_deadline(self.now),
        };
        for p in &self.phones {
            if p.awake_at > self.now {
                d = d.min(p.awake_at);
            }
            if let (Some((at, _)), false) = (p.retx, p.acked) {
                d = d.min(at);
            }
        }
        d
    }

    fn advance(&mut self, to: Instant) -> Result<(), String> {
        let mut spins = 0;
        loop {
            let d = self.next_event();
            if d > to {
                break;
            }
            if d < self.now {
                return Err("event in the past".into());
            }
            if d == self.now {
                spins += 1;
                if spins > 50 {
                    return Err(format!("timer spin at {:.3}", self.t()));
                }
            }
            self.now = d;
            self.fire();
        }
        self.now = to;
        self.fire();
        Ok(())
    }

    fn fire(&mut self) {
        for i in 0..self.phones.len() {
            if self.now >= self.phones[i].awake_at && !self.phones[i].inbox.is_empty() {
                self.phone_process(i);
            }
            let p = &mut self.phones[i];
            if let (Some((at, iv)), false) = (p.retx, p.acked) {
                if at <= self.now {
                    if self.now - p.final_at.unwrap() >= TIMER_B {
                        p.retx = None;
                    } else {
                        p.retx = Some((self.now + (iv * 2).min(T2), (iv * 2).min(T2)));
                        let l = p.last.clone().unwrap();
                        self.phone_says(i, l);
                    }
                }
            }
        }
        if !self.gone {
            let now = self.now;
            let outs = self.f.tick(now);
            self.deliver(outs);
            if self.f.finished(now) {
                self.gone = true;
                self.finished_at = Some(now);
                self.log.push(format!("{:>8.3}s fork reaped", self.t()));
            }
        }
        // caller ACKs any final it got
        if let Some(fr) = self.cv.need_ack.take() {
            let mut a = self.f.invite.clone();
            a.start = request("ACK", a.uri());
            a.set("CSeq", "7 ACK".into());
            a.set("To", fr.hdr("To").unwrap().to_string());
            self.caller_req(a);
        }
    }
}

fn run(seed: u64, n: usize, loss: u64, max_wake: u64) -> Result<f64, String> {
    let mut r = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
    let origin = Instant::now();
    let same_ext = r.chance(50);
    let f = nfork(origin, n, same_ext);
    let phones: Vec<Phone> = (0..n)
        .map(|_| {
            let frozen = r.chance(25);
            let wake = Duration::from_millis(r.below(max_wake * 1000));
            Phone {
                st: Ph::Idle,
                awake_at: origin + if frozen { wake } else { Duration::ZERO },
                inbox: Vec::new(),
                last: None,
                acked: false,
                final_at: None,
                retx: None,
                ignores_cancel: r.chance(5),
                got_bye: false,
                first_resp: [100u16, 180, 183, 180, 486, 200, 603, 480, 180, 180][r.below(10) as usize],
            }
        })
        .collect();
    let mut w = World {
        origin,
        now: origin,
        queue: Default::default(),
        delivering: false,
        f,
        gone: false,
        phones,
        cv: CallerView::default(),
        log: vec![format!("seed {seed}: {n} phones, same extension: {same_ext}")],
        r,
        loss,
        lossy: true,
        finished_at: None,
    };
    for i in 0..n {
        let inv = w.f.branches[i].t.invite.clone();
        w.phones[i].inbox.push(inv);
        w.phone_process(i);
    }
    let steps = 10 + w.r.below(60);
    let mut caller_cancels = w.r.chance(40);
    let cancel_step = w.r.below(steps);
    for step in 0..steps {
        match w.r.below(10) {
            0..=3 => {
                let i = w.r.below(n as u64) as usize;
                if w.now >= w.phones[i].awake_at && w.phones[i].st == Ph::Ringing && w.r.chance(30) {
                    let code = [200u16, 486, 603, 180, 183][w.r.below(5) as usize];
                    if code >= 200 {
                        w.phone_send_final(i, code);
                    } else {
                        let resp = response(&w.f, i, code);
                        w.phone_says(i, resp);
                    }
                }
            }
            4 => {
                if caller_cancels && step >= cancel_step {
                    caller_cancels = false;
                    let mut c = w.f.invite.clone();
                    c.start = request("CANCEL", c.uri());
                    c.set("CSeq", "7 CANCEL".into());
                    c.body.clear();
                    w.cv.canceled_at.get_or_insert(w.log.len());
                    w.caller_req(c);
                } else if w.r.chance(20) {
                    let inv = w.f.invite.clone();
                    w.caller_req(inv);
                }
            }
            _ => {
                let dt = [10u64, 100, 500, 1500, 4000, 10_000, 40_000][w.r.below(7) as usize];
                let to = w.now + Duration::from_millis(dt);
                w.advance(to)
                    .map_err(|e| format!("seed {seed}: {e}\n{}", w.log.join("\n")))?;
            }
        }
    }
    // quiescent phase
    w.lossy = false;
    let end = w.now + Duration::from_secs(1500);
    w.advance(end)
        .map_err(|e| format!("seed {seed}: {e}\n{}", w.log.join("\n")))?;
    let mut errs = Vec::new();
    if !w.gone {
        errs.push("fork never reaped".to_string());
    }
    let cv = &w.cv;
    if cv.oks > 0 && !cv.finals.is_empty() {
        errs.push(format!("caller got both 2xx and {:?}", cv.finals));
    }
    if cv.finals.windows(2).any(|x| x[0] != x[1]) {
        errs.push(format!("caller got different finals {:?}", cv.finals));
    }
    if cv.oks == 0 && cv.finals.is_empty() {
        errs.push("caller never got a final".into());
    }
    if cv.prov_after_final {
        errs.push("provisional after final".into());
    }
    let canceled_first = cv
        .canceled_at
        .is_some_and(|c| cv.final_sent_at.is_none_or(|f| c < f));
    if canceled_first && cv.oks == 0 && cv.finals.first() != Some(&487) {
        errs.push(format!("caller canceled but got {:?}", cv.finals));
    }
    if let (true, Some(code), 0, false) = (same_ext, cv.declined, cv.oks, canceled_first) {
        if cv.finals.first() != Some(&code) {
            errs.push(format!(
                "a device declined with {code}, caller got {:?}",
                cv.finals
            ));
        }
    }
    for (i, p) in w.phones.iter().enumerate() {
        // A phone waking only after reaping cannot be cancelled. Likewise,
        // a final first sent after reaping cannot be ACKed or hung up. Keep
        // all cleanup assertions for phones responding while state exists.
        let awake_while_active = w.finished_at.is_none_or(|t| p.awake_at <= t);
        let final_while_active = p.final_at.is_some_and(|at| w.finished_at.is_none_or(|t| at <= t));
        if p.st == Ph::Ringing && awake_while_active && !p.ignores_cancel {
            let at = (p.awake_at - origin).as_secs_f64();
            errs.push(format!("phone{i} still ringing at end (awake_at {at:.1})"));
        }
        if matches!(p.st, Ph::Final(_)) && final_while_active && !p.acked && !p.ignores_cancel {
            errs.push(format!("phone{i} final {:?} never ACKed", p.st));
        }
        if p.st == Ph::Answered && final_while_active && cv.oks == 0 && !p.got_bye && !p.ignores_cancel {
            errs.push(format!("phone{i} answered, not passed on and not hung up"));
        }
    }
    let dur = w.finished_at.map(|t| (t - origin).as_secs_f64()).unwrap_or(-1.0);
    if std::env::var("SIM_SEED").is_ok() {
        println!("{}", w.log.join("\n"));
    }
    match errs.is_empty() {
        true => Ok(dur),
        false => Err(format!(
            "seed {seed} n={n}: {}\n{}",
            errs.join("; "),
            w.log.join("\n")
        )),
    }
}

#[test]
fn randomized_model_check() {
    let env = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
    let loss = env("SIM_LOSS").unwrap_or(10);
    let seeds = match env("SIM_SEED") {
        Some(s) => s..s + 1,
        None => 1..env("SIM_SEEDS").unwrap_or(2000) + 1,
    };
    crate::util::set_log_level(crate::util::ERROR);
    let mut fails = Vec::new();
    let mut maxdur = 0.0f64;
    for seed in seeds.clone() {
        let n = 2 + (seed % 3) as usize;
        let wake = env("SIM_WAKE").unwrap_or(if seed % 2 == 0 { 20 } else { 100 });
        match run(seed, n, loss, wake) {
            Ok(d) => maxdur = maxdur.max(d),
            Err(e) => fails.push(e),
        }
    }
    println!(
        "max fork lifetime {maxdur:.1}s; {} failures of {}",
        fails.len(),
        seeds.count()
    );
    for f in fails.iter().take(2) {
        println!("---------------\n{f}");
    }
    assert!(fails.is_empty(), "{} failures", fails.len());
}
