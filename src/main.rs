//! tiny-pbx — a tiny SIP registrar + proxy for a handful of LAN phones.

// unsafe only where allowed explicitly: the syscalls std has no wrapper for
// (udp.rs, util::interface_ips, the signal handling below)
#![deny(unsafe_code)]

mod config;
mod digest;
mod fork;
mod proxy;
mod registrar;
mod routing;
mod sip;
#[cfg(test)]
mod tests;
mod udp;
#[macro_use]
mod util;

use std::net::UdpSocket;
use std::path::Path;
use std::process::exit;

const USAGE: &str = "\
usage: tiny-pbx [-c CONFIG] [run|status|check]

  run      serve SIP on UDP (default)
  status   show registered phones (reads the state file)
  check    validate the config file, list what it defines, and exit

CONFIG defaults to $PBX_CONFIG or /etc/tiny-pbx.conf.
$PBX_LOG=debug|info|warn|error overrides the configured log level.";

#[allow(unsafe_code)]
extern "C" fn on_signal(_: libc::c_int) {
    // Registrations are saved as they change, so there is nothing to flush.
    // SAFETY: _exit takes no pointers and is async-signal-safe.
    unsafe { libc::_exit(0) }
}

/// Exit (at once, with status 0) on SIGTERM and SIGINT.
#[allow(unsafe_code)]
fn exit_on_signals() {
    // SAFETY: the handler is an extern "C" fn of the type signal() expects,
    // and only calls _exit, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
    }
}

fn main() {
    let mut cfg_path = std::env::var("PBX_CONFIG").unwrap_or_else(|_| "/etc/tiny-pbx.conf".into());
    let mut cmd = String::from("run");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => match args.next() {
                Some(p) => cfg_path = p,
                None => {
                    eprintln!("{}", USAGE);
                    exit(2)
                }
            },
            "run" | "status" | "check" => cmd = a,
            "-V" | "--version" => {
                println!("{}", proxy::SERVER);
                return;
            }
            "-h" | "--help" => {
                println!("{}", USAGE);
                return;
            }
            _ => {
                eprintln!("{}", USAGE);
                exit(2)
            }
        }
    }
    let mut cfg = match config::Config::load(Path::new(&cfg_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tiny-pbx: {}", e);
            exit(1)
        }
    };
    if let Ok(l) = std::env::var("PBX_LOG") {
        match config::parse_log_level(&l) {
            Some(level) => cfg.log_level = level,
            None => eprintln!(
                "tiny-pbx: ignoring PBX_LOG={:?} (expected error, warn, info or debug)",
                l
            ),
        }
    }
    match cmd.as_str() {
        "check" => check(&cfg_path, &cfg),
        "status" => status(&cfg),
        _ => run(cfg),
    }
}

fn run(cfg: config::Config) {
    util::set_log_level(cfg.log_level);
    exit_on_signals();
    let sock = match UdpSocket::bind(cfg.listen) {
        Ok(s) => s,
        Err(e) => {
            log!(util::ERROR, "cannot listen on udp {}: {}", cfg.listen, e);
            exit(1)
        }
    };
    let mut pbx = proxy::Pbx::new(cfg, sock);
    log!(
        util::INFO,
        "{} listening on udp {}, realm {:?}, extensions: {}",
        proxy::SERVER,
        pbx.cfg.listen,
        pbx.cfg.realm,
        pbx.cfg.extensions.keys().cloned().collect::<Vec<_>>().join(" ")
    );
    for (g, members) in &pbx.cfg.groups {
        log!(util::INFO, "group {} rings {}", g, members.join(" "));
    }
    for (ext, b) in pbx.reg.all() {
        log!(
            util::INFO,
            "{} still registered from {} (restored)",
            ext,
            b.source
        );
    }
    pbx.run()
}

/// What `check` parsed, so that a misplaced line is easy to spot.
fn check(cfg_path: &str, cfg: &config::Config) {
    println!("{}: OK, {} extensions", cfg_path, cfg.extensions.len());
    println!(
        "extensions: {}",
        cfg.extensions.keys().cloned().collect::<Vec<_>>().join(" ")
    );
    for (g, members) in &cfg.groups {
        println!("group {} rings {}", g, members.join(" "));
    }
    if let Some(state) = &cfg.state_file {
        println!("registrations are kept in {}", state.display());
    }
}

fn status(cfg: &config::Config) {
    let reg = registrar::Registrar::new(cfg.state_file.clone(), cfg.max_expires);
    let now = util::mono_now();
    println!("{:<8} {:<22} {:>8}  DEVICE", "EXT", "ADDRESS", "EXPIRES");
    for ext in cfg.extensions.keys() {
        let list = reg.get(ext);
        if list.is_empty() {
            println!("{:<8} {:<22} {:>8}", ext, "-", "-");
        }
        for b in list {
            // (from the phones: escaped for the terminal)
            println!(
                "{:<8} {:<22} {:>7}s  {}",
                ext,
                b.source.to_string(),
                b.expires_in(now),
                util::clip(if b.user_agent.is_empty() {
                    &b.contact
                } else {
                    &b.user_agent
                })
            );
        }
    }
    for (g, members) in &cfg.groups {
        println!("group {} rings {}", g, members.join(" "));
    }
}
