# Testing tiny-pbx

Run commands from the repository root. `cargo test` runs the Rust tests,
including a fork simulator with packet loss, frozen phones and CANCEL races.
It runs fixed seeds 1–2000 by default. To replay one seed and see its trace:

```sh
SIM_SEED=42 cargo test randomized_model_check -- --nocapture
```

Use `SIM_SEEDS` for a different number of seeds, `SIM_LOSS` for the packet
loss percentage (default 10; above about 20 a few seeds fail legitimately,
when every copy of a message is lost), and `SIM_WAKE` for the maximum time a
phone stays frozen (simulated seconds).

## Interoperability suites

`python3 -m unittest discover -s tests` checks the test runner without SIP
clients. The interop suites run the PBX against real clients. Both need Linux, Cargo,
Python 3 (standard library) and `pjsua` (pjproject 2.x CLI) on `PATH`.
Loopback also needs `sipp` (3.7); the Docker suite needs a working local
Docker daemon and two free bridge subnets.

```sh
tests/interop.sh          # loopback calls and ring groups
tests/interop.sh docker   # baresip and linphonec in containers, pjsua on the host
tests/interop.sh all      # both suites
tests/interop.sh full     # both, including slower load and protocol-timer tests
```

Loopback checks registration, authentication, call setup and cancellation,
transfers, messaging, restart and idle behaviour. Ring-group tests exercise
multiple devices per extension, simultaneous answers and unresponsive phones.
The Docker suite tests client interoperability and routing across two PBX
interfaces. The harness checks signalling in packet logs and verifies direct
media by recording the other phone's tone where the network allows RTP.

A failed run exits nonzero. Look in `tests/out/loopback/` or `tests/out/docker/`,
including their subdirectories, for PBX packet logs (`pbx*.N.log`), client logs,
SIPp message traces and `.wav` recordings. The next run replaces that suite's logs.

### Selecting tests and addresses

```sh
tests/interop.sh loopback --only 'busy,transfer'
tests/interop.sh docker --only 'register'
```

`--only` matches comma-separated substrings of test names. Both suites reject
empty or unmatched terms before setup. Loopback includes prerequisites and
runs a slow test if explicitly selected. Loopback only: `--slow` includes all
slow tests, and `--serial` runs the loopback and ring-group blocks one after
the other.

- **Loopback:** clients use `127.0.0.1`. The main PBX defaults to
  `127.0.0.2:5060` (`--host` / `--port` or `PBX_TEST_HOST` / `PBX_TEST_PORT`);
  groups use `127.0.0.4:5060` (`--group-host` or `PBX_TEST_GROUP_HOST`). If
  an address is taken, prefer another host to another port: off port 5060
  the attended-transfer test fails, because pjsua leaves the port out of
  `Refer-To`. Three tests start a PBX of their own, whatever these options say:
  one on UDP port 5080 of every address (its phones use `127.0.0.2` and
  `127.0.0.3`), two on a free port of `127.0.0.3`. Set `PBX_BIN` to use a
  prebuilt binary.
- **Docker:** the harness builds `pbx-interop-ua:latest` and a static binary
  in `target/static` (override with `PBX_STATIC_BIN`). By default it uses
  `10.231.1.0/24` and `10.231.2.0/24`; if those are taken, set `PBXI_NET1` /
  `PBXI_NET2` to the first three octets of two other /24s (e.g. `10.99.1`).
  Reserve `pbxi-*` for test containers and networks; `--keep` leaves the
  networks in place. No ports are published.

The suites use IPv4 software clients, not physical handsets. They do not wait
through full registration, session or nonce lifetimes. Long fork timers and
late responses after fork expiry or restart are covered in Rust tests instead.
