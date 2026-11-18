# tiny-pbx

A small SIP registrar and proxy for a handful of phones on a trusted LAN.
Phones register with an extension and password, then dial each other by
number. Calling an extension rings all its devices; a ring group rings
several extensions at once.

The PBX handles **signalling only**, over UDP. Audio flows directly between
phones, so firewalls and VLANs must allow phone-to-phone RTP. Compatible
phones can negotiate hold, transfers and DTMF, and exchange SIP messages.
There are no trunks, voicemail, conferencing or media relay. The server is
single-threaded and needs no periodic timers while idle.

## Configuration

Start with [tiny-pbx.conf.example](tiny-pbx.conf.example). Set a strong
password for each `[extensions]` entry; optional `[groups]` entries list
extensions or `*` for all. Restart the PBX after editing the config.

Keep the registration file (default `bindings.txt` next to the config) and
its `.key` file in a writable directory. Preserve both so registered phones
and established calls can continue after a restart. Calls that are still
ringing multiple devices rely on in-memory state: late responses are dropped
after that state expires or the PBX restarts.

## Running

The configured UDP port (5060 by default) must be free and reachable from
the phones.

### Without Docker

From the repository root, with Rust 1.82 or newer and Cargo installed:

```sh
cp tiny-pbx.conf.example tiny-pbx.conf
# Edit tiny-pbx.conf and replace the example passwords before starting.
cargo build --release
./target/release/tiny-pbx -c tiny-pbx.conf check
./target/release/tiny-pbx -c tiny-pbx.conf
```

Use `status` instead of `check` to list registered phones. Set `PBX_LOG=debug`
to log SIP packets for troubleshooting.

### Docker (Linux)

From the **parent directory** of the checkout:

```sh
mkdir -p data/tiny-pbx
cp tiny-pbx/tiny-pbx.conf.example data/tiny-pbx/tiny-pbx.conf
```

Replace the example passwords, then save this as `compose.yaml`. Host
networking lets the PBX use the host's LAN addresses.

```yaml
services:
  tiny-pbx:
    container_name: tiny-pbx
    build: ./tiny-pbx
    restart: unless-stopped
    network_mode: host
    user: "${PUID:?set PUID}:${PGID:?set PGID}"
    volumes:
      - ./data/tiny-pbx:/data
```

```sh
PUID=$(id -u) PGID=$(id -g) docker compose up -d --build tiny-pbx
docker logs tiny-pbx
docker exec tiny-pbx /tiny-pbx status
```

## Phone setup

| Setting | Value |
|---------|-------|
| SIP server / registrar / domain | PBX host IP or hostname, configured SIP port |
| Transport | UDP (not TCP, TLS or WebSocket) |
| User / auth user | Extension number, e.g. `101` |
| Password | From `tiny-pbx.conf` |
| Outbound proxy, STUN, ICE | Off / empty |

Phones should advertise their own LAN IP in `Contact`. The PBX does not
resolve hostnames in SIP requests; it treats them as names for itself. If
several accounts share one UDP socket, point them all at the same PBX IP.

**Do not expose the SIP port to the Internet.** Digest replay protection is
bounded: the PBX remembers up to 1,024 nonce/user pairs and can forget one
before its five-minute nonce expires.

## Development

Run `cargo test` for the Rust tests. See [tests/README.md](tests/README.md)
for interoperability tests with real SIP clients.
