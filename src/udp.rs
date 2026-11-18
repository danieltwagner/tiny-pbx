//! UDP with a choice of source address. A wildcard listener learns which
//! local address each datagram reached (IP_PKTINFO / IPV6_RECVPKTINFO), and
//! can reply from that address rather than the routing table's choice.
//! This matters for multihomed SIP servers and connected UDP clients.
//! Linux uses libc recvmsg/sendmsg; elsewhere the kernel chooses the source.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

pub use imp::{enable_pktinfo, recv, send};

/// A usable reply source, with IPv4-mapped addresses normalized to IPv4.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn local_addr(ip: IpAddr) -> Option<IpAddr> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    };
    let broadcast = matches!(ip, IpAddr::V4(v4) if v4.is_broadcast());
    (!ip.is_unspecified() && !ip.is_multicast() && !broadcast).then_some(ip)
}

/// The Linux FFI boundary. No raw pointers escape this module. Socket
/// addresses and ancillary data use libc's layouts, aligned storage, and
/// initialized buffers. Validate received lengths/alignment before typed
/// reads; the kernel borrows the syscall buffers only for the call.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod imp {
    use super::*;
    use libc::c_int;
    use std::mem::{align_of, size_of, zeroed};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};
    use std::os::fd::AsRawFd;

    // More than enough for both IPv4 and IPv6 pktinfo on a dual-stack socket.
    // The zero-sized field gives the bytes cmsghdr alignment, not just u8's.
    #[repr(C)]
    struct Control {
        _align: [libc::cmsghdr; 0],
        bytes: [u8; 128],
    }

    impl Control {
        fn new() -> Self {
            Self {
                _align: [],
                bytes: [0; 128],
            }
        }
    }

    // SAFETY: CMSG_LEN/SPACE only do arithmetic on these small constant sizes.
    const HEADER: usize = unsafe { libc::CMSG_LEN(0) as usize };
    const SPACE4: usize = unsafe { libc::CMSG_SPACE(size_of::<libc::in_pktinfo>() as _) as usize };
    const SPACE6: usize = unsafe { libc::CMSG_SPACE(size_of::<libc::in6_pktinfo>() as _) as usize };
    const _: () = {
        assert!(SPACE4 + SPACE6 <= 128);
        assert!(HEADER == size_of::<libc::cmsghdr>());
        assert!(align_of::<Control>() >= align_of::<libc::in_pktinfo>());
        assert!(align_of::<Control>() >= align_of::<libc::in6_pktinfo>());
        assert!(HEADER % align_of::<libc::in_pktinfo>() == 0);
        assert!(HEADER % align_of::<libc::in6_pktinfo>() == 0);
        assert!(size_of::<libc::sockaddr_storage>() >= size_of::<libc::sockaddr_in6>());
        assert!(size_of::<libc::sockaddr_storage>() >= size_of::<libc::sockaddr_in>());
        assert!(align_of::<libc::sockaddr_storage>() >= align_of::<libc::sockaddr_in6>());
        assert!(align_of::<libc::sockaddr_storage>() >= align_of::<libc::sockaddr_in>());
    };

    /// Ask the kernel for the local destination of each received datagram.
    pub fn enable_pktinfo(sock: &UdpSocket) -> bool {
        match sock.local_addr() {
            Ok(SocketAddr::V4(_)) => set_on(sock, libc::IPPROTO_IP, libc::IP_PKTINFO),
            Ok(SocketAddr::V6(_)) => {
                // Request both: mapped IPv4 packets may carry both messages.
                let v4 = set_on(sock, libc::IPPROTO_IP, libc::IP_PKTINFO);
                set_on(sock, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO) || v4
            }
            Err(_) => false,
        }
    }

    fn set_on(sock: &UdpSocket, level: c_int, name: c_int) -> bool {
        let one: c_int = 1;
        // SAFETY: a live integer and its exact size, read only during the call.
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                level,
                name,
                (&one as *const c_int).cast(),
                size_of::<c_int>() as _,
            ) == 0
        }
    }

    /// recv_from, plus the usable local destination (None without pktinfo).
    pub fn recv(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
        // SAFETY: sockaddr_storage contains only integers/bytes; zero is valid.
        let mut name = unsafe { zeroed() };
        let mut control = Control::new();
        let (n, namelen, controllen, flags) = recvmsg(sock, buf, &mut name, &mut control.bytes)?;
        let from = from_sockaddr(&name, namelen)
            .ok_or_else(|| io::Error::other("datagram from an invalid or unknown address family"))?;
        let local = control
            .bytes
            .get(..controllen)
            .and_then(|c| local_from_cmsgs(c, flags));
        Ok((n, from, local.and_then(local_addr)))
    }

    fn recvmsg(
        sock: &UdpSocket,
        buf: &mut [u8],
        name: &mut libc::sockaddr_storage,
        control: &mut [u8],
    ) -> io::Result<(usize, usize, usize, c_int)> {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: msghdr's integers, pointers and libc-private padding can be zero.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = (name as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        // SAFETY: all writable buffers are exclusively borrowed, with their
        // actual sizes. No pointer is retained by recvmsg after it returns.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        // No MSG_TRUNC input flag: n is the copied length, even if data was cut.
        Ok((
            n as usize,
            msg.msg_namelen as usize,
            msg.msg_controllen as usize,
            msg.msg_flags,
        ))
    }

    /// Send from src. On a dual-stack socket, dst may be IPv4-mapped while
    /// src is plain IPv4; native IPv6 uses IPV6_PKTINFO as well.
    pub fn send(sock: &UdpSocket, data: &[u8], dst: SocketAddr, src: IpAddr) -> io::Result<usize> {
        let (mut name, namelen) = to_sockaddr(dst);
        let mut control = Control::new();
        let controllen = put_pktinfo(&mut control, dst, src).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "source and destination address families differ",
            )
        })?;
        let mut iov = libc::iovec {
            iov_base: data.as_ptr().cast_mut().cast(),
            iov_len: data.len(),
        };
        // SAFETY: zero is valid for all msghdr fields, including private padding.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = (&mut name as *mut libc::sockaddr_storage).cast();
        msg.msg_namelen = namelen as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.bytes.as_mut_ptr().cast();
        msg.msg_controllen = controllen as _;
        // SAFETY: every pointer refers to live storage of the given length.
        // sendmsg only reads it (despite C's mutable pointer types).
        let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn from_sockaddr(name: &libc::sockaddr_storage, len: usize) -> Option<SocketAddr> {
        if !(size_of::<libc::sa_family_t>()..=size_of::<libc::sockaddr_storage>()).contains(&len) {
            return None;
        }
        let ptr = name as *const libc::sockaddr_storage;
        // SAFETY: storage is initialized and aligned for either address (asserts
        // above). Each cast/read is gated by the family and the full struct size.
        unsafe {
            match name.ss_family as c_int {
                libc::AF_INET if len >= size_of::<libc::sockaddr_in>() => {
                    let a = &*ptr.cast::<libc::sockaddr_in>();
                    Some(SocketAddr::new(
                        Ipv4Addr::from(a.sin_addr.s_addr.to_ne_bytes()).into(),
                        u16::from_be(a.sin_port),
                    ))
                }
                libc::AF_INET6 if len >= size_of::<libc::sockaddr_in6>() => {
                    let a = &*ptr.cast::<libc::sockaddr_in6>();
                    Some(SocketAddr::V6(SocketAddrV6::new(
                        Ipv6Addr::from(a.sin6_addr.s6_addr),
                        u16::from_be(a.sin6_port),
                        a.sin6_flowinfo,
                        a.sin6_scope_id,
                    )))
                }
                _ => None,
            }
        }
    }

    fn to_sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, usize) {
        // SAFETY: these C structs contain only integers/bytes. Storage has room
        // and alignment for both structs (asserted above). Set fields in place
        // so all unused fields and padding remain zero for the syscall.
        unsafe {
            let mut name: libc::sockaddr_storage = zeroed();
            let ptr = &mut name as *mut libc::sockaddr_storage;
            let len = match addr {
                SocketAddr::V4(a) => {
                    let out = &mut *ptr.cast::<libc::sockaddr_in>();
                    out.sin_family = libc::AF_INET as _;
                    out.sin_port = a.port().to_be();
                    out.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
                    size_of::<libc::sockaddr_in>()
                }
                SocketAddr::V6(a) => {
                    let out = &mut *ptr.cast::<libc::sockaddr_in6>();
                    out.sin6_family = libc::AF_INET6 as _;
                    out.sin6_port = a.port().to_be();
                    out.sin6_flowinfo = a.flowinfo();
                    out.sin6_addr.s6_addr = a.ip().octets();
                    out.sin6_scope_id = a.scope_id();
                    size_of::<libc::sockaddr_in6>()
                }
            };
            (name, len)
        }
    }

    /// A truncated control buffer cannot reliably tell which pktinfo wins.
    /// IPv4's spec_dst takes precedence over IPv6, regardless of message order:
    /// it is a local unicast address even when the IPv4 destination is broadcast.
    fn local_from_cmsgs(control: &[u8], flags: c_int) -> Option<IpAddr> {
        if flags & libc::MSG_CTRUNC != 0 || !control.as_ptr().cast::<libc::cmsghdr>().is_aligned() {
            return None;
        }
        // SAFETY: zeroed msghdr is valid. CMSG helpers only read this slice; no
        // typed read occurs until a whole, aligned header/payload is in bounds.
        unsafe {
            let mut msg: libc::msghdr = zeroed();
            msg.msg_control = control.as_ptr().cast_mut().cast();
            msg.msg_controllen = control.len() as _;
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            let mut local = None;
            while !cmsg.is_null() {
                let offset = (cmsg as usize).checked_sub(control.as_ptr() as usize)?;
                let remaining = control.len().checked_sub(offset)?;
                if !cmsg.is_aligned() || remaining < HEADER {
                    break;
                }
                let h = &*cmsg;
                let len = h.cmsg_len as usize;
                if len < HEADER || len > remaining {
                    break;
                }
                let data = libc::CMSG_DATA(cmsg);
                match (h.cmsg_level, h.cmsg_type) {
                    (libc::IPPROTO_IP, libc::IP_PKTINFO)
                        if len - HEADER >= size_of::<libc::in_pktinfo>()
                            && data.cast::<libc::in_pktinfo>().is_aligned() =>
                    {
                        let info = &*data.cast::<libc::in_pktinfo>();
                        let ip = if info.ipi_spec_dst.s_addr != 0 {
                            info.ipi_spec_dst
                        } else {
                            info.ipi_addr
                        };
                        local = Some(Ipv4Addr::from(ip.s_addr.to_ne_bytes()).into());
                    }
                    (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO)
                        if local.is_none()
                            && len - HEADER >= size_of::<libc::in6_pktinfo>()
                            && data.cast::<libc::in6_pktinfo>().is_aligned() =>
                    {
                        local = Some(
                            Ipv6Addr::from((*data.cast::<libc::in6_pktinfo>()).ipi6_addr.s6_addr).into(),
                        );
                    }
                    _ => {}
                }
                // Validate the aligned step before CMSG_NXTHDR: no overflow or
                // pointer arithmetic beyond the allocation, even with bad data.
                let Ok(payload) = u32::try_from(len - HEADER) else {
                    break;
                };
                if payload > u32::MAX - HEADER as u32 - align_of::<libc::cmsghdr>() as u32 {
                    break;
                }
                let step = libc::CMSG_SPACE(payload) as usize;
                if step > remaining || remaining - step < HEADER {
                    break;
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
            local
        }
    }

    fn put_pktinfo(control: &mut Control, dst: SocketAddr, src: IpAddr) -> Option<usize> {
        let src = match (dst, src) {
            (SocketAddr::V4(_), IpAddr::V4(s)) => IpAddr::V4(s),
            (SocketAddr::V6(d), IpAddr::V4(s)) if d.ip().to_ipv4_mapped().is_some() => {
                IpAddr::V6(s.to_ipv6_mapped())
            }
            (SocketAddr::V6(d), IpAddr::V6(s)) if d.ip().to_ipv4_mapped().is_none() => IpAddr::V6(s),
            _ => return None,
        };
        control.bytes.fill(0);
        // SAFETY: Control is aligned for header and payload, with room for either
        // pktinfo (constant assertions above). All C fields/padding start zero.
        unsafe {
            let h = control.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
            let data = libc::CMSG_DATA(h);
            let (size, space) = match src {
                IpAddr::V4(s) => {
                    (*h).cmsg_level = libc::IPPROTO_IP;
                    (*h).cmsg_type = libc::IP_PKTINFO;
                    (*data.cast::<libc::in_pktinfo>()).ipi_spec_dst.s_addr = u32::from_ne_bytes(s.octets());
                    (size_of::<libc::in_pktinfo>(), SPACE4)
                }
                IpAddr::V6(s) => {
                    (*h).cmsg_level = libc::IPPROTO_IPV6;
                    (*h).cmsg_type = libc::IPV6_PKTINFO;
                    (*data.cast::<libc::in6_pktinfo>()).ipi6_addr.s6_addr = s.octets();
                    (size_of::<libc::in6_pktinfo>(), SPACE6)
                }
            };
            (*h).cmsg_len = libc::CMSG_LEN(size as _) as _;
            Some(space)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::time::Duration;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        // Every socket, including the wildcard receiver, has a deadline.
        fn socket(bind: &str) -> io::Result<UdpSocket> {
            let s = UdpSocket::bind(bind)?;
            s.set_read_timeout(Some(Duration::from_secs(2)))?;
            Ok(s)
        }

        fn ipv4_listener(bind: &str) -> Option<UdpSocket> {
            let s = match socket(bind) {
                Ok(s) => s,
                Err(e) if bind.starts_with('[') => {
                    eprintln!("skipping IPv6: {e}");
                    return None;
                }
                Err(e) => panic!("{bind}: {e}"),
            };
            if s.local_addr().unwrap().is_ipv6() {
                let mut only: c_int = 0;
                let mut len = size_of::<c_int>() as libc::socklen_t;
                // SAFETY: getsockopt writes to a live integer and its length.
                let rc = unsafe {
                    libc::getsockopt(
                        s.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        libc::IPV6_V6ONLY,
                        (&mut only as *mut c_int).cast(),
                        &mut len,
                    )
                };
                assert_eq!(rc, 0);
                if only != 0 {
                    eprintln!("skipping mapped IPv4: IPV6_V6ONLY is enabled");
                    return None;
                }
            }
            Some(s)
        }

        #[test]
        fn answers_from_the_address_it_was_sent_to() {
            for bind in ["0.0.0.0:0", "[::]:0"] {
                let Some(s) = ipv4_listener(bind) else {
                    continue;
                };
                assert!(enable_pktinfo(&s));
                let port = s.local_addr().unwrap().port();
                let c = socket("127.0.0.1:0").unwrap();
                let mut buf = [0; 64];
                for addr in ["127.0.0.2", "127.0.0.3"] {
                    c.send_to(b"ping", (addr, port)).unwrap();
                    let (n, from, local) = recv(&s, &mut buf).unwrap();
                    assert_eq!(&buf[..n], b"ping");
                    assert_eq!(local, Some(ip(addr)), "{bind}");
                    assert_eq!(from.port(), c.local_addr().unwrap().port());
                    assert_eq!(
                        from.ip(),
                        ip(if s.local_addr().unwrap().is_ipv6() {
                            "::ffff:127.0.0.1"
                        } else {
                            "127.0.0.1"
                        })
                    );
                    send(&s, b"pong", from, local.unwrap()).unwrap();
                    let (n, seen) = c.recv_from(&mut buf).unwrap();
                    assert_eq!(&buf[..n], b"pong");
                    assert_eq!(seen, SocketAddr::new(ip(addr), port), "{bind}");
                    // A nonlocal or mismatched source fails, allowing caller fallback.
                    assert!(send(&s, b"x", from, ip("192.0.2.1")).is_err());
                    assert_eq!(
                        send(&s, b"x", from, ip("::1")).unwrap_err().kind(),
                        io::ErrorKind::InvalidInput
                    );
                }
            }
        }

        #[test]
        fn native_ipv6_source_selection() {
            let (Ok(s), Ok(c)) = (socket("[::]:0"), socket("[::1]:0")) else {
                return;
            };
            assert!(enable_pktinfo(&s));
            let port = s.local_addr().unwrap().port();
            c.send_to(b"ping", ("::1", port)).unwrap();
            let mut buf = [0; 64];
            let (n, from, local) = recv(&s, &mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping");
            assert_eq!(from, c.local_addr().unwrap());
            assert_eq!(local, Some(ip("::1")));
            send(&s, b"pong", from, local.unwrap()).unwrap();
            let (n, seen) = c.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"pong");
            assert_eq!(seen, SocketAddr::new(ip("::1"), port));
            assert_eq!(
                send(&s, b"x", from, ip("127.0.0.1")).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }

        #[test]
        fn no_pktinfo_and_truncated_payload() {
            let s = socket("0.0.0.0:0").unwrap();
            let c = socket("127.0.0.1:0").unwrap();
            let dst = ("127.0.0.2", s.local_addr().unwrap().port());
            let mut buf = [0; 2];
            c.send_to(b"ping", dst).unwrap();
            let (n, from, local) = recv(&s, &mut buf).unwrap();
            assert_eq!((n, from, local), (2, c.local_addr().unwrap(), None));
            assert_eq!(&buf, b"pi");
            assert!(enable_pktinfo(&s));
            c.send_to(b"ping", dst).unwrap();
            let (n, _, local) = recv(&s, &mut buf).unwrap();
            assert_eq!((n, local), (2, Some(ip("127.0.0.2"))));
            c.send_to(b"", dst).unwrap();
            assert_eq!(recv(&s, &mut []).unwrap().0, 0);
        }

        #[test]
        fn kernel_pktinfo_and_control_truncation() {
            for bind in ["0.0.0.0:0", "[::]:0"] {
                let Some(s) = ipv4_listener(bind) else {
                    continue;
                };
                assert!(enable_pktinfo(&s));
                let c = socket("127.0.0.1:0").unwrap();
                let port = s.local_addr().unwrap().port();
                let mut buf = [0; 64];
                // SAFETY: sockaddr_storage consists of integers and bytes.
                let mut name = unsafe { zeroed() };
                let mut control = Control::new();
                c.send_to(b"ping", ("127.0.0.2", port)).unwrap();
                let (n, namelen, len, flags) = recvmsg(&s, &mut buf, &mut name, &mut control.bytes).unwrap();
                assert_eq!(&buf[..n], b"ping");
                let from = from_sockaddr(&name, namelen).unwrap();
                assert_eq!(local_addr(from.ip()), Some(ip("127.0.0.1")));
                assert_eq!(from.port(), c.local_addr().unwrap().port());
                assert_eq!(flags & libc::MSG_CTRUNC, 0);
                assert_eq!(
                    len,
                    if s.local_addr().unwrap().is_ipv6() {
                        SPACE6 + SPACE4
                    } else {
                        SPACE4
                    }
                );
                assert_eq!(
                    local_from_cmsgs(&control.bytes[..len], flags),
                    Some(ip("127.0.0.2"))
                );

                c.send_to(b"ping", ("127.0.0.3", port)).unwrap();
                let short = &mut control.bytes[..HEADER + size_of::<libc::in_pktinfo>() - 1];
                let (_, _, len, flags) = recvmsg(&s, &mut buf, &mut name, short).unwrap();
                assert_ne!(flags & libc::MSG_CTRUNC, 0);
                assert_eq!(local_from_cmsgs(&control.bytes[..len], flags), None);
                assert_eq!(local_from_cmsgs(&control.bytes[..len], 0), None);
            }
        }

        #[test]
        fn sockaddr_lengths_and_scopes() {
            for addr in [
                "192.0.2.7:5060".parse().unwrap(),
                "0.0.0.0:0".parse().unwrap(),
                "255.255.255.255:65535".parse().unwrap(),
                "[2001:db8::42]:5060".parse().unwrap(),
                "[::ffff:10.1.2.3]:5062".parse().unwrap(),
                SocketAddr::V6(SocketAddrV6::new(
                    "fe80::1:2".parse().unwrap(),
                    5061,
                    0x000a_bcde,
                    7,
                )),
            ] {
                let (mut name, len) = to_sockaddr(addr);
                assert_eq!(from_sockaddr(&name, len), Some(addr));
                for n in 0..len {
                    assert_eq!(from_sockaddr(&name, n), None);
                }
                assert_eq!(
                    from_sockaddr(&name, size_of::<libc::sockaddr_storage>() + 1),
                    None
                );
                name.ss_family = libc::AF_UNIX as _;
                assert_eq!(from_sockaddr(&name, len), None);
            }
        }

        fn control(ips: &[IpAddr]) -> (Control, usize) {
            let mut out = Control::new();
            let mut len = 0;
            for &src in ips {
                let mut one = Control::new();
                let n = put_pktinfo(&mut one, SocketAddr::new(src, 5060), src).unwrap();
                out.bytes[len..len + n].copy_from_slice(&one.bytes[..n]);
                len += n;
            }
            (out, len)
        }

        #[test]
        fn ipv4_precedence_and_short_control_messages() {
            let (a4, a6) = (ip("10.0.0.1"), ip("::ffff:10.0.0.2"));
            // Build mapped IPv6 pktinfo explicitly: send expects plain IPv4 src.
            let mut mapped = Control::new();
            let n6 = put_pktinfo(
                &mut mapped,
                "[::ffff:10.0.0.9]:5060".parse().unwrap(),
                ip("10.0.0.2"),
            )
            .unwrap();
            assert_eq!(local_from_cmsgs(&mapped.bytes[..n6], 0), Some(a6));
            let (v4, n4) = control(&[a4]);
            for reverse in [false, true] {
                let mut both = Control::new();
                let (first, second) = if reverse {
                    (&mapped.bytes[..n6], &v4.bytes[..n4])
                } else {
                    (&v4.bytes[..n4], &mapped.bytes[..n6])
                };
                both.bytes[..first.len()].copy_from_slice(first);
                both.bytes[first.len()..first.len() + second.len()].copy_from_slice(second);
                for n in 0..=n4 + n6 {
                    let expected = if !reverse {
                        (n >= HEADER + size_of::<libc::in_pktinfo>()).then_some(a4)
                    } else if n >= n6 + HEADER + size_of::<libc::in_pktinfo>() {
                        Some(a4)
                    } else {
                        (n >= HEADER + size_of::<libc::in6_pktinfo>()).then_some(a6)
                    };
                    assert_eq!(
                        local_from_cmsgs(&both.bytes[..n], 0),
                        expected,
                        "reverse={reverse}, n={n}"
                    );
                }
                assert_eq!(local_from_cmsgs(&both.bytes[..n4 + n6], libc::MSG_CTRUNC), None);
                assert_eq!(
                    local_from_cmsgs(&both.bytes[..n4 + n6], libc::MSG_TRUNC),
                    Some(a4)
                );
            }
            // IPv4 spec_dst wins over the broadcast destination; with no
            // spec_dst, fall back to ipi_addr. Outgoing interface/addr stay zero.
            let (mut c, n) = control(&[a4]);
            // SAFETY: fixture contains a full aligned in_pktinfo after its header.
            unsafe {
                let h = c.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
                let info = &mut *libc::CMSG_DATA(h).cast::<libc::in_pktinfo>();
                assert_eq!((info.ipi_ifindex, info.ipi_addr.s_addr), (0, 0));
                info.ipi_addr.s_addr = u32::MAX;
            }
            assert_eq!(local_from_cmsgs(&c.bytes[..n], 0), Some(a4));
            unsafe {
                let h = c.bytes.as_mut_ptr().cast::<libc::cmsghdr>();
                let info = &mut *libc::CMSG_DATA(h).cast::<libc::in_pktinfo>();
                info.ipi_spec_dst.s_addr = 0;
                info.ipi_addr.s_addr = u32::from_ne_bytes([10, 0, 0, 3]);
            }
            assert_eq!(local_from_cmsgs(&c.bytes[..n], 0), Some(ip("10.0.0.3")));
        }

        #[test]
        fn malformed_or_unaligned_control_is_safe() {
            let (mut c, n) = control(&[ip("10.0.0.1")]);
            c.bytes.copy_within(..n, 1);
            assert_eq!(local_from_cmsgs(&c.bytes[1..n + 1], 0), None);
            for bad in [
                0,
                1,
                HEADER - 1,
                HEADER,
                HEADER + size_of::<libc::in_pktinfo>() - 1,
                n + 1,
                usize::MAX,
            ] {
                let (mut c, n) = control(&[ip("10.0.0.1")]);
                // SAFETY: fixture has a complete aligned cmsghdr; only its
                // declared length is corrupted, not the allocation's bounds.
                unsafe {
                    (*c.bytes.as_mut_ptr().cast::<libc::cmsghdr>()).cmsg_len = bad as _;
                }
                assert_eq!(local_from_cmsgs(&c.bytes[..n], 0), None, "{bad}");
            }
            // Unknown messages are skipped; a malformed later header must not
            // cause a read past the buffer or lose an earlier valid pktinfo.
            let (mut c, n) = control(&[ip("10.0.0.1"), ip("10.0.0.2")]);
            // SAFETY: both fixtures have full, aligned headers at these offsets.
            unsafe {
                (*c.bytes.as_mut_ptr().cast::<libc::cmsghdr>()).cmsg_type = -1;
            }
            assert_eq!(local_from_cmsgs(&c.bytes[..n], 0), Some(ip("10.0.0.2")));
            unsafe {
                (*c.bytes.as_mut_ptr().cast::<libc::cmsghdr>()).cmsg_type = libc::IP_PKTINFO;
                (*c.bytes.as_mut_ptr().add(SPACE4).cast::<libc::cmsghdr>()).cmsg_len = !0;
            }
            assert_eq!(local_from_cmsgs(&c.bytes[..n], 0), Some(ip("10.0.0.1")));

            // Random bytes and mutations of valid messages cannot panic or use
            // bytes beyond the reported length (different hidden tails).
            let mut rng = 0x9e37_79b9_7f4a_7c15u64;
            for round in 0..5000 {
                let (mut c, _) = control(&[ip("10.0.0.1"), ip("2001:db8::1"), ip("10.0.0.3")]);
                for b in &mut c.bytes {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    if round % 2 == 0 || rng % 16 == 0 {
                        *b = rng as u8;
                    }
                }
                let n = round % (c.bytes.len() + 1);
                let result = local_from_cmsgs(&c.bytes[..n], 0);
                c.bytes[n..].fill(0xff);
                assert_eq!(local_from_cmsgs(&c.bytes[..n], 0), result);
            }
        }

        #[test]
        fn no_source_from_multicast_broadcast_or_unspecified() {
            for addr in [
                "0.0.0.0",
                "255.255.255.255",
                "224.0.1.75",
                "ff02::1",
                "::",
                "::ffff:0.0.0.0",
                "::ffff:255.255.255.255",
                "::ffff:224.0.1.75",
            ] {
                assert_eq!(local_addr(ip(addr)), None, "{addr}");
            }
            assert_eq!(local_addr(ip("::ffff:10.0.0.1")), Some(ip("10.0.0.1")));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::*;

    pub fn enable_pktinfo(_: &UdpSocket) -> bool {
        false
    }

    pub fn recv(sock: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
        sock.recv_from(buf).map(|(n, src)| (n, src, None))
    }

    pub fn send(sock: &UdpSocket, data: &[u8], dst: SocketAddr, _src: IpAddr) -> io::Result<usize> {
        sock.send_to(data, dst)
    }
}
