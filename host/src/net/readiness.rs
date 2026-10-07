//! Event-ready execution socket operations with a finite cancellation boundary.
use super::listener::owned_stream;
use crate::dispatcher_wake::DispatcherWake;
use anyhow::Result;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[cfg(unix)]
fn wait(
    socket: &std::net::TcpStream,
    writing: bool,
    deadline: Instant,
    wake: &DispatcherWake,
    revision: u64,
) -> Result<()> {
    use std::os::fd::AsRawFd;
    loop {
        if wake.execution_cancelled() || wake.execution_revision() != revision {
            return Err(std::io::Error::from_raw_os_error(125).into());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock).into());
        }
        let mut descriptors = [
            libc::pollfd {
                fd: socket.as_raw_fd(),
                events: if writing { libc::POLLOUT } else { libc::POLLIN },
                revents: 0,
            },
            libc::pollfd {
                fd: wake.execution_cancel_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let millis = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        // SAFETY: two live owned descriptors and a writable two-element pollfd
        // array. Socket/cancellation events wake immediately, timeout only ends
        // unresolved I/O; no shared socket-table guard crosses this call.
        #[cfg(test)]
        wake.record_execution_wait();
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, millis) };
        if result > 0 {
            if descriptors[1].revents != 0 {
                wake.drain_execution_cancel();
                if wake.execution_cancelled() || wake.execution_revision() != revision {
                    return Err(std::io::Error::from_raw_os_error(125).into());
                }
            }
            if descriptors[0].revents != 0 {
                return Ok(());
            }
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }
}

#[cfg(not(unix))]
fn wait(
    _socket: &std::net::TcpStream,
    _writing: bool,
    _deadline: Instant,
    _wake: &DispatcherWake,
    _revision: u64,
) -> Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::WouldBlock).into())
}

pub(crate) fn send(fd: i32, bytes: &[u8], wake: &DispatcherWake) -> Result<usize> {
    let revision = wake.execution_revision();
    let mut socket = owned_stream(fd)?;
    let deadline = Instant::now() + Duration::from_millis(100);
    loop {
        if wake.execution_cancelled() || wake.execution_revision() != revision {
            return Err(std::io::Error::from_raw_os_error(125).into());
        }
        match socket.write(bytes) {
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait(&socket, true, deadline, wake, revision)?
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn receive(fd: i32, bytes: &mut [u8], wake: &DispatcherWake) -> Result<usize> {
    let revision = wake.execution_revision();
    let mut socket = owned_stream(fd)?;
    let deadline = Instant::now() + Duration::from_millis(100);
    loop {
        if wake.execution_cancelled() || wake.execution_revision() != revision {
            return Err(std::io::Error::from_raw_os_error(125).into());
        }
        match socket.read(bytes) {
            Ok(count) => return Ok(count),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait(&socket, false, deadline, wake, revision)?
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(all(test, unix))]
pub(crate) fn check() {
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::{mpsc, Arc, Barrier};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();
    let fd = super::listener::install_for_readiness_test(stream);
    let wake = Arc::new(DispatcherWake::new());
    let (tx, rx) = mpsc::channel();
    let started = Arc::new(Barrier::new(2));
    let reader = {
        let (wake, started) = (wake.clone(), started.clone());
        std::thread::spawn(move || {
            started.wait();
            let mut bytes = [0; 4];
            tx.send((receive(fd, &mut bytes, &wake).unwrap(), bytes))
                .unwrap();
        })
    };
    started.wait();
    let entered_by = Instant::now() + Duration::from_secs(1);
    while wake.execution_waits() == 0 {
        assert!(Instant::now() < entered_by, "readiness entry not observed");
        std::thread::yield_now();
    }
    // While data I/O is unresolved, control must still acquire the socket table.
    let control = super::listener::tcp_listen(0, 1).unwrap();
    super::listener::tcp_close(control);
    assert!(rx.try_recv().is_err());
    peer.write_all(b"data").unwrap();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        (4, *b"data")
    );
    reader.join().unwrap();
    let mut bytes = [0; 4];
    let before = Instant::now();
    assert!(receive(fd, &mut bytes, &wake).is_err());
    assert!(before.elapsed() >= Duration::from_millis(90));
    super::listener::tcp_close(fd);

    for stopping in [false, true] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        stream.set_nonblocking(true).unwrap();
        let fd = super::listener::install_for_readiness_test(stream);
        let wake = Arc::new(DispatcherWake::new());
        let (tx, rx) = mpsc::channel();
        let reader = {
            let wake = wake.clone();
            std::thread::spawn(move || {
                let mut bytes = [0; 1];
                tx.send(receive(fd, &mut bytes, &wake)).unwrap();
            })
        };
        // Wait for the production helper to expose that it entered readiness.
        let entered_by = Instant::now() + Duration::from_secs(1);
        while wake.execution_waits() == 0 {
            assert!(Instant::now() < entered_by, "readiness entry not observed");
            std::thread::yield_now();
        }
        if stopping {
            wake.shutdown(&std::sync::atomic::AtomicBool::new(false));
        } else {
            wake.notify_execution_cancel();
        }
        let error = rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(125)
        );
        reader.join().unwrap();
        super::listener::tcp_close(fd);
    }
    check_bounded_cancel_drain();
    check_send_ready();
    println!("EXECUTION-SOCKET-READY: real data, control-table independence, finite unresolved boundary, fence/stop event cancellation PASS");
}

#[cfg(all(test, unix))]
fn check_send_ready() {
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::{mpsc, Arc};
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    socket2::SockRef::from(&stream)
        .set_send_buffer_size(4096)
        .unwrap();
    stream.set_nonblocking(true).unwrap();
    let fill = [19; 4096];
    let mut sent = 0_usize;
    loop {
        match stream.write(&fill) {
            Ok(count) => sent += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            other => panic!("unexpected backpressure fixture result: {other:?}"),
        }
        assert!(
            sent < 16 * 1024 * 1024,
            "backpressure fixture must remain bounded"
        );
    }
    let fd = super::listener::install_for_readiness_test(stream);
    let wake = Arc::new(DispatcherWake::new());
    let (tx, rx) = mpsc::channel();
    let writer = {
        let wake = wake.clone();
        std::thread::spawn(move || tx.send(send(fd, b"tail", &wake)).unwrap())
    };
    let entered_by = Instant::now() + Duration::from_secs(1);
    while wake.execution_waits() == 0 {
        assert!(Instant::now() < entered_by, "send wait not observed");
        std::thread::yield_now();
    }
    let mut bytes = vec![0; sent];
    peer.read_exact(&mut bytes).unwrap();
    assert!(bytes.iter().all(|byte| *byte == 19));
    assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap(), 4);
    let mut tail = [0; 4];
    peer.read_exact(&mut tail).unwrap();
    assert_eq!(&tail, b"tail");
    writer.join().unwrap();
    super::listener::tcp_close(fd);
}

#[cfg(all(test, unix))]
fn check_bounded_cancel_drain() {
    let wake = DispatcherWake::new();
    for _ in 0..8 {
        wake.notify_execution_cancel();
    }
    let revision = wake.execution_revision();
    assert_eq!(revision, 8);
    wake.drain_execution_cancel();
    let mut descriptor = libc::pollfd {
        fd: wake.execution_cancel_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid live cancellation descriptor, zero-duration poll.
    assert_eq!(
        unsafe { libc::poll(&mut descriptor, 1, 0) },
        1,
        "one bounded drain must leave retained cancellation queued"
    );
    assert_eq!(wake.execution_revision(), revision);
    wake.notify_execution_cancel();
    assert_ne!(
        wake.execution_revision(),
        revision,
        "later cancel remains observable after bounded drain"
    );
}
