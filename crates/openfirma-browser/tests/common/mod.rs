//! Shared helpers for the loopback-endpoint integration tests.

#![allow(dead_code)] // each binary links only the helpers it uses

use std::net::{SocketAddr, TcpStream};

/// A loopback connect that the OS occasionally refuses under load, retried.
///
/// Measured on the macOS CI runner: while this suite's own saturation test had
/// sixteen stalled connections open, `connect()` to 127.0.0.1 failed with
/// `Os { code: 49, kind: AddrNotAvailable, message: "Can't assign requested
/// address" }` — the kernel could not assign a local port for the outbound
/// side. The endpoint was up and answering the whole time (the same run logged
/// its own "16 requests in flight and answered a new connection with 503"), so
/// a refusal here is not the listener dying and must not be read as one.
///
/// A caller retries; so does this. Twenty attempts 150 ms apart is three
/// seconds, well inside every patience loop in these tests, and the refusal
/// that persists is a different animal — a port nobody is listening on — whose
/// panic says exactly that instead of guessing which of the two happened.
pub fn connect(addr: SocketAddr) -> TcpStream {
    const ATTEMPTS: usize = 20;
    for attempt in 0..ATTEMPTS {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(error) if attempt + 1 == ATTEMPTS => panic!(
                "the endpoint at {addr} refused {ATTEMPTS} connections in a row ({error}); \
                 either nothing is listening or the OS kept refusing the local port"
            ),
            Err(error) => {
                eprintln!("openfirma tests: connecting to {addr} was refused ({error}); retrying");
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
        }
    }
    unreachable!("the loop returns or panics")
}
