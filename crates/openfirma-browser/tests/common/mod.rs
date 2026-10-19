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
/// The two cases get their own patience, because they are different animals.
/// A port nobody is listening on answers ECONNREFUSED immediately and is the
/// failure this helper reports, so it gets 20 attempts (three seconds) —
/// long enough for a listener that is still binding. `AddrNotAvailable` never
/// reached the listener at all: the kernel had no local port to give THIS
/// connect, and the round-two run's two heaviest tests (hundreds of loopback
/// sockets each, thirty seconds each) exhausted the three-second budget while
/// the endpoint stayed up. That case waits thirty seconds, which is spent only
/// when the kernel — not the endpoint — is saying no, and both messages still
/// say which of the two happened instead of guessing.
pub fn connect(addr: SocketAddr) -> TcpStream {
    let mut refusals = 0usize;
    let mut no_local_port = 0usize;
    loop {
        match TcpStream::connect(addr) {
            Ok(stream) => return stream,
            Err(error) => {
                // `AddrNotAvailable` is EADDRNOTAVAIL: the kernel could not
                // pick a source address/port. Everything else is the peer's
                // own answer.
                let kernel_said_no = error.kind() == std::io::ErrorKind::AddrNotAvailable;
                let spent = if kernel_said_no {
                    no_local_port += 1;
                    no_local_port
                } else {
                    refusals += 1;
                    refusals
                };
                if spent >= budget_for(error.kind()) {
                    panic!(
                        "the endpoint at {addr} refused {spent} connections in a row ({error}); \
                         either nothing is listening or the OS kept refusing the local port"
                    );
                }
                eprintln!("openfirma tests: connecting to {addr} was refused ({error}); retrying");
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
        }
    }
}

/// A port nobody is listening on answers ECONNREFUSED immediately and is the
/// failure `connect` reports, so it gets 20 attempts (three seconds) — long
/// enough for a listener that is still binding. `AddrNotAvailable` never
/// reached the listener at all: the kernel had no local port to give THIS
/// connect, and the round-two run's two heaviest tests (hundreds of loopback
/// sockets each, thirty seconds each) exhausted the three-second budget while
/// the endpoint stayed up. That one waits thirty seconds, spent only when the
/// kernel — not the endpoint — is saying no.
fn budget_for(kind: std::io::ErrorKind) -> usize {
    const REFUSALS: usize = 20;
    const NO_LOCAL_PORT: usize = 200;
    if kind == std::io::ErrorKind::AddrNotAvailable {
        NO_LOCAL_PORT
    } else {
        REFUSALS
    }
}

#[cfg(test)]
mod budget_tests {
    use super::budget_for;

    /// The two refusals are different animals and must not share a patience:
    /// a listener that is not answering gets three seconds, a kernel that has
    /// no local port to hand out gets thirty. Collapsing them back into one
    /// budget is what the macOS run punished.
    #[test]
    fn the_kernels_refusal_gets_a_longer_patience_than_the_endpoints() {
        assert_eq!(budget_for(std::io::ErrorKind::ConnectionRefused), 20);
        assert_eq!(budget_for(std::io::ErrorKind::AddrNotAvailable), 200);
        assert!(
            budget_for(std::io::ErrorKind::AddrNotAvailable)
                > budget_for(std::io::ErrorKind::ConnectionRefused)
        );
    }
}
