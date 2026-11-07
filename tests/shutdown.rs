#![cfg(unix)]

use std::{
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

#[test]
#[ignore = "loads the full CPU model"]
fn sigterm_shuts_down_and_removes_staged_model_files() {
    let temporary = tempfile::tempdir().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut child = Command::new(env!("CARGO_BIN_EXE_threat-classifier-proxy"))
        .env("TMPDIR", temporary.path())
        .env("LISTEN_ADDR", address.to_string())
        .env("UPSTREAM_URL", "http://127.0.0.1:9")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ready = false;
    for _ in 0..600 {
        if TcpStream::connect(address).is_ok() {
            ready = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !ready {
        let _ = child.kill();
        let _ = child.wait();
        panic!("proxy did not become ready");
    }
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "proxy was terminated instead of shutting down: {status}"
    );
    assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
}
