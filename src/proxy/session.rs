use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::protocol::{Address, Command};

static SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Session {
    pub id: u64,
    pub client_addr: SocketAddr,
    pub target: Address,
    pub command: Command,
    pub start_time: Instant,
    pub bytes_sent: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
}

impl Session {
    pub fn new(client_addr: SocketAddr, target: Address, command: Command) -> Self {
        let id = SESSION_ID.fetch_add(1, Ordering::SeqCst);
        Self {
            id,
            client_addr,
            target,
            command,
            start_time: Instant::now(),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn duration(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    pub fn add_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }
}
