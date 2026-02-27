use anyhow::Result;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use trojan_rust::proxy::relay;

#[tokio::test]
async fn relay_copies_data_in_both_directions() -> Result<()> {
    let payload_up = vec![0x11; 32 * 1024];
    let payload_down = vec![0x22; 16 * 1024];
    let expected_up = payload_up.clone();
    let expected_down = payload_down.clone();

    let (client_stream, client_peer) = duplex(64 * 1024);
    let (remote_stream, remote_peer) = duplex(64 * 1024);

    let relay_task = tokio::spawn(async move { relay(client_stream, remote_stream).await });

    let (mut client_reader, mut client_writer) = tokio::io::split(client_peer);
    let (mut remote_reader, mut remote_writer) = tokio::io::split(remote_peer);

    let upstream_len = payload_up.len();
    let downstream_len = payload_down.len();

    let upstream_writer = tokio::spawn(async move {
        client_writer.write_all(&payload_up).await?;
        client_writer.shutdown().await
    });

    let downstream_writer = tokio::spawn(async move {
        remote_writer.write_all(&payload_down).await?;
        remote_writer.shutdown().await
    });

    let upstream_reader = tokio::spawn(async move {
        let mut received = vec![0u8; upstream_len];
        remote_reader.read_exact(&mut received).await?;
        Ok::<Vec<u8>, std::io::Error>(received)
    });

    let downstream_reader = tokio::spawn(async move {
        let mut received = vec![0u8; downstream_len];
        client_reader.read_exact(&mut received).await?;
        Ok::<Vec<u8>, std::io::Error>(received)
    });

    upstream_writer.await??;
    downstream_writer.await??;
    let received_up = upstream_reader.await??;
    let received_down = downstream_reader.await??;

    let (upstream_bytes, downstream_bytes) = relay_task.await??;

    assert_eq!(upstream_bytes, upstream_len as u64);
    assert_eq!(downstream_bytes, downstream_len as u64);
    assert_eq!(received_up, expected_up);
    assert_eq!(received_down, expected_down);

    Ok(())
}
