//! SOCKS protocol implementation for dynamic port forwarding

use crate::{
    forwarding::tunnel::Tunnel,
    ssh::tokio_client::{AddressFamily, Client, Error as SshError},
};
use anyhow::Result;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Handle SOCKS4 connection protocol
pub async fn handle_socks4_connection(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    ssh_client: &Client,
    cancel_token: CancellationToken,
    address_family: AddressFamily,
) -> Result<super::super::tunnel::TunnelStats> {
    handle_socks4_connection_with(
        tcp_stream,
        peer_addr,
        cancel_token,
        address_family,
        |destination| async move {
            ssh_client
                .open_direct_tcpip_channel(destination.as_str(), None)
                .await
                .map_err(anyhow::Error::from)
        },
        |tcp_stream, ssh_channel, cancel_token| async move {
            Tunnel::run(tcp_stream, ssh_channel, cancel_token).await
        },
    )
    .await
}

async fn handle_socks4_connection_with<
    IoStream,
    OpenChannel,
    OpenFuture,
    ChannelTarget,
    RunTunnel,
    RunFuture,
>(
    mut tcp_stream: IoStream,
    peer_addr: SocketAddr,
    cancel_token: CancellationToken,
    address_family: AddressFamily,
    open_channel: OpenChannel,
    run_tunnel: RunTunnel,
) -> Result<super::super::tunnel::TunnelStats>
where
    IoStream: AsyncRead + AsyncWrite + Unpin,
    OpenChannel: FnOnce(String) -> OpenFuture,
    OpenFuture: Future<Output = Result<ChannelTarget>>,
    RunTunnel: FnOnce(IoStream, ChannelTarget, CancellationToken) -> RunFuture,
    RunFuture: Future<Output = Result<super::super::tunnel::TunnelStats>>,
{
    debug!("Handling SOCKS4 connection from {}", peer_addr);

    // Read SOCKS4 request: VER(1) + CMD(1) + DSTPORT(2) + DSTIP(4) + USERID(variable) + NULL(1)
    let mut request_header = [0u8; 8]; // First 8 bytes (VER + CMD + DSTPORT + DSTIP)
    tcp_stream.read_exact(&mut request_header).await?;

    let version = request_header[0];
    let command = request_header[1];
    let dest_port = u16::from_be_bytes([request_header[2], request_header[3]]);
    let dest_ip = std::net::Ipv4Addr::from([
        request_header[4],
        request_header[5],
        request_header[6],
        request_header[7],
    ]);

    // Verify SOCKS4 version
    if version != 4 {
        debug!("Invalid SOCKS4 version: {} from {}", version, peer_addr);
        // Send failure response
        let response = [0, 0x5B, 0, 0, 0, 0, 0, 0]; // 0x5B = request rejected
        tcp_stream.write_all(&response).await?;
        return Err(anyhow::anyhow!("Invalid SOCKS4 version: {version}"));
    }

    // Only support CONNECT command (0x01)
    if command != 0x01 {
        debug!("Unsupported SOCKS4 command: {} from {}", command, peer_addr);
        let response = [0, 0x5C, 0, 0, 0, 0, 0, 0]; // 0x5C = request failed
        tcp_stream.write_all(&response).await?;
        return Err(anyhow::anyhow!("Unsupported SOCKS4 command: {command}"));
    }

    // Read USERID (until NULL byte)
    let mut userid = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        tcp_stream.read_exact(&mut byte).await?;
        if byte[0] == 0 {
            break; // NULL terminator
        }
        userid.push(byte[0]);
        if userid.len() > 255 {
            // Prevent excessive memory usage
            let response = [0, 0x5B, 0, 0, 0, 0, 0, 0]; // Request rejected
            tcp_stream.write_all(&response).await?;
            return Err(anyhow::anyhow!("USERID too long"));
        }
    }

    let destination = match socks4_destination_for_family(dest_ip, dest_port, address_family) {
        Ok(destination) => destination,
        Err(e) => {
            debug!(
                "Rejected SOCKS4 CONNECT to {}:{} for forced {} from {}: {}",
                dest_ip, dest_port, address_family, peer_addr, e
            );
            let response = [0, 0x5B, 0, 0, 0, 0, 0, 0]; // Request rejected
            tcp_stream.write_all(&response).await?;
            return Err(e.into());
        }
    };
    debug!("SOCKS4 CONNECT to {} from {}", destination, peer_addr);

    // Create SSH channel to destination
    let ssh_channel = match open_channel(destination.clone()).await {
        Ok(channel) => channel,
        Err(e) => {
            debug!("Failed to create SSH channel to {}: {}", destination, e);
            // Send failure response
            let response = [0, 0x5B, 0, 0, 0, 0, 0, 0]; // Request rejected
            tcp_stream.write_all(&response).await?;
            return Err(e);
        }
    };

    // Send success response: VER(1) + REP(1) + DSTPORT(2) + DSTIP(4)
    let response = [
        0,    // VER (should be 0 for response)
        0x5A, // REP (0x5A = success)
        (dest_port >> 8) as u8,
        (dest_port & 0xff) as u8, // DSTPORT
        dest_ip.octets()[0],
        dest_ip.octets()[1],
        dest_ip.octets()[2],
        dest_ip.octets()[3], // DSTIP
    ];
    tcp_stream.write_all(&response).await?;

    debug!("SOCKS4 tunnel established: {} ↔ {}", peer_addr, destination);

    // Start bidirectional tunnel
    run_tunnel(tcp_stream, ssh_channel, cancel_token).await
}

fn socks4_destination_for_family(
    dest_ip: Ipv4Addr,
    dest_port: u16,
    address_family: AddressFamily,
) -> Result<String, SshError> {
    let destination = SocketAddr::new(IpAddr::V4(dest_ip), dest_port);
    if address_family.is_forced() && !address_family.matches(&destination) {
        return Err(SshError::NoAddressForFamily {
            host: dest_ip.to_string(),
            family: address_family,
        });
    }

    Ok(format!("{dest_ip}:{dest_port}"))
}

/// Handle SOCKS5 connection protocol
pub async fn handle_socks5_connection(
    mut tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    ssh_client: &Client,
    cancel_token: CancellationToken,
    address_family: AddressFamily,
) -> Result<super::super::tunnel::TunnelStats> {
    debug!("Handling SOCKS5 connection from {}", peer_addr);

    // Step 1: Authentication negotiation
    // Read client's authentication methods: VER(1) + NMETHODS(1) + METHODS(1-255)
    let mut auth_request = [0u8; 2];
    tcp_stream.read_exact(&mut auth_request).await?;

    let version = auth_request[0];
    let nmethods = auth_request[1];

    if version != 5 {
        return Err(anyhow::anyhow!("Invalid SOCKS5 version: {version}"));
    }

    // Read authentication methods
    let mut methods = vec![0u8; nmethods as usize];
    tcp_stream.read_exact(&mut methods).await?;

    // We only support "no authentication required" (0x00)
    let selected_method = if methods.contains(&0x00) {
        0x00 // No authentication required
    } else {
        0xFF // No acceptable methods
    };

    // Send authentication method selection response: VER(1) + METHOD(1)
    let auth_response = [5, selected_method];
    tcp_stream.write_all(&auth_response).await?;

    if selected_method == 0xFF {
        return Err(anyhow::anyhow!("No acceptable authentication method"));
    }

    // Step 2: Connection request
    // Read SOCKS5 request: VER(1) + CMD(1) + RSV(1) + ATYP(1) + DST.ADDR(variable) + DST.PORT(2)
    let mut request_header = [0u8; 4];
    tcp_stream.read_exact(&mut request_header).await?;

    let version = request_header[0];
    let command = request_header[1];
    let _reserved = request_header[2];
    let address_type = request_header[3];

    if version != 5 {
        return Err(anyhow::anyhow!("Invalid SOCKS5 request version: {version}"));
    }

    // Only support CONNECT command (0x01)
    if command != 0x01 {
        // Send error response
        let response = [5, 0x07, 0, 1, 0, 0, 0, 0, 0, 0]; // Command not supported
        tcp_stream.write_all(&response).await?;
        return Err(anyhow::anyhow!("Unsupported SOCKS5 command: {command}"));
    }

    // Parse destination address based on address type
    let destination = match address_type {
        0x01 => {
            // IPv4 address: 4 bytes
            let mut addr_bytes = [0u8; 4];
            tcp_stream.read_exact(&mut addr_bytes).await?;
            let mut port_bytes = [0u8; 2];
            tcp_stream.read_exact(&mut port_bytes).await?;

            let ip = std::net::Ipv4Addr::from(addr_bytes);
            let port = u16::from_be_bytes(port_bytes);
            format!("{ip}:{port}")
        }
        0x03 => {
            // Domain name: 1 byte length + domain name + 2 bytes port
            let mut len_byte = [0u8; 1];
            tcp_stream.read_exact(&mut len_byte).await?;
            let domain_len = len_byte[0] as usize;

            let mut domain_bytes = vec![0u8; domain_len];
            tcp_stream.read_exact(&mut domain_bytes).await?;
            let domain = String::from_utf8_lossy(&domain_bytes);

            let mut port_bytes = [0u8; 2];
            tcp_stream.read_exact(&mut port_bytes).await?;
            let port = u16::from_be_bytes(port_bytes);

            format!("{domain}:{port}")
        }
        0x04 => {
            // IPv6 address: 16 bytes + 2 bytes port (not fully implemented)
            let response = [5, 0x08, 0, 1, 0, 0, 0, 0, 0, 0]; // Address type not supported
            tcp_stream.write_all(&response).await?;
            return Err(anyhow::anyhow!("IPv6 address type not yet supported"));
        }
        _ => {
            let response = [5, 0x08, 0, 1, 0, 0, 0, 0, 0, 0]; // Address type not supported
            tcp_stream.write_all(&response).await?;
            return Err(anyhow::anyhow!("Unsupported address type: {address_type}"));
        }
    };

    debug!("SOCKS5 CONNECT to {} from {}", destination, peer_addr);

    // Create SSH channel to destination. Domain requests stay as names unless
    // an address family is forced, in which case the channel manager resolves
    // and sends a matching numeric address.
    let ssh_channel = match ssh_client
        .open_direct_tcpip_channel_with_family(destination.as_str(), None, address_family)
        .await
    {
        Ok(channel) => channel,
        Err(e) => {
            debug!("Failed to create SSH channel to {}: {}", destination, e);
            // Send failure response: VER + REP + RSV + ATYP + BND.ADDR + BND.PORT
            let response = [5, 0x05, 0, 1, 0, 0, 0, 0, 0, 0]; // Connection refused
            tcp_stream.write_all(&response).await?;
            return Err(e.into());
        }
    };

    // Send success response: VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(4) + BND.PORT(2)
    let response = [5, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]; // Success, bound to 0.0.0.0:0
    tcp_stream.write_all(&response).await?;

    debug!("SOCKS5 tunnel established: {} ↔ {}", peer_addr, destination);

    // Start bidirectional tunnel
    Tunnel::run(tcp_stream, ssh_channel, cancel_token).await
}

// **SOCKS Protocol Implementation Notes:**
//
// The full dynamic forwarding implementation will require:
//
// 1. **SOCKS Protocol Implementation:**
//    - SOCKS4: Simple protocol with IP addresses only
//      * Request format: [VER, CMD, DST.PORT, DST.IP, USER_ID, NULL]
//      * Response format: [VER, STATUS, DST.PORT, DST.IP]
//    - SOCKS5: Advanced protocol with authentication and hostname support
//      * Authentication negotiation step
//      * Connection request step with multiple address types
//      * Support for CONNECT, BIND, and UDP ASSOCIATE commands
//
// 2. **DNS Resolution:**
//    - For SOCKS5 hostname requests, resolve through remote SSH connection
//    - Implement DNS-over-SSH for accurate remote resolution
//    - Cache resolved addresses for performance
//
// 3. **Authentication Support (SOCKS5):**
//    - No authentication (method 0x00)
//    - Username/password authentication (method 0x02)
//    - Future: GSSAPI authentication (method 0x01)

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::tunnel::TunnelStats;
    use anyhow::anyhow;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn socks4_request(dest_ip: Ipv4Addr, dest_port: u16, userid: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(8 + userid.len() + 1);
        frame.push(0x04);
        frame.push(0x01);
        frame.extend_from_slice(&dest_port.to_be_bytes());
        frame.extend_from_slice(&dest_ip.octets());
        frame.extend_from_slice(userid);
        frame.push(0x00);
        frame
    }

    async fn run_socks4_protocol_case(
        address_family: AddressFamily,
    ) -> Result<([u8; 8], usize, anyhow::Error)> {
        let open_count = Arc::new(AtomicUsize::new(0));
        let open_count_for_task = Arc::clone(&open_count);
        let peer_addr: SocketAddr = "127.0.0.1:4242".parse().expect("peer address parses");
        let (mut client_stream, server_stream) = tokio::io::duplex(128);

        let server = tokio::spawn(async move {
            handle_socks4_connection_with(
                server_stream,
                peer_addr,
                CancellationToken::new(),
                address_family,
                move |destination| {
                    let open_count = Arc::clone(&open_count_for_task);
                    async move {
                        open_count.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(destination, "192.0.2.25:8080");
                        Err(anyhow!("synthetic channel-open stop"))
                    }
                },
                |_tcp_stream, _channel_target: (), _cancel_token| async move {
                    Ok(TunnelStats::default())
                },
            )
            .await
            .expect_err("the synthetic seam stop must surface as an error")
        });

        client_stream
            .write_all(&socks4_request(
                Ipv4Addr::new(192, 0, 2, 25),
                8080,
                b"acceptance-user",
            ))
            .await
            .expect("client sends SOCKS4 request");

        let mut response = [0u8; 8];
        client_stream
            .read_exact(&mut response)
            .await
            .expect("client reads SOCKS4 response");

        let err = server.await.expect("server task joins");
        Ok((response, open_count.load(Ordering::Relaxed), err))
    }

    #[test]
    fn socks4_destination_accepts_ipv4_when_unforced_or_ipv4_forced() {
        let dest_ip = Ipv4Addr::new(192, 0, 2, 25);
        let dest_port = 8080;

        assert_eq!(
            socks4_destination_for_family(dest_ip, dest_port, AddressFamily::Any)
                .expect("unforced SOCKS4 must preserve the IPv4 destination"),
            "192.0.2.25:8080"
        );
        assert_eq!(
            socks4_destination_for_family(dest_ip, dest_port, AddressFamily::V4)
                .expect("forced IPv4 must still allow the SOCKS4 IPv4 destination"),
            "192.0.2.25:8080"
        );
    }

    #[test]
    fn socks4_destination_rejects_forced_ipv6() {
        let err =
            socks4_destination_for_family(Ipv4Addr::new(192, 0, 2, 25), 8080, AddressFamily::V6)
                .expect_err("forced IPv6 must reject the SOCKS4 IPv4 literal");

        assert!(matches!(
            err,
            SshError::NoAddressForFamily {
                ref host,
                family: AddressFamily::V6,
            } if host == "192.0.2.25"
        ));
        assert_eq!(err.to_string(), "no IPv6 address found for 192.0.2.25");
    }

    #[tokio::test]
    async fn socks4_protocol_rejects_forced_ipv6_before_channel_open() {
        let (response, open_count, err) = run_socks4_protocol_case(AddressFamily::V6)
            .await
            .expect("protocol case completes");

        assert_eq!(response, [0, 0x5B, 0, 0, 0, 0, 0, 0]);
        assert_eq!(open_count, 0, "forced IPv6 must reject before channel open");
        assert_eq!(err.to_string(), "no IPv6 address found for 192.0.2.25");
    }

    #[tokio::test]
    async fn socks4_protocol_any_reaches_channel_open_seam() {
        let (response, open_count, err) = run_socks4_protocol_case(AddressFamily::Any)
            .await
            .expect("protocol case completes");

        assert_eq!(response, [0, 0x5B, 0, 0, 0, 0, 0, 0]);
        assert_eq!(open_count, 1, "unforced SOCKS4 must reach channel open");
        assert!(
            err.to_string().contains("synthetic channel-open stop"),
            "the injected channel-open seam error must surface"
        );
    }

    #[tokio::test]
    async fn socks4_protocol_ipv4_reaches_channel_open_seam() {
        let (response, open_count, err) = run_socks4_protocol_case(AddressFamily::V4)
            .await
            .expect("protocol case completes");

        assert_eq!(response, [0, 0x5B, 0, 0, 0, 0, 0, 0]);
        assert_eq!(open_count, 1, "forced IPv4 must reach channel open");
        assert!(
            err.to_string().contains("synthetic channel-open stop"),
            "the injected channel-open seam error must surface"
        );
    }
}
