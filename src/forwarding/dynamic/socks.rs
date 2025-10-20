//! SOCKS protocol implementation for dynamic port forwarding

use crate::{forwarding::tunnel::Tunnel, ssh::tokio_client::Client};
use anyhow::Result;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Handle SOCKS4 connection protocol
pub async fn handle_socks4_connection(
    mut tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    ssh_client: &Client,
    cancel_token: CancellationToken,
) -> Result<super::super::tunnel::TunnelStats> {
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

    let destination = format!("{dest_ip}:{dest_port}");
    debug!("SOCKS4 CONNECT to {} from {}", destination, peer_addr);

    // Create SSH channel to destination
    let ssh_channel = match ssh_client
        .open_direct_tcpip_channel(destination.as_str(), None)
        .await
    {
        Ok(channel) => channel,
        Err(e) => {
            debug!("Failed to create SSH channel to {}: {}", destination, e);
            // Send failure response
            let response = [0, 0x5B, 0, 0, 0, 0, 0, 0]; // Request rejected
            tcp_stream.write_all(&response).await?;
            return Err(e.into());
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
    Tunnel::run(tcp_stream, ssh_channel, cancel_token).await
}

/// Handle SOCKS5 connection protocol
pub async fn handle_socks5_connection(
    mut tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    ssh_client: &Client,
    cancel_token: CancellationToken,
) -> Result<super::super::tunnel::TunnelStats> {
    debug!("Handling SOCKS5 connection from {}", peer_addr);

    // Phase 1: Authentication negotiation
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

    // Phase 2: Connection request
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

    // Create SSH channel to destination
    let ssh_channel = match ssh_client
        .open_direct_tcpip_channel(destination.as_str(), None)
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

// **Phase 2 Implementation Notes:**
//
// The full dynamic forwarding implementation will require:
//
// 1. **SOCKS Protocol Implementation:**
//    - SOCKS4: Simple protocol with IP addresses only
//      * Request format: [VER, CMD, DST.PORT, DST.IP, USER_ID, NULL]
//      * Response format: [VER, STATUS, DST.PORT, DST.IP]
//    - SOCKS5: Advanced protocol with authentication and hostname support
//      * Authentication negotiation phase
//      * Connection request phase with multiple address types
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
