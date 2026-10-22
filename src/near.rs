//! The archival NEAR RPC client the fill run and the review use.
//!
//! One blocking HTTPS POST of a JSON-RPC `tx` call per attestation, over
//! rustls with the ring provider and the webpki roots, which the light
//! server path already uses. It returns the response body exactly as
//! received, because the attestation hashes those bytes.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::json;

use crate::attest::NearRpc;
use crate::error::Error;

/// Above the archival node's own wait: a `tx` call with `wait_until: FINAL`
/// for a transaction it has not seen holds for about 33 s and then answers
/// HTTP 408 with a JSON error (measured 2026-10-22). A final transaction
/// answers at once.
/// A `tx` response is a few kB; anything near this is not one.
const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

const TIMEOUT: Duration = Duration::from_secs(75);

/// A NEAR JSON-RPC endpoint over HTTPS.
#[derive(Clone, Debug)]
pub struct ArchivalRpc {
    url: String,
    host: String,
    port: u16,
    path: String,
}

impl ArchivalRpc {
    /// An endpoint such as `https://archival-rpc.testnet.near.org`.
    pub fn new(url: &str) -> Result<Self, Error> {
        let rest = url
            .strip_prefix("https://")
            .ok_or_else(|| Error::Attestation(format!("{url}: only https is supported")))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_string(),
                p.parse()
                    .map_err(|_| Error::Attestation(format!("{url}: bad port")))?,
            ),
            None => (authority.to_string(), 443),
        };
        Ok(ArchivalRpc {
            url: url.to_string(),
            host,
            port,
            path,
        })
    }

    fn post(&self, body: &[u8]) -> Result<Vec<u8>, Error> {
        let err = |what: &str, e: &dyn std::fmt::Display| {
            Error::Attestation(format!("{}: {what}: {e}", self.url))
        };
        let address = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| err("resolve", &e))?
            .next()
            .ok_or_else(|| Error::Attestation(format!("{}: no address", self.url)))?;
        let tcp = TcpStream::connect_timeout(&address, TIMEOUT).map_err(|e| err("connect", &e))?;
        tcp.set_read_timeout(Some(TIMEOUT))
            .map_err(|e| err("socket", &e))?;
        tcp.set_write_timeout(Some(TIMEOUT))
            .map_err(|e| err("socket", &e))?;
        let name = ServerName::try_from(self.host.clone()).map_err(|e| err("server name", &e))?;
        let connection = ClientConnection::new(tls_config()?, name).map_err(|e| err("tls", &e))?;
        let mut stream = StreamOwned::new(connection, tcp);
        let head = format!(
            "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.path,
            self.host,
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .and_then(|()| stream.write_all(body))
            .map_err(|e| err("write", &e))?;
        let mut response = Vec::new();
        match (&mut stream).take(MAX_RESPONSE).read_to_end(&mut response) {
            Ok(_) => {}
            // Some servers close without TLS close_notify after a complete
            // HTTP/1.0 response.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !response.is_empty() => {}
            Err(e) => return Err(err("read", &e)),
        }
        if response.len() as u64 >= MAX_RESPONSE {
            return Err(Error::Attestation(format!(
                "{}: the response exceeds 16 MiB",
                self.url
            )));
        }
        http_body(&response).map_err(|e| err("response", &e))
    }
}

impl NearRpc for ArchivalRpc {
    fn url(&self) -> &str {
        &self.url
    }

    fn tx(&self, hash: &str, sender: &str) -> Result<Vec<u8>, Error> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": "ironwood-intent-escrow",
            "method": "tx",
            "params": {"tx_hash": hash, "sender_account_id": sender, "wait_until": "FINAL"},
        });
        self.post(request.to_string().as_bytes())
    }
}

fn tls_config() -> Result<Arc<ClientConfig>, Error> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::Attestation(format!("tls: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The body of an HTTP/1.x response with status 2xx or 4xx; NEAR reports
/// handler errors as JSON with either. A chunked body is decoded.
fn http_body(response: &[u8]) -> Result<Vec<u8>, String> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no header terminator")?;
    let head = String::from_utf8_lossy(&response[..split]);
    let body = &response[split + 4..];
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("no status code")?;
    if !(200..500).contains(&status) {
        return Err(format!("HTTP {status}"));
    }
    let chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().replace(' ', "") == "transfer-encoding:chunked");
    if chunked {
        dechunk(body)
    } else {
        Ok(body.to_vec())
    }
}

fn dechunk(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("bad chunk")?;
        let size_text = String::from_utf8_lossy(&body[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "bad chunk size")?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        let chunk = body.get(..size).ok_or("short chunk")?;
        out.extend_from_slice(chunk);
        body = body.get(size + 2..).ok_or("short chunk")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn near_rpc_parses_urls_and_http_bodies() {
        let rpc = ArchivalRpc::new("https://archival-rpc.testnet.near.org").unwrap();
        assert_eq!(
            (rpc.host.as_str(), rpc.port, rpc.path.as_str()),
            ("archival-rpc.testnet.near.org", 443, "/")
        );
        assert!(ArchivalRpc::new("http://example.org").is_err());

        let plain = b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        assert_eq!(http_body(plain).unwrap(), b"{\"a\":1}");
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        assert_eq!(http_body(chunked).unwrap(), b"{\"a\":1}");
        assert!(http_body(b"HTTP/1.1 503 Service Unavailable\r\n\r\n").is_err());
    }
}
