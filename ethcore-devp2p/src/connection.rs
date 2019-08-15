// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;

use crypto::aes::{AesCtr256, AesEcb256};
use ethereum_types::{H128, H256, H512};
use futures::prelude::*;
use keccak_hash::{keccak, write_keccak};
use log::{debug, trace, warn};
use mio::{Ready, Token};
use parity_bytes::Bytes;
use rlp::{Rlp, RlpStream};
use runtime::net::TcpStream;
use tiny_keccak::Keccak;

use ethcore_io::{IoContext, StreamToken};
use ethkey::{crypto as ethcrypto, Secret};
use network::Error;

use crate::handshake::Handshake;

const ENCRYPTED_HEADER_LEN: usize = 32;
const RECEIVE_PAYLOAD: Duration = Duration::from_secs(30);
pub const MAX_PAYLOAD_SIZE: usize = (1 << 24) - 1;

/// Network responses should try not to go over this limit.
/// This should be lower than MAX_PAYLOAD_SIZE
pub const PAYLOAD_SOFT_LIMIT: usize = (1 << 22) - 1;

pub trait GenericSocket {}

impl GenericSocket for TcpStream {}

/// Writer half of the connection
pub type ConnectionWriter = futures::io::WriteHalf<TcpStream>;

/// Info from the connection, local & remote addresses
pub struct ConnectionInfo {
	pub remote_address: Option<SocketAddr>,
	pub local_address: Option<SocketAddr>,
}

impl From<&TcpStream> for ConnectionInfo {
	fn from(stream: &TcpStream) -> ConnectionInfo {
		let remote_address = stream.peer_addr().ok();
		let local_address = stream.local_addr().ok();

		ConnectionInfo {
			remote_address,
			local_address,
		}
	}
}

pub struct GenericConnection {
    /// Connection id (token)
    pub token: StreamToken,
    /// Writer half of the network socket
    pub writer: ConnectionWriter,
	/// Connection info from the network socket
	pub info: ConnectionInfo,
    /// Receive buffer
    rec_buf: Bytes,
    /// Expected size
    rec_size: usize,
    // /// Send out packets FIFO
    // send_queue: VecDeque<Cursor<Bytes>>,
    /// Event flags this connection expects
    interest: Ready,
    /// Registered flag
    registered: AtomicBool,
}

impl GenericConnection {
    pub fn expect(&mut self, size: usize) {
        trace!(target:"network", "Expect to read {} bytes", size);
        if self.rec_size != self.rec_buf.len() {
            warn!(target:"network", "Unexpected connection read start");
        }
        self.rec_size = size;
    }

    /// Readable IO handler. Called when there is some data to be read.
    pub async fn readable(&mut self) -> io::Result<Option<Bytes>> {
        if self.rec_size == 0 || self.rec_buf.len() >= self.rec_size {
            return Ok(None);
        }
        let mut buf = vec![0u8; self.rec_size];
        // self.socket.read(&mut buf).await?;
        Ok(Some(Bytes::from(buf)))
    }

    /// Add a packet to send queue.
    pub async fn send(&mut self, data: Bytes) -> Result<(), Error> {
        if !data.is_empty() {
            trace!(target:"network", "{}: Sending {} bytes", self.token, data.len());
            self.writer.write_all(&data).await?;
        }
        Ok(())
    }

    /// Check if this connection has data to be sent.
    pub fn is_sending(&self) -> bool {
        self.interest.is_writable()
    }

    /// Writable IO handler. Called when the socket is ready to send.
    pub async fn writable(&mut self) -> Result<WriteStatus, Error> {
        return Ok(WriteStatus::Complete);
    }
}

/// Low level tcp connection
// pub type Connection = GenericConnection<TcpStream>;
pub type Connection = GenericConnection;

impl Connection {
    /// Create a new connection with given id and socket.
    pub fn new(token: StreamToken, conn_writer: ConnectionWriter, conn_info: ConnectionInfo) -> Connection {
        Connection {
            token,
			writer: conn_writer,
			info: conn_info,
            rec_buf: Bytes::new(),
            rec_size: 0,
            interest: Ready::hup() | Ready::readable(),
            registered: AtomicBool::new(false),
        }
    }

    /// Get socket token
    pub fn token(&self) -> StreamToken {
        self.token
    }

    /// Get remote peer address
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.info.remote_address.clone()
    }

    /// Get remote peer address string
    pub fn remote_addr_str(&self) -> String {
        self.info.remote_address
            .map(|a| a.to_string())
            .unwrap_or_else(|| {
                debug!(
                    "Error occurred getting peer_addr, connection token: {}",
                    self.token
                );
                "Unknown peer address".to_owned()
            })
    }

    /// Get local peer address string
    pub fn local_addr_str(&self) -> String {
        self.info.local_address
            .map(|a| a.to_string())
            .unwrap_or_else(|| "Unknown".to_owned())
    }

    /// Register this connection with the IO event loop.
    pub fn register_socket(
        &self,
        reg: Token,
    ) -> io::Result<()> {
        if self.registered.load(AtomicOrdering::SeqCst) {
            return Ok(());
        }
        trace!(target: "network", "connection register; token={:?}", reg);
        // if let Err(e) = event_loop.register(
        //     &self.socket,
        //     reg,
        //     self.interest,
        //     PollOpt::edge(), /* | PollOpt::oneshot() */
        // ) {
        //     // TODO: oneshot is broken on windows
        //     trace!(target: "network", "Failed to register {:?}, {:?}", reg, e);
        // }
        self.registered.store(true, AtomicOrdering::SeqCst);
        Ok(())
    }

    /// Update connection registration. Should be called at the end of the IO handler.
    pub fn update_socket(
        &self,
        reg: Token,
    ) -> io::Result<()> {
        trace!(target: "network", "connection reregister; token={:?}", reg);
        if !self.registered.load(AtomicOrdering::SeqCst) {
            self.register_socket(reg)
        } else {
            // event_loop
            //     .reregister(
            //         &self.socket,
            //         reg,
            //         self.interest,
            //         PollOpt::edge(), /* | PollOpt::oneshot() */
            //     )
            //     .unwrap_or_else(|e| {
            //         // TODO: oneshot is broken on windows
            //         trace!(target: "network", "Failed to reregister {:?}, {:?}", reg, e);
            //     });
            Ok(())
        }
    }

    /// Delete connection registration. Should be called at the end of the IO handler.
    pub fn deregister_socket(
        &self,
    ) -> io::Result<()> {
        trace!(target: "network", "connection deregister; token={:?}", self.token);
        // event_loop.deregister(&self.socket).ok(); // ignore errors here
        Ok(())
    }
}

/// Connection write status.
#[derive(PartialEq, Eq)]
pub enum WriteStatus {
    /// All data sent.
    Complete,
}

/// `RLPx` packet
pub struct Packet {
    pub protocol: u16,
    pub data: Bytes,
}

/// Encrypted connection receiving state.
enum EncryptedConnectionState {
    /// Reading a header.
    Header,
    /// Reading the rest of the packet.
    Payload,
}

/// Connection implementing `RLPx` framing
/// https://github.com/ethereum/devp2p/blob/master/rlpx.md#framing
pub struct EncryptedConnection {
    /// Underlying tcp connection
    pub connection: Connection,
    /// Egress data encryptor
    encoder: AesCtr256,
    /// Ingress data decryptor
    decoder: AesCtr256,
    /// Ingress data decryptor
    mac_encoder_key: Secret,
    /// MAC for egress data
    egress_mac: Keccak,
    /// MAC for ingress data
    ingress_mac: Keccak,
    /// Read state
    read_state: EncryptedConnectionState,
    /// Protocol id for the last received packet
    protocol_id: u16,
    /// Payload expected to be received for the last header.
    payload_len: usize,
}

const NULL_IV: [u8; 16] = [0; 16];
impl EncryptedConnection {
    /// Create an encrypted connection out of the handshake.
    pub fn new(handshake: Handshake) -> Result<EncryptedConnection, Error> {
        let shared = ethcrypto::ecdh::agree(handshake.ecdhe.secret(), &handshake.remote_ephemeral)?;
        let mut nonce_material = H512::default();
        if handshake.originated {
            (&mut nonce_material[0..32]).copy_from_slice(handshake.remote_nonce.as_bytes());
            (&mut nonce_material[32..64]).copy_from_slice(handshake.nonce.as_bytes());
        } else {
            (&mut nonce_material[0..32]).copy_from_slice(handshake.nonce.as_bytes());
            (&mut nonce_material[32..64]).copy_from_slice(handshake.remote_nonce.as_bytes());
        }
        let mut key_material = H512::default();
        (&mut key_material[0..32]).copy_from_slice(shared.as_bytes());
        write_keccak(&nonce_material, &mut key_material[32..64]);
        let key_material_keccak = keccak(&key_material);
        (&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());
        let key_material_keccak = keccak(&key_material);
        (&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());

        // Using a 0 IV with CTR is fine as long as the same IV is never reused with the same key.
        // This is the case here: ecdh creates a new secret which will be the symmetric key used
        // only for this session the 0 IV is only use once with this secret, so we are in the case
        // of same IV use for different key.
        let encoder = AesCtr256::new(&key_material[32..64], &NULL_IV)?;
        let decoder = AesCtr256::new(&key_material[32..64], &NULL_IV)?;
        let key_material_keccak = keccak(&key_material);
        (&mut key_material[32..64]).copy_from_slice(key_material_keccak.as_bytes());
        let mac_encoder_key: Secret = Secret::from_slice(&key_material[32..64])
            .expect("can create Secret from 32 bytes; qed");

        let mut egress_mac = Keccak::new_keccak256();
        let mut mac_material = H256::from_slice(&key_material[32..64]) ^ handshake.remote_nonce;
        egress_mac.update(mac_material.as_bytes());
        egress_mac.update(if handshake.originated {
            &handshake.auth_cipher
        } else {
            &handshake.ack_cipher
        });

        let mut ingress_mac = Keccak::new_keccak256();
        mac_material = H256::from_slice(&key_material[32..64]) ^ handshake.nonce;
        ingress_mac.update(mac_material.as_bytes());
        ingress_mac.update(if handshake.originated {
            &handshake.ack_cipher
        } else {
            &handshake.auth_cipher
        });

        // let old_connection = handshake.connection.try_clone()?;
        // let connection = ::std::mem::replace(&mut handshake.connection, old_connection);
        let mut enc = EncryptedConnection {
            connection: handshake.connection,
            encoder,
            decoder,
            mac_encoder_key,
            egress_mac,
            ingress_mac,
            read_state: EncryptedConnectionState::Header,
            protocol_id: 0,
            payload_len: 0,
        };
        enc.connection.expect(ENCRYPTED_HEADER_LEN);
        Ok(enc)
    }

    /// Send a packet
    pub async fn send_packet(&mut self, payload: &[u8]) -> Result<(), Error> {
        const HEADER_LEN: usize = 16;
        let mut header = RlpStream::new();
        let len = payload.len();
        if len > MAX_PAYLOAD_SIZE {
            return Err(Error::OversizedPacket);
        }

        header.append_raw(&[(len >> 16) as u8, (len >> 8) as u8, len as u8], 1);
        header.append_raw(&[0xc2u8, 0x80u8, 0x80u8], 1);
        let padding = (16 - (len % 16)) % 16;

        let mut packet = vec![0u8; 16 + 16 + len + padding + 16];
        let mut header = header.out();
        header.resize(HEADER_LEN, 0u8);
        &mut packet[..HEADER_LEN].copy_from_slice(&mut header);
        self.encoder.encrypt(&mut packet[..HEADER_LEN])?;
        EncryptedConnection::update_mac(
            &mut self.egress_mac,
            &self.mac_encoder_key,
            &packet[..HEADER_LEN],
        )?;
        self.egress_mac
            .clone()
            .finalize(&mut packet[HEADER_LEN..32]);
        &mut packet[32..32 + len].copy_from_slice(payload);
        self.encoder.encrypt(&mut packet[32..32 + len])?;
        if padding != 0 {
            self.encoder
                .encrypt(&mut packet[(32 + len)..(32 + len + padding)])?;
        }
        self.egress_mac.update(&packet[32..(32 + len + padding)]);
        EncryptedConnection::update_mac(&mut self.egress_mac, &self.mac_encoder_key, &[0u8; 0])?;
        self.egress_mac
            .clone()
            .finalize(&mut packet[(32 + len + padding)..]);
        self.connection.send(packet).await?;
        Ok(())
    }

    /// Decrypt and authenticate an incoming packet header. Prepare for receiving payload.
    fn read_header(&mut self, mut header: Bytes) -> Result<(), Error> {
        if header.len() != ENCRYPTED_HEADER_LEN {
            return Err(Error::Auth);
        }
        EncryptedConnection::update_mac(
            &mut self.ingress_mac,
            &self.mac_encoder_key,
            &header[0..16],
        )?;
        let mac = &header[16..];
        let mut expected = H256::zero();
        self.ingress_mac.clone().finalize(expected.as_bytes_mut());
        if mac != &expected[0..16] {
            return Err(Error::Auth);
        }
        self.decoder.decrypt(&mut header[..16])?;

        let length = ((((header[0] as u32) << 8) + (header[1] as u32)) << 8) + (header[2] as u32);
        let header_rlp = Rlp::new(&header[3..6]);
        let protocol_id = header_rlp.val_at::<u16>(0)?;

        self.payload_len = length as usize;
        self.protocol_id = protocol_id;
        self.read_state = EncryptedConnectionState::Payload;

        let padding = (16 - (length % 16)) % 16;
        let full_length = length + padding + 16;

        self.connection.expect(full_length as usize);
        Ok(())
    }

    /// Decrypt and authenticate packet payload.
    fn read_payload(&mut self, mut payload: Bytes) -> Result<Packet, Error> {
        let padding = (16 - (self.payload_len % 16)) % 16;
        let full_length = self.payload_len + padding + 16;
        if payload.len() != full_length {
            return Err(Error::Auth);
        }
        self.ingress_mac.update(&payload[0..payload.len() - 16]);
        EncryptedConnection::update_mac(&mut self.ingress_mac, &self.mac_encoder_key, &[0u8; 0])?;

        let mac = &payload[(payload.len() - 16)..];
        let mut expected = H128::default();
        self.ingress_mac.clone().finalize(expected.as_bytes_mut());
        if mac != &expected[..] {
            return Err(Error::Auth);
        }
        self.decoder
            .decrypt(&mut payload[..self.payload_len + padding])?;
        payload.truncate(self.payload_len);
        Ok(Packet {
            protocol: self.protocol_id,
            data: payload,
        })
    }

    /// Update MAC after reading or writing any data.
    fn update_mac(mac: &mut Keccak, mac_encoder_key: &Secret, seed: &[u8]) -> Result<(), Error> {
        let mut prev = H128::default();
        mac.clone().finalize(prev.as_bytes_mut());
        let mut enc = H128::default();
        &mut enc[..].copy_from_slice(prev.as_bytes());
        let mac_encoder = AesEcb256::new(mac_encoder_key.as_bytes())?;
        mac_encoder.encrypt(enc.as_bytes_mut())?;

        enc = enc
            ^ if seed.is_empty() {
                prev
            } else {
                H128::from_slice(seed)
            };
        mac.update(enc.as_bytes());
        Ok(())
    }

    /// Readable IO handler. Tracker receive status and returns decoded packet if available.
    pub async fn readable(
        &mut self,
    ) -> Result<Option<Packet>, Error> {
        // io.clear_timer(self.connection.token)?;
        if let EncryptedConnectionState::Header = self.read_state {
            if let Some(data) = self.connection.readable().await? {
                self.read_header(data)?;
                // io.register_timer(self.connection.token, RECEIVE_PAYLOAD)?;
            }
        };
        if let EncryptedConnectionState::Payload = self.read_state {
            match self.connection.readable().await? {
                Some(data) => {
                    self.read_state = EncryptedConnectionState::Header;
                    self.connection.expect(ENCRYPTED_HEADER_LEN);
                    Ok(Some(self.read_payload(data)?))
                },
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// Writable IO handler. Processes send queue.
    pub async fn writable(&mut self) -> Result<(), Error> {
        self.connection.writable().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cmp;
    use std::collections::VecDeque;
    use std::io::{Cursor, Error, ErrorKind, Read, Result, Write};
    use std::sync::atomic::AtomicBool;

    use mio::Ready;
    use parity_bytes::Bytes;

    use ethcore_io::*;

    use super::*;

    pub struct TestSocket {
        pub read_buffer: Vec<u8>,
        pub write_buffer: Vec<u8>,
        pub cursor: usize,
        pub buf_size: usize,
    }

    impl Default for TestSocket {
        fn default() -> Self {
            TestSocket::new()
        }
    }

    impl TestSocket {
        pub fn new() -> Self {
            TestSocket {
                read_buffer: vec![],
                write_buffer: vec![],
                cursor: 0,
                buf_size: 0,
            }
        }

        pub fn new_buf(buf_size: usize) -> TestSocket {
            TestSocket {
                read_buffer: vec![],
                write_buffer: vec![],
                cursor: 0,
                buf_size,
            }
        }
    }

    impl Read for TestSocket {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
            let end_position = cmp::min(self.read_buffer.len(), self.cursor + buf.len());
            if self.cursor > end_position {
                return Ok(0);
            }
            let len = cmp::max(end_position - self.cursor, 0);
            match len {
                0 => Ok(0),
                _ => {
                    for i in self.cursor..end_position {
                        buf[i - self.cursor] = self.read_buffer[i];
                    }
                    self.cursor = end_position;
                    Ok(len)
                },
            }
        }
    }

    impl Write for TestSocket {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            if self.buf_size == 0 || buf.len() < self.buf_size {
                self.write_buffer.extend(buf.iter().cloned());
                Ok(buf.len())
            } else {
                self.write_buffer
                    .extend(buf.iter().take(self.buf_size).cloned());
                Ok(self.buf_size)
            }
        }

        fn flush(&mut self) -> Result<()> {
            unimplemented!();
        }
    }

    impl GenericSocket for TestSocket {}

    struct TestBrokenSocket {
        error: String,
    }

    impl Read for TestBrokenSocket {
        fn read(&mut self, _: &mut [u8]) -> Result<usize> {
            Err(Error::new(ErrorKind::Other, self.error.clone()))
        }
    }

    impl Write for TestBrokenSocket {
        fn write(&mut self, _: &[u8]) -> Result<usize> {
            Err(Error::new(ErrorKind::Other, self.error.clone()))
        }

        fn flush(&mut self) -> Result<()> {
            unimplemented!();
        }
    }

    impl GenericSocket for TestBrokenSocket {}

    type TestConnection = GenericConnection<TestSocket>;

    impl Default for TestConnection {
        fn default() -> Self {
            TestConnection::new()
        }
    }

    impl TestConnection {
        pub fn new() -> Self {
            TestConnection {
                token: 999998888usize,
                socket: TestSocket::new(),
                send_queue: VecDeque::new(),
                rec_buf: Bytes::new(),
                rec_size: 0,
                interest: Ready::hup() | Ready::readable(),
                registered: AtomicBool::new(false),
            }
        }
    }

    type TestBrokenConnection = GenericConnection<TestBrokenSocket>;

    impl Default for TestBrokenConnection {
        fn default() -> Self {
            TestBrokenConnection::new()
        }
    }

    impl TestBrokenConnection {
        pub fn new() -> Self {
            TestBrokenConnection {
                token: 999998888usize,
                socket: TestBrokenSocket {
                    error: "test broken socket".to_owned(),
                },
                send_queue: VecDeque::new(),
                rec_buf: Bytes::new(),
                rec_size: 0,
                interest: Ready::hup() | Ready::readable(),
                registered: AtomicBool::new(false),
            }
        }
    }

    fn test_io() -> IoContext<i32> {
        IoContext::new(IoChannel::disconnected(), 0)
    }

    #[test]
    pub fn test_encryption() {
        use ethereum_types::{H128, H256};
        use std::str::FromStr;
        let key =
            H256::from_str("2212767d793a7a3d66f869ae324dd11bd17044b82c9f463b8a541a4d089efec5")
                .unwrap();
        let before = H128::from_str("12532abaec065082a3cf1da7d0136f15").unwrap();
        let before2 = H128::from_str("7e99f682356fdfbc6b67a9562787b18a").unwrap();
        let after = H128::from_str("89464c6b04e7c99e555c81d3f7266a05").unwrap();
        let after2 = H128::from_str("85c070030589ef9c7a2879b3a8489316").unwrap();

        let mut got = H128::default();

        let encoder = AesEcb256::new(key.as_bytes()).unwrap();
        got.as_bytes_mut().copy_from_slice(before.as_bytes());
        encoder.encrypt(got.as_bytes_mut()).unwrap();
        assert_eq!(got, after);

        let encoder = AesEcb256::new(key.as_bytes()).unwrap();
        got = H128::default();
        got.as_bytes_mut().copy_from_slice(&before2.as_bytes());
        encoder.encrypt(got.as_bytes_mut()).unwrap();
        assert_eq!(got, after2);
    }

    #[test]
    fn connection_expect() {
        let mut connection = TestConnection::new();
        connection.expect(1024);
        assert_eq!(1024, connection.rec_size);
    }

    #[test]
    fn connection_write_empty() {
        let mut connection = TestConnection::new();
        let status = connection.writable(&test_io());
        assert!(status.is_ok());
        assert!(WriteStatus::Complete == status.unwrap());
    }

    #[test]
    fn connection_write() {
        let mut connection = TestConnection::new();
        let data = Cursor::new(vec![0; 10240]);
        connection.send_queue.push_back(data);

        let status = connection.writable(&test_io());
        assert!(status.is_ok());
        assert!(WriteStatus::Complete == status.unwrap());
        assert_eq!(10240, connection.socket.write_buffer.len());
    }

    #[test]
    fn connection_write_is_buffered() {
        let mut connection = TestConnection::new();
        connection.socket = TestSocket::new_buf(1024);
        let data = Cursor::new(vec![0; 10240]);
        connection.send_queue.push_back(data);

        let status = connection.writable(&test_io());

        assert!(status.is_ok());
        assert!(WriteStatus::Ongoing == status.unwrap());
        assert_eq!(1024, connection.socket.write_buffer.len());
    }

    #[test]
    fn connection_write_to_broken() {
        let mut connection = TestBrokenConnection::new();
        let data = Cursor::new(vec![0; 10240]);
        connection.send_queue.push_back(data);

        let status = connection.writable(&test_io());

        assert!(!status.is_ok());
        assert_eq!(1, connection.send_queue.len());
    }

    #[test]
    fn connection_read() {
        let mut connection = TestConnection::new();
        connection.rec_size = 2048;
        connection.rec_buf = vec![10; 1024];
        connection.socket.read_buffer = vec![99; 2048];

        let status = connection.readable();

        assert!(status.is_ok());
        assert_eq!(1024, connection.socket.cursor);
    }

    #[test]
    fn connection_read_from_broken() {
        let mut connection = TestBrokenConnection::new();
        connection.rec_size = 2048;

        let status = connection.readable();
        assert!(!status.is_ok());
        assert_eq!(0, connection.rec_buf.len());
    }

    #[test]
    fn connection_read_nothing() {
        let mut connection = TestConnection::new();
        connection.rec_size = 2048;

        let status = connection.readable();

        assert!(status.is_ok());
        assert_eq!(0, connection.rec_buf.len());
    }

    #[test]
    fn connection_read_full() {
        let mut connection = TestConnection::new();
        connection.rec_size = 1024;
        connection.rec_buf = vec![76; 1024];

        let status = connection.readable();

        assert!(status.is_ok());
        assert_eq!(0, connection.socket.cursor);
    }
}
