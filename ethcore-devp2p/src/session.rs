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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::{io, str};

use ethereum_types::H256;
use log::{debug, trace, warn};
use mio::deprecated::{EventLoop, Handler};
// use mio::tcp::*;
use mio::*;
use parity_snappy as snappy;
use rlp::{Rlp, RlpStream, EMPTY_LIST_RLP};
use runtime::net::TcpStream;

use ethcore_io::{IoContext, StreamToken};
use network::client_version::ClientVersion;
use network::SessionCapabilityInfo;
use network::{DisconnectReason, Error, PeerCapabilityInfo, ProtocolId, SessionInfo};

use crate::{
    connection::{Connection, ConnectionWriter, ConnectionInfo, EncryptedConnection, Packet, MAX_PAYLOAD_SIZE},
    handshake::Handshake,
    host::HostInfo,
    node_table::NodeId,
};

// Timeout must be less than (interval - 1).
const PING_TIMEOUT: Duration = Duration::from_secs(60);
const PING_INTERVAL: Duration = Duration::from_secs(120);
const MIN_PROTOCOL_VERSION: u32 = 4;
const MIN_COMPRESSION_PROTOCOL_VERSION: u32 = 5;

#[derive(Debug, Clone)]
enum ProtocolState {
    // Packets pending protocol on_connect event return.
    Pending(Vec<(Vec<u8>, u8)>),
    // Protocol connected.
    Connected,
}

/// Peer session over encrypted connection.
/// When created waits for Hello packet exchange and signals ready state.
/// Sends and receives protocol packets and handles basic packets such as ping/pong and disconnect.
pub struct Session {
    /// Shared session information
    pub info: SessionInfo,
    /// Session ready flag. Set after successful Hello packet exchange
    had_hello: bool,
    /// Session is no longer active flag.
    expired: bool,
    ping_time: Instant,
    pong_time: Option<Instant>,
    state: State,
    // Protocol states -- accumulates pending packets until signaled as ready.
    protocol_states: HashMap<ProtocolId, ProtocolState>,
    compression: bool,
}

enum State {
    Unknown,
    Handshake(Handshake),
    Session(EncryptedConnection),
}

/// Structure used to report various session events.
pub enum SessionData {
    None,
    /// Session is ready to send/receive packets.
    Ready,
    /// A packet has been received
    Packet {
        /// Packet data
        data: Vec<u8>,
        /// Packet protocol ID
        protocol: [u8; 3],
        /// Zero based packet ID
        packet_id: u8,
    },
    /// Session has more data to be read
    Continue,
}

const PACKET_HELLO: u8 = 0x80;
const PACKET_DISCONNECT: u8 = 0x01;
const PACKET_PING: u8 = 0x02;
const PACKET_PONG: u8 = 0x03;
const PACKET_GET_PEERS: u8 = 0x04;
const PACKET_PEERS: u8 = 0x05;
const PACKET_USER: u8 = 0x10;
const PACKET_LAST: u8 = 0x7f;

impl Session {
    /// Create a new session out of completed handshake. This clones the handshake connection object
    /// and leaves the handshake in limbo to be de-registered from the event loop.
    pub async fn new(
		conn_writer: ConnectionWriter,
		conn_info: ConnectionInfo,
        token: StreamToken,
        id: Option<&NodeId>,
        nonce: &H256,
        host: &HostInfo,
    ) -> Result<Session, Error> {
        let originated = id.is_some();
        let mut handshake =
            Handshake::new(token, id, conn_writer, conn_info, nonce).expect("Can't create handshake");
        let local_addr = handshake.connection.local_addr_str();
        handshake.start(host, originated).await?;
        Ok(Session {
            state: State::Handshake(handshake),
            had_hello: false,
            info: SessionInfo {
                id: id.cloned(),
                client_version: ClientVersion::from(""),
                protocol_version: 0,
                capabilities: Vec::new(),
                peer_capabilities: Vec::new(),
                ping: None,
                originated,
                remote_address: "Handshake".to_owned(),
                local_address: local_addr,
            },
            ping_time: Instant::now(),
            pong_time: None,
            expired: false,
            protocol_states: HashMap::new(),
            compression: false,
        })
    }

    async fn complete_handshake(&mut self, host: &HostInfo) -> Result<(), Error> {
        let connection =
            if let State::Handshake(h) = std::mem::replace(&mut self.state, State::Unknown) {
                self.info.id = Some(h.id);
                self.info.remote_address = h.connection.remote_addr_str();
                EncryptedConnection::new(h)?
            } else {
                panic!("Unexpected state");
            };
        self.state = State::Session(connection);
        self.write_hello(host).await?;
        Ok(())
    }

    fn connection(&self) -> &Connection {
        match self.state {
            State::Handshake(ref h) => &h.connection,
            State::Session(ref s) => &s.connection,
            _ => panic!("Unknown state"),
        }
    }

    /// Get id of the remote peer
    pub fn id(&self) -> Option<&NodeId> {
        self.info.id.as_ref()
    }

    /// Check if session is ready to send/receive data
    pub fn is_ready(&self) -> bool {
        self.had_hello
    }

    /// Mark this session as inactive to be deleted lated.
    pub fn set_expired(&mut self) {
        self.expired = true;
    }

    /// Check if this session is expired.
    pub fn expired(&self) -> bool {
        self.expired
    }

    /// Check if this session is over and there is nothing to be sent.
    pub fn done(&self) -> bool {
        self.expired() && !self.connection().is_sending()
    }

    /// Get remote peer address
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.connection().remote_addr()
    }

    /// Readable IO handler. Returns packet data if available.
    pub async fn readable(
        &mut self,
        host: &HostInfo,
    ) -> Result<SessionData, Error> {
        if self.expired() {
            return Ok(SessionData::None);
        }
        let mut create_session = false;
        let mut packet_data = None;
        match self.state {
            State::Handshake(ref mut h) => {
                h.readable(host).await?;
                if h.done() {
                    create_session = true;
                }
            },
            State::Session(ref mut c) => match c.readable().await? {
                data @ Some(_) => packet_data = data,
                None => return Ok(SessionData::None),
            },
            State::Unknown => panic!("Unknown state!"),
        }
        if let Some(data) = packet_data {
            return Ok(self.read_packet(&data, host).await?);
        }
        if create_session {
            self.complete_handshake(host).await?;
			// @todo
            // io.update_registration(self.token())
            //     .unwrap_or_else(|e| debug!(target: "network", "Token registration error: {:?}", e));
        }
        Ok(SessionData::None)
    }

    /// Writable IO handler. Sends pending packets.
    pub async fn writable(&mut self, _host: &HostInfo) -> Result<(), Error> {
        match self.state {
            State::Handshake(ref mut h) => h.writable().await,
            State::Session(ref mut c) => c.writable().await,
            State::Unknown => panic!("Unknown state!"),
        }
    }

    /// Checks if peer supports given capability
    pub fn have_capability(&self, protocol: [u8; 3]) -> bool {
        self.info
            .capabilities
            .iter()
            .any(|c| c.protocol == protocol)
    }

    /// Checks if peer supports given capability
    pub fn capability_version(&self, protocol: [u8; 3]) -> Option<u8> {
        self.info
            .capabilities
            .iter()
            .filter_map(|c| {
                if c.protocol == protocol {
                    Some(c.version)
                } else {
                    None
                }
            })
            .max()
    }

    /// Register the session socket with the event loop
    pub fn register_socket(
        &self,
        reg: Token,
    ) -> Result<(), Error> {
        if self.expired() {
            return Ok(());
        }
        self.connection().register_socket(reg)?;
        Ok(())
    }

    /// Update registration with the event loop. Should be called at the end of the IO handler.
    pub fn update_socket(
        &self,
        reg: Token,
    ) -> Result<(), Error> {
        self.connection().update_socket(reg)?;
        Ok(())
    }

    /// Delete registration
    pub fn deregister_socket(
        &self,
    ) -> Result<(), Error> {
        self.connection().deregister_socket()?;
        Ok(())
    }

    /// Send a protocol packet to peer.
    pub async fn send_packet(
        &mut self,
        protocol: Option<[u8; 3]>,
        packet_id: u8,
        data: &[u8],
    ) -> Result<(), Error> {
        if protocol.is_some() && (self.info.capabilities.is_empty() || !self.had_hello) {
            debug!(target: "network", "Sending to unconfirmed session {}, protocol: {:?}, packet: {}", self.token(), protocol.as_ref().map(|p| str::from_utf8(&p[..]).unwrap_or("??")), packet_id);
            return Err(Error::BadProtocol);
        }
        if self.expired() {
            return Err(Error::Expired);
        }
        let mut i = 0usize;
        let pid = match protocol {
            Some(protocol) => {
                while protocol != self.info.capabilities[i].protocol {
                    i += 1;
                    if i == self.info.capabilities.len() {
                        debug!(target: "network", "Unknown protocol: {:?}", protocol);
                        return Ok(());
                    }
                }
                self.info.capabilities[i].id_offset + packet_id
            },
            None => packet_id,
        };
        let mut rlp = RlpStream::new();
        rlp.append(&(u32::from(pid)));
        let mut compressed = Vec::new();
        let mut payload = data; // create a reference with local lifetime
        if self.compression {
            if payload.len() > MAX_PAYLOAD_SIZE {
                return Err(Error::OversizedPacket);
            }
            let len = snappy::compress_into(&payload, &mut compressed);
            trace!(target: "network", "compressed {} to {}", payload.len(), len);
            payload = &compressed[0..len];
        }
        rlp.append_raw(payload, 1);
        let data = rlp.drain();
        self.send(&data).await
    }

    /// Keep this session alive. Returns false if ping timeout happened
    pub async fn keep_alive(&mut self) -> bool {
        if let State::Handshake(_) = self.state {
            return true;
        }
        let timed_out = if let Some(pong) = self.pong_time {
            pong.duration_since(self.ping_time) > PING_TIMEOUT
        } else {
            self.ping_time.elapsed() > PING_TIMEOUT
        };

        if !timed_out && self.ping_time.elapsed() > PING_INTERVAL {
            if let Err(e) = self.send_ping().await {
                debug!("Error sending ping message: {:?}", e);
            }
        }
        !timed_out
    }

    pub fn token(&self) -> StreamToken {
        self.connection().token()
    }

    /// Signal that a subprotocol has handled the connection successfully and
    /// get all pending packets in order received.
    pub fn mark_connected(&mut self, protocol: ProtocolId) -> Vec<(ProtocolId, u8, Vec<u8>)> {
        match self
            .protocol_states
            .insert(protocol, ProtocolState::Connected)
        {
            None => Vec::new(),
            Some(ProtocolState::Connected) => {
                debug!(target: "network", "Protocol {:?} marked as connected more than once", protocol);
                Vec::new()
            },
            Some(ProtocolState::Pending(pending)) => pending
                .into_iter()
                .map(|(data, id)| (protocol, id, data))
                .collect(),
        }
    }

    async fn read_packet(
        &mut self,
        packet: &Packet,
        host: &HostInfo,
    ) -> Result<SessionData, Error> {
        if packet.data.len() < 2 {
            return Err(Error::BadProtocol);
        }
        let packet_id = packet.data[0];
        if packet_id != PACKET_HELLO && packet_id != PACKET_DISCONNECT && !self.had_hello {
            return Err(Error::BadProtocol);
        }
        let data = if self.compression {
            let compressed = &packet.data[1..];
            if snappy::decompressed_len(&compressed)? > MAX_PAYLOAD_SIZE {
                return Err(Error::OversizedPacket);
            }
            snappy::decompress(&compressed)?
        } else {
            packet.data[1..].to_owned()
        };
        match packet_id {
            PACKET_HELLO => {
                self.read_hello(&data, host).await?;
                Ok(SessionData::Ready)
            },
            PACKET_DISCONNECT => {
                let rlp = Rlp::new(&data);
                let reason: u8 = rlp.val_at(0)?;
                if self.had_hello {
                    debug!(target:"network", "Disconnected: {}: {:?}", self.token(), DisconnectReason::from_u8(reason));
                }
                Err(Error::Disconnect(DisconnectReason::from_u8(reason)))
            },
            PACKET_PING => {
                self.send_pong().await?;
                Ok(SessionData::Continue)
            },
            PACKET_PONG => {
                let time = Instant::now();
                self.pong_time = Some(time);
                self.info.ping = Some(time.duration_since(self.ping_time));
                Ok(SessionData::Continue)
            },
            PACKET_GET_PEERS => Ok(SessionData::None), //TODO;
            PACKET_PEERS => Ok(SessionData::None),
            PACKET_USER..=PACKET_LAST => {
                let mut i = 0usize;
                while packet_id
                    >= self.info.capabilities[i].id_offset + self.info.capabilities[i].packet_count
                {
                    i += 1;
                    if i == self.info.capabilities.len() {
                        debug!(target: "network", "Unknown packet: {:?}", packet_id);
                        return Ok(SessionData::Continue);
                    }
                }

                // map to protocol
                let protocol = self.info.capabilities[i].protocol;
                let protocol_packet_id = packet_id - self.info.capabilities[i].id_offset;

                match *self
                    .protocol_states
                    .entry(protocol)
                    .or_insert_with(|| ProtocolState::Pending(Vec::new()))
                {
                    ProtocolState::Connected => {
                        trace!(target: "network", "Packet {} mapped to {:?}:{}, i={}, capabilities={:?}", packet_id, protocol, protocol_packet_id, i, self.info.capabilities);
                        Ok(SessionData::Packet {
                            data,
                            protocol,
                            packet_id: protocol_packet_id,
                        })
                    },
                    ProtocolState::Pending(ref mut pending) => {
                        trace!(target: "network", "Packet {} deferred until protocol connection event completion", packet_id);
                        pending.push((data, protocol_packet_id));

                        Ok(SessionData::Continue)
                    },
                }
            },
            _ => {
                debug!(target: "network", "Unknown packet: {:?}", packet_id);
                Ok(SessionData::Continue)
            },
        }
    }

    async fn write_hello(&mut self, host: &HostInfo) -> Result<(), Error> {
        let mut rlp = RlpStream::new();
        rlp.append_raw(&[PACKET_HELLO as u8], 0);
        rlp.begin_list(5)
            .append(&host.protocol_version)
            .append(&host.client_version())
            .append_list(&host.capabilities)
            .append(&host.local_endpoint.address.port())
            .append(host.id());
        let data = rlp.drain();
        self.send(&data).await
    }

    async fn read_hello(&mut self, data: &[u8], host: &HostInfo) -> Result<(), Error> {
		let (protocol, client_version, peer_caps, id) = {
			let rlp = Rlp::new(data); //TODO: validate rlp expected size
			let protocol = rlp.val_at::<u32>(0)?;
			let client_version_string = rlp.val_at::<String>(1)?;
			let client_version = ClientVersion::from(client_version_string);
			let peer_caps: Vec<PeerCapabilityInfo> = rlp.list_at(2)?;
			let id = rlp.val_at::<NodeId>(4)?;
			(protocol, client_version, peer_caps, id)
		};

        // Intersect with host capabilities
        // Leave only highset mutually supported capability version
        let mut caps: Vec<SessionCapabilityInfo> = Vec::new();
        for hc in &host.capabilities {
            if peer_caps
                .iter()
                .any(|c| c.protocol == hc.protocol && c.version == hc.version)
            {
                caps.push(SessionCapabilityInfo {
                    protocol: hc.protocol,
                    version: hc.version,
                    id_offset: 0,
                    packet_count: hc.packet_count,
                });
            }
        }

        caps.retain(|c| {
            host.capabilities
                .iter()
                .any(|hc| hc.protocol == c.protocol && hc.version == c.version)
        });
        let mut i = 0;
        while i < caps.len() {
            if caps
                .iter()
                .any(|c| c.protocol == caps[i].protocol && c.version > caps[i].version)
            {
                caps.remove(i);
            } else {
                i += 1;
            }
        }

        // Sort capabilities alphabetically.
        caps.sort();

        i = 0;
        let mut offset: u8 = PACKET_USER;
        while i < caps.len() {
            caps[i].id_offset = offset;
            offset += caps[i].packet_count;
            i += 1;
        }
        debug!(target: "network", "Hello: {} v{} {} {:?}", client_version, protocol, id, caps);
        let protocol = ::std::cmp::min(protocol, host.protocol_version);
        self.info.protocol_version = protocol;
        self.info.client_version = client_version;
        self.info.capabilities = caps;
        self.info.peer_capabilities = peer_caps;
        if self.info.capabilities.is_empty() {
            trace!(target: "network", "No common capabilities with peer.");
            return Err(self.disconnect(DisconnectReason::UselessPeer).await);
        }
        if protocol < MIN_PROTOCOL_VERSION {
            trace!(target: "network", "Peer protocol version mismatch: {}", protocol);
            return Err(self.disconnect(DisconnectReason::UselessPeer).await);
        }
        self.compression = protocol >= MIN_COMPRESSION_PROTOCOL_VERSION;
        self.send_ping().await?;
        self.had_hello = true;
        Ok(())
    }

    /// Send ping packet
    pub async fn send_ping(&mut self) -> Result<(), Error> {
        self.send_packet(None, PACKET_PING, &EMPTY_LIST_RLP).await?;
        self.ping_time = Instant::now();
        self.pong_time = None;
        Ok(())
    }

    async fn send_pong(&mut self) -> Result<(), Error> {
        self.send_packet(None, PACKET_PONG, &EMPTY_LIST_RLP).await
    }

    /// Disconnect this session
    pub async fn disconnect(&mut self, reason: DisconnectReason) -> Error {
        if let State::Session(_) = self.state {
            let mut rlp = RlpStream::new();
            rlp.begin_list(1);
            rlp.append(&(reason as u32));
            let data = rlp.drain();
            self.send_packet(None, PACKET_DISCONNECT, &data).await.ok();
        }
        Error::Disconnect(reason)
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.state {
            State::Handshake(_) => {
                warn!(target:"network", "Unexpected send request");
            },
            State::Session(ref mut s) => s.send_packet(data).await?,
            State::Unknown => panic!("Unknown state!"),
        }
        Ok(())
    }
}
