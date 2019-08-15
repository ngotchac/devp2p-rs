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

use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::*;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ethereum_types::H256;
use futures::prelude::*;
use futures::lock::Mutex;
use keccak_hash::keccak;
use log::{debug, info, trace, warn};
use mio::udp::UdpSocket;
use parity_path::restrict_permissions_owner;
use parking_lot::RwLock;
use rlp::{Encodable, RlpStream};
use runtime::net::{TcpListener, TcpStream};
// use ethcore_io::{IoContext, IoHandler, IoManager, StreamToken, TimerToken};
use ethcore_io::{IoContext, IoHandler, StreamToken, TimerToken};
use ethkey::{Generator, KeyPair, Random, Secret};
use network::{
    ConnectionDirection, ConnectionFilter, DisconnectReason, Error, NetworkConfiguration,
    NetworkContext as NetworkContextTrait, NetworkIoMessage, NetworkProtocolHandler,
    NonReservedPeerMode, PacketId, PeerId, ProtocolId,
};

use crate::network_context::{NetworkContext, SharedSession, Slab};
use crate::connection::ConnectionInfo;
use crate::{
    discovery::{Discovery, NodeEntry, TableUpdates, MAX_DATAGRAM_SIZE},
    ip_utils::{map_external_address, select_public_address},
    node_table::*,
    session::{Session, SessionData},
    PROTOCOL_VERSION,
};

const MAX_SESSIONS: usize = 2048 + MAX_HANDSHAKES;
const MAX_HANDSHAKES: usize = 1024;

const DEFAULT_PORT: u16 = 30303;

// StreamToken/TimerToken
const TCP_ACCEPT: StreamToken = SYS_TIMER + 1;
const IDLE: TimerToken = SYS_TIMER + 2;
const DISCOVERY: StreamToken = SYS_TIMER + 3;
const DISCOVERY_REFRESH: TimerToken = SYS_TIMER + 4;
const FAST_DISCOVERY_REFRESH: TimerToken = SYS_TIMER + 5;
const DISCOVERY_ROUND: TimerToken = SYS_TIMER + 6;
const NODE_TABLE: TimerToken = SYS_TIMER + 7;
const FIRST_SESSION: StreamToken = 0;
const LAST_SESSION: StreamToken = FIRST_SESSION + MAX_SESSIONS - 1;
const USER_TIMER: TimerToken = LAST_SESSION + 256;
const SYS_TIMER: TimerToken = LAST_SESSION + 1;

// Timeouts
// for IDLE TimerToken
const MAINTENANCE_TIMEOUT: Duration = Duration::from_secs(1);
// for DISCOVERY_REFRESH TimerToken
const DISCOVERY_REFRESH_TIMEOUT: Duration = Duration::from_secs(60);
// for FAST_DISCOVERY_REFRESH TimerToken
const FAST_DISCOVERY_REFRESH_TIMEOUT: Duration = Duration::from_secs(10);
// for DISCOVERY_ROUND TimerToken
const DISCOVERY_ROUND_TIMEOUT: Duration = Duration::from_millis(300);
// for NODE_TABLE TimerToken
const NODE_TABLE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, PartialEq, Eq)]
/// Protocol info
pub struct CapabilityInfo {
    /// Protocol ID
    pub protocol: ProtocolId,
    /// Protocol version
    pub version: u8,
    /// Total number of packet IDs this protocol support.
    pub packet_count: u8,
}

impl Encodable for CapabilityInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&&self.protocol[..]);
        s.append(&self.version);
    }
}

/// Shared host information
#[derive(Clone)]
pub struct HostInfo {
    /// Our private and public keys.
    keys: KeyPair,
    /// Current network configuration
    config: NetworkConfiguration,
    /// Connection nonce.
    nonce: H256,
    /// RLPx protocol version
    pub protocol_version: u32,
    /// Registered capabilities (handlers)
    pub capabilities: Vec<CapabilityInfo>,
    /// Local address + discovery port
    pub local_endpoint: NodeEndpoint,
    /// Public address + discovery port
    pub public_endpoint: Option<NodeEndpoint>,
}

impl HostInfo {
    fn next_nonce(&mut self) -> H256 {
        self.nonce = keccak(&self.nonce);
        self.nonce
    }

    pub(crate) fn client_version(&self) -> &str {
        &self.config.client_version
    }

    pub(crate) fn secret(&self) -> &Secret {
        self.keys.secret()
    }

    pub(crate) fn id(&self) -> &NodeId {
        self.keys.public()
    }
}

#[derive(Copy, Clone)]
struct ProtocolTimer {
    pub protocol: ProtocolId,
    pub token: TimerToken, // Handler level token
}

/// Root IO handler. Manages protocol handlers, IO timers and network connections.
pub struct Host {
    pub info: Mutex<HostInfo>,
    udp_socket: Mutex<Option<UdpSocket>>,
    // tcp_listener: Mutex<TcpListener>,
    sessions: Arc<Mutex<Slab<SharedSession>>>,
    discovery: Mutex<Option<Discovery<'static>>>,
    nodes: Mutex<NodeTable>,
    handlers: Mutex<HashMap<ProtocolId, Arc<dyn NetworkProtocolHandler + Sync>>>,
    timers: Mutex<HashMap<TimerToken, ProtocolTimer>>,
    timer_counter: Mutex<usize>,
    reserved_nodes: Mutex<HashSet<NodeId>>,
    stopping: AtomicBool,
    filter: Option<Arc<dyn ConnectionFilter>>,
}

impl Host {
    /// Create a new instance
    pub async fn new(
        mut config: NetworkConfiguration,
        filter: Option<Arc<dyn ConnectionFilter>>,
    ) -> Result<Arc<Mutex<Host>>, Error> {
        let mut listen_address = match config.listen_address {
            None => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), DEFAULT_PORT)),
            Some(addr) => addr,
        };

        let keys = if let Some(ref secret) = config.use_secret {
            KeyPair::from_secret(secret.clone())?
        } else {
            config
                .config_path
                .clone()
                .and_then(|ref p| load_key(Path::new(&p)))
                .map_or_else(
                    || {
                        let key = Random.generate().expect("Error generating random key pair");
                        if let Some(path) = config.config_path.clone() {
                            save_key(Path::new(&path), key.secret());
                        }
                        key
                    },
                    |s| KeyPair::from_secret(s).expect("Error creating node secret key"),
                )
        };
        let path = config.net_config_path.clone();
        // Setup the server socket
        let mut tcp_listener = TcpListener::bind(&listen_address)?;
        listen_address = SocketAddr::new(listen_address.ip(), tcp_listener.local_addr()?.port());
        debug!(target: "network", "Listening at {:?}", listen_address);
        let udp_port = config.udp_port.unwrap_or_else(|| listen_address.port());
        let local_endpoint = NodeEndpoint {
            address: listen_address,
            udp_port,
        };

        let boot_nodes = config.boot_nodes.clone();
        let reserved_nodes = config.reserved_nodes.clone();
        config.max_handshakes = min(config.max_handshakes, MAX_HANDSHAKES as u32);

        let mut host = Host {
            info: Mutex::new(HostInfo {
                keys,
                config,
                nonce: H256::random(),
                protocol_version: PROTOCOL_VERSION,
                capabilities: Vec::new(),
                public_endpoint: None,
                local_endpoint,
            }),
            discovery: Mutex::new(None),
            udp_socket: Mutex::new(None),
            sessions: Arc::new(Mutex::new(Slab::new_starting_at(
                FIRST_SESSION,
                MAX_SESSIONS,
            ))),
            nodes: Mutex::new(NodeTable::new(path)),
            handlers: Mutex::new(HashMap::new()),
            timers: Mutex::new(HashMap::new()),
            timer_counter: Mutex::new(USER_TIMER),
            reserved_nodes: Mutex::new(HashSet::new()),
            stopping: AtomicBool::new(false),
            filter,
        };

        for n in boot_nodes {
            host.add_node(&n).await;
        }

        for n in reserved_nodes {
            if let Err(e) = host.add_reserved_node(&n).await {
                debug!(target: "network", "Error parsing node id: {}: {:?}", n, e);
            }
        }

		let host = Arc::new(Mutex::new(host));
		let host_2 = host.clone();

		runtime::spawn(async move {
			let mut incoming = tcp_listener.incoming();
    		while let Some(stream) = incoming.next().await {
				let stream = stream?;
				info!("Accepting from: {}", stream.peer_addr()?);

				let host = host_2.lock().await;
				if let Err(e) = host.create_connection(stream, None).await {
					debug!(target: "network", "Can't create connection: {:?}", e);
				}
			}
			Ok::<(), std::io::Error>(())
		});

        Ok(host)
    }

    pub async fn add_node(&mut self, id: &str) {
        match Node::from_str(id) {
            Err(e) => {
                debug!(target: "network", "Could not add node {}: {:?}", id, e);
            },
            Ok(n) => {
                let entry = NodeEntry {
                    endpoint: n.endpoint.clone(),
                    id: n.id,
                };

                self.nodes.lock().await.add_node(n);
                if let Some(ref mut discovery) = *self.discovery.lock().await {
                    discovery.add_node(entry);
                }
            },
        }
    }

    pub async fn add_reserved_node(&self, id: &str) -> Result<(), Error> {
        let n = Node::from_str(id)?;

        let entry = NodeEntry {
            endpoint: n.endpoint.clone(),
            id: n.id,
        };
        self.reserved_nodes.lock().await.insert(n.id);
        self.nodes
            .lock()
			.await
            .add_node(Node::new(entry.id, entry.endpoint.clone()));

        if let Some(ref mut discovery) = *self.discovery.lock().await {
            discovery.add_node(entry);
        }

		self.maintain_network().await;

        Ok(())
    }

    pub async fn set_non_reserved_mode(&self, mode: NonReservedPeerMode) {
        let mut info = self.info.lock().await;

        if info.config.non_reserved_mode != mode {
            info.config.non_reserved_mode = mode;
            drop(info);
            if let NonReservedPeerMode::Deny = mode {
                // disconnect all non-reserved peers here.
                let reserved: HashSet<NodeId> = self.reserved_nodes.lock().await.clone();
                let mut to_kill = Vec::new();
                for e in self.sessions.lock().await.iter() {
                    let mut s = e.lock().await;
                    {
                        let id = s.id();
                        if id.map_or(false, |id| reserved.contains(id)) {
                            continue;
                        }
                    }

                    s.disconnect(DisconnectReason::ClientQuit).await;
                    to_kill.push(s.token());
                }
                for p in to_kill {
                    trace!(target: "network", "Disconnecting on reserved-only mode: {}", p);
                    self.kill_connection(p, false).await;
                }
            }
        }
    }

    pub async fn remove_reserved_node(&self, id: &str) -> Result<(), Error> {
        let n = Node::from_str(id)?;
        self.reserved_nodes.lock().await.remove(&n.id);

        Ok(())
    }

    pub async fn external_url(&self) -> Option<String> {
        let info = self.info.lock().await;
        info.public_endpoint
            .as_ref()
            .map(|e| format!("{}", Node::new(*info.id(), e.clone())))
    }

    pub async fn local_url(&self) -> String {
        let info = self.info.lock().await;
        format!("{}", Node::new(*info.id(), info.local_endpoint.clone()))
    }

    pub async fn stop(&self) {
        self.stopping.store(true, AtomicOrdering::Release);
        let mut to_kill = Vec::new();
        for e in self.sessions.lock().await.iter() {
            let mut s = e.lock().await;
            s.disconnect(DisconnectReason::ClientQuit).await;
            to_kill.push(s.token());
        }
        for p in to_kill {
            trace!(target: "network", "Disconnecting on shutdown: {}", p);
            self.kill_connection(p, true).await;
        }
        // io.unregister_handler();
    }

    /// Get all connected peers.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        let sessions = self.sessions.lock().await;
        let sessions = &*sessions;

        let mut peers = Vec::with_capacity(sessions.count());
        for i in (0..MAX_SESSIONS).map(|x| x + FIRST_SESSION) {
            if sessions.get(i).is_some() {
                peers.push(i);
            }
        }
        peers
    }

    async fn init_public_interface(&self, io: &IoContext<NetworkIoMessage>) -> Result<(), Error> {
        if self.info.lock().await.public_endpoint.is_some() {
            return Ok(());
        }
        let local_endpoint = self.info.lock().await.local_endpoint.clone();
        let public_address = self.info.lock().await.config.public_address;
        let allow_ips = self.info.lock().await.config.ip_filter.clone();
        let public_endpoint = match public_address {
            None => {
                let public_address = select_public_address(local_endpoint.address.port());
                let public_endpoint = NodeEndpoint {
                    address: public_address,
                    udp_port: local_endpoint.udp_port,
                };
                if self.info.lock().await.config.nat_enabled {
                    match map_external_address(&local_endpoint) {
                        Some(endpoint) => {
                            info!("NAT mapped to external address {}", endpoint.address);
                            endpoint
                        },
                        None => public_endpoint,
                    }
                } else {
                    public_endpoint
                }
            },
            Some(addr) => NodeEndpoint {
                address: addr,
                udp_port: local_endpoint.udp_port,
            },
        };

        self.info.lock().await.public_endpoint = Some(public_endpoint.clone());

        if let Some(url) = self.external_url().await {
            io.message(NetworkIoMessage::NetworkStarted(url))
                .unwrap_or_else(|e| warn!("Error sending IO notification: {:?}", e));
        }

        // Initialize discovery.
        let discovery = {
            let info = self.info.lock().await;
            if info.config.discovery_enabled
                && info.config.non_reserved_mode == NonReservedPeerMode::Accept
            {
                Some(Discovery::new(&info.keys, public_endpoint, allow_ips))
            } else {
                None
            }
        };

        if let Some(mut discovery) = discovery {
            let mut udp_addr = local_endpoint.address;
            udp_addr.set_port(local_endpoint.udp_port);
            let socket = UdpSocket::bind(&udp_addr).expect("Error binding UDP socket");
            *self.udp_socket.lock().await = Some(socket);

            discovery.add_node_list(self.nodes.lock().await.entries());
            *self.discovery.lock().await = Some(discovery);
            io.register_stream(DISCOVERY)?;
            io.register_timer(FAST_DISCOVERY_REFRESH, FAST_DISCOVERY_REFRESH_TIMEOUT)?;
            io.register_timer(DISCOVERY_REFRESH, DISCOVERY_REFRESH_TIMEOUT)?;
            io.register_timer(DISCOVERY_ROUND, DISCOVERY_ROUND_TIMEOUT)?;
        }
        io.register_timer(NODE_TABLE, NODE_TABLE_TIMEOUT)?;
        io.register_stream(TCP_ACCEPT)?;
        Ok(())
    }

    async fn maintain_network(&self) {
        self.keep_alive().await;
        self.connect_peers().await;
    }

    async fn have_session(&self, id: &NodeId) -> bool {
        for e in self.sessions.lock().await.iter() {
            if e.lock().await.info.id == Some(*id) {
                return true;
            }
        }
        false
    }

    // returns (handshakes, egress, ingress)
    async fn session_count(&self) -> (usize, usize, usize) {
        let mut handshakes = 0;
        let mut egress = 0;
        let mut ingress = 0;
        for s in self.sessions.lock().await.iter() {
            match s.try_lock() {
                Some(ref s) if s.is_ready() && s.info.originated => egress += 1,
                Some(ref s) if s.is_ready() && !s.info.originated => ingress += 1,
                _ => handshakes += 1,
            }
        }
        (handshakes, egress, ingress)
    }

    async fn connecting_to(&self, id: &NodeId) -> bool {
        for e in self.sessions.lock().await.iter() {
            if e.lock().await.id() == Some(id) {
                return true;
            }
        }
        false
    }

    async fn keep_alive(&self) {
        let mut to_kill = Vec::new();
		let sessions = {
			self.sessions.lock().await
		};
        for e in sessions.iter() {
			let should_keep_alive = {
            	let mut s = e.lock().await;
				s.keep_alive().await
			};
            if !should_keep_alive {
            	let mut s = e.lock().await;
                s.disconnect(DisconnectReason::PingTimeout).await;
                to_kill.push(s.token());
            }
        }
        for p in to_kill {
            trace!(target: "network", "Ping timeout: {}", p);
            self.kill_connection(p, true).await;
        }
    }

    async fn has_enough_peers(&self) -> bool {
        let min_peers = {
            let info = self.info.lock().await;
            let config = &info.config;

            config.min_peers
        };
        let (_, egress_count, ingress_count) = self.session_count().await;

        return egress_count + ingress_count >= min_peers as usize;
    }

    async fn connect_peers(&self) {
        let (min_peers, mut pin, max_handshakes, allow_ips, self_id) = {
            let info = self.info.lock().await;
            if info.capabilities.is_empty() {
                return;
            }
            let config = &info.config;

            (
                config.min_peers,
                config.non_reserved_mode == NonReservedPeerMode::Deny,
                config.max_handshakes as usize,
                config.ip_filter.clone(),
                *info.id(),
            )
        };

        let (handshake_count, egress_count, ingress_count) = self.session_count().await;
        let reserved_nodes = self.reserved_nodes.lock().await;
        if egress_count + ingress_count >= min_peers as usize + reserved_nodes.len() {
            // check if all pinned nodes are connected.
            let mut all_connected = true;
            for n in reserved_nodes.iter() {
                let n_connected = self.have_session(n).await && self.connecting_to(n).await;
                all_connected = all_connected && n_connected;
            }
            if all_connected {
                return;
            }

            // if not, only attempt connect to reserved peers
            pin = true;
        }

        // allow 16 slots for incoming connections
        if handshake_count >= max_handshakes {
            return;
        }

        // iterate over all nodes, reserved ones coming first.
        // if we are pinned to only reserved nodes, ignore all others.
        let nodes = reserved_nodes.iter().cloned().chain(if !pin {
            self.nodes.lock().await.nodes(&allow_ips)
        } else {
            Vec::new()
        });

        let max_handshakes_per_round = max_handshakes / 2;
        let mut started: usize = 0;

        let mut nodes_idx = 0;
        let max_nodes_idx = min(max_handshakes_per_round, max_handshakes - handshake_count);
        for id in nodes {
            let should_try = !self.have_session(&id).await
                && !self.connecting_to(&id).await
                && id != self_id
                && self.filter.as_ref().map_or(true, |f| {
                    f.connection_allowed(&self_id, &id, ConnectionDirection::Outbound)
                });
            if !should_try {
                continue;
            }
            nodes_idx += 1;
            if nodes_idx > max_nodes_idx {
                break;
            }
            self.connect_peer(&id).await;
            started += 1;
        }
        debug!(target: "network", "Connecting peers: {} sessions, {} pending + {} started", egress_count + ingress_count, handshake_count, started);
    }

    async fn connect_peer(&self, id: &NodeId) {
        if self.have_session(id).await {
            trace!(target: "network", "Aborted connect. Node already connected.");
            return;
        }
        if self.connecting_to(id).await {
            trace!(target: "network", "Aborted connect. Node already connecting.");
            return;
        }

        let socket = {
            let address = {
                let nodes = self.nodes.lock().await;
                if let Some(node) = nodes.get(id) {
                    node.endpoint.address
                } else {
                    debug!(target: "network", "Connection to expired node aborted");
                    return;
                }
            };
            match TcpStream::connect(&address).await {
                Ok(socket) => {
                    trace!(target: "network", "{}: Connecting to {:?}", id, address);
                    socket
                },
                Err(e) => {
                    debug!(target: "network", "{}: Can't connect to address {:?}: {:?}", id, address, e);
                    self.nodes.lock().await.note_failure(&id);
                    return;
                },
            }
        };

        if let Err(e) = self.create_connection(socket, Some(id)).await {
            debug!(target: "network", "Can't create connection: {:?}", e);
        }
    }

    async fn create_connection(
        &self,
        stream: TcpStream,
        id: Option<&NodeId>,
    ) -> Result<(), Error> {
        let nonce = self.info.lock().await.next_nonce();
        let mut sessions = self.sessions.lock().await;

        let vacant_session = sessions.vacant_entry();
        let token = if let Some(vacant_session) = vacant_session {
            let token = vacant_session.index();
            trace!(target: "network", "{}: Initiating session {:?}", token, id);
            let info = {
				(*self.info.lock().await).clone()
			};
			let conn_info: ConnectionInfo = (&stream).into();
			let (mut conn_reader, conn_writer) = stream.split();
            match Session::new(conn_writer, conn_info, token, id, &nonce, &info).await {
                Ok(s) => {
                    let new_session = Arc::new(Mutex::new(s));
					let new_session_2 = new_session.clone();
                    vacant_session.insert(new_session);

					let host = Arc::new(Mutex::new(&self));

					runtime::spawn(async move {
						loop {
							let mut buf = vec![0u8; 1024];
							let bytes_len = conn_reader.read(&mut buf).await?;
							let data = Bytes::from(&buf[0..bytes_len]);
							debug!("Read {} bytes", data.len());

							let host = host.lock().await;
							host.session_readable(token).await;
						}
						Ok::<(), std::io::Error>(())
					});

                    Some(token)
                },
                Err(e) => {
                    debug!(target: "network", "Session create error: {:?}", e);
                    None
                },
            }
        } else {
            None
        };

		Ok(())

        // match token {
        //     Some(t) => io.register_stream(t).map(|_| ()).map_err(Into::into),
        //     None => {
        //         debug!(target: "network", "Max sessions reached");
        //         Ok(())
        //     },
        // }
    }

    // async fn accept(&self, io: &IoContext<NetworkIoMessage>) {
    //     trace!(target: "network", "Accepting incoming connection");
    //     loop {
    //         let mut listener = self.tcp_listener.lock().await;
    //         let socket = match listener.accept().await {
    //             Ok((sock, _addr)) => sock,
    //             Err(e) => {
    //                 if e.kind() != io::ErrorKind::WouldBlock {
    //                     debug!(target: "network", "Error accepting connection: {:?}", e);
    //                 }
    //                 break;
    //             },
    //         };
    //         if let Err(e) = self.create_connection(socket, None, io).await {
    //             debug!(target: "network", "Can't accept connection: {:?}", e);
    //         }
    //     }
    // }

    async fn session_writable(&self, token: StreamToken) {
        let session = { self.sessions.lock().await.get(token).cloned() };

        if let Some(session) = session {
            let mut s = session.lock().await;
            let info = self.info.lock().await;
            if let Err(e) = s.writable(&info).await {
                trace!(target: "network", "Session write error: {}: {:?}", token, e);
            }
			// @todo
            // if s.done() {
            //     io.deregister_stream(token)
            //         .unwrap_or_else(|e| debug!("Error deregistering stream: {:?}", e));
            // }
        }
    }

    async fn connection_closed(&self, token: StreamToken) {
        trace!(target: "network", "Connection closed: {}", token);
        self.kill_connection(token, true).await;
    }

    async fn session_readable(&self, token: StreamToken) {
        let mut ready_data: Vec<ProtocolId> = Vec::new();
        let mut packet_data: Vec<(ProtocolId, PacketId, Vec<u8>)> = Vec::new();
        let mut kill = false;
        let session = { self.sessions.lock().await.get(token).cloned() };
        let mut ready_id = None;
        if let Some(session) = session.clone() {
            {
                loop {
                    let session_result = {
                        let mut s = session.lock().await;
                        let info = self.info.lock().await;
                        s.readable(&info).await
                    };
					// let session_result = Ok(SessionData::None);
                    match session_result {
                        Err(e) => {
                            let s = session.lock().await;
                            trace!(target: "network", "Session read error: {}:{:?} ({:?}) {:?}", token, s.id(), s.remote_addr(), e);
                            match e {
                                Error::Disconnect(DisconnectReason::IncompatibleProtocol)
                                | Error::Disconnect(DisconnectReason::UselessPeer) => {
                                    if let Some(id) = s.id() {
                                        if !self.reserved_nodes.lock().await.contains(id) {
                                            let mut nodes = self.nodes.lock().await;
                                            nodes.note_failure(&id);
                                            nodes.mark_as_useless(id);
                                        }
                                    }
                                },
                                _ => {},
                            }
                            kill = true;
                            break;
                        },
                        Ok(SessionData::Ready) => {
                            let (_, egress_count, ingress_count) = self.session_count().await;
                            let mut s = session.lock().await;
                            let (min_peers, mut max_peers, reserved_only, self_id) = {
                                let info = self.info.lock().await;
                                let mut max_peers = info.config.max_peers;
                                for cap in &s.info.capabilities {
                                    if let Some(num) =
                                        info.config.reserved_protocols.get(&cap.protocol)
                                    {
                                        max_peers += *num;
                                        break;
                                    }
                                }
                                (
                                    info.config.min_peers as usize,
                                    max_peers as usize,
                                    info.config.non_reserved_mode == NonReservedPeerMode::Deny,
                                    *info.id(),
                                )
                            };

                            max_peers = max(max_peers, min_peers);

                            let id = *s.id().expect("Ready session always has id");

                            // Check for the session limit.
                            // Outgoing connections are allowed as long as their count is <= min_peers
                            // Incoming connections are allowed to take all of the max_peers reserve, or at most half of the slots.
                            let max_ingress = max(max_peers - min_peers, min_peers / 2);
                            if reserved_only
                                || (s.info.originated && egress_count > min_peers)
                                || (!s.info.originated && ingress_count > max_ingress)
                            {
                                if !self.reserved_nodes.lock().await.contains(&id) {
                                    // only proceed if the connecting peer is reserved.
                                    trace!(target: "network", "Disconnecting non-reserved peer {:?}", id);
                                    s.disconnect(DisconnectReason::TooManyPeers).await;
                                    kill = true;
                                    break;
                                }
                            }

                            if !self.filter.as_ref().map_or(true, |f| {
                                f.connection_allowed(&self_id, &id, ConnectionDirection::Inbound)
                            }) {
                                trace!(target: "network", "Inbound connection not allowed for {:?}", id);
                                s.disconnect(DisconnectReason::UnexpectedIdentity).await;
                                kill = true;
                                break;
                            }

                            ready_id = Some(id);

                            // Add it to the node table
                            if !s.info.originated {
                                if let Some(address) = s.remote_addr() {
                                    // We can't know remote listening ports, so just assume defaults and hope for the best.
                                    let endpoint = NodeEndpoint {
                                        address: SocketAddr::new(address.ip(), DEFAULT_PORT),
                                        udp_port: DEFAULT_PORT,
                                    };
                                    let entry = NodeEntry { id, endpoint };
                                    let mut nodes = self.nodes.lock().await;
                                    if !nodes.contains(&entry.id) {
                                        nodes.add_node(Node::new(entry.id, entry.endpoint.clone()));
                                        let mut discovery = self.discovery.lock().await;
                                        if let Some(ref mut discovery) = *discovery {
                                            discovery.add_node(entry);
                                        }
                                    }
                                }
                            }

                            // Note connection success
                            self.nodes.lock().await.note_success(&id);

                            for (p, _) in self.handlers.lock().await.iter() {
                                if s.have_capability(*p) {
                                    ready_data.push(*p);
                                }
                            }
                        },
                        Ok(SessionData::Packet {
                            data,
                            protocol,
                            packet_id,
                        }) => match self.handlers.lock().await.get(&protocol) {
                            None => {
                                warn!(target: "network", "No handler found for protocol: {:?}", protocol)
                            },
                            Some(_) => packet_data.push((protocol, packet_id, data)),
                        },
                        Ok(SessionData::Continue) => (),
                        Ok(SessionData::None) => break,
                    }
                }
            }

            if kill {
                self.kill_connection(token, true).await;
            }

            let handlers = self.handlers.lock().await;
            if !ready_data.is_empty() {
                let mut duplicate = false;
                for e in self.sessions.lock().await.iter() {
                    let session = e.lock().await;
                    if session.token() != token && session.info.id == ready_id {
                        duplicate = true;
                        break;
                    }
                }
                if duplicate {
                    trace!(target: "network", "Rejected duplicate connection: {}", token);
                    {
                        let mut s = session.lock().await;
                        s.disconnect(DisconnectReason::DuplicatePeer).await;
                    }
                    self.kill_connection(token, false).await;
                    return;
                }
                for p in ready_data {
                    let reserved = self.reserved_nodes.lock().await.clone();
                    if let Some(h) = handlers.get(&p) {
                        h.connected(
                            &NetworkContext::new(
                                p,
                                Some(session.clone()),
                                self.sessions.clone(),
                                reserved,
                            )
                            .await,
                            &token,
                        );
                        // accumulate pending packets.
                        let mut session = session.lock().await;
                        packet_data.extend(session.mark_connected(p));
                    }
                }
            }

            for (p, packet_id, data) in packet_data {
                let reserved = self.reserved_nodes.lock().await.clone();
                if let Some(h) = handlers.get(&p) {
                    h.read(
                        &NetworkContext::new(
                            p,
                            Some(session.clone()),
                            self.sessions.clone(),
                            reserved,
                        )
                        .await,
                        &token,
                        packet_id,
                        &data,
                    );
                }
            }
        }
    }

    async fn discovery_readable(&self, io: &IoContext<NetworkIoMessage>) {
        let node_changes = match (
            self.udp_socket.lock().await.as_ref(),
            self.discovery.lock().await.as_mut(),
        ) {
            (Some(udp_socket), Some(discovery)) => {
                let mut buf = [0u8; MAX_DATAGRAM_SIZE];
                let writable = discovery.any_sends_queued();
                let res = match udp_socket.recv_from(&mut buf) {
                    Ok(Some((len, address))) => discovery
                        .on_packet(&buf[0..len], address)
                        .unwrap_or_else(|e| {
                            debug!(target: "network", "Error processing UDP packet: {:?}", e);
                            None
                        }),
                    Ok(_) => None,
                    Err(e) => {
                        debug!(target: "network", "Error reading UPD socket: {:?}", e);
                        None
                    },
                };
                let new_writable = discovery.any_sends_queued();
                if writable != new_writable {
                    io.update_registration(DISCOVERY)
						.unwrap_or_else(|e| {
							debug!(target: "network" ,"Error updating discovery registration: {:?}", e)
						});
                }
                res
            },
            _ => None,
        };
        if let Some(node_changes) = node_changes {
            self.update_nodes(io, node_changes).await;
        }
    }

    async fn discovery_writable(&self, io: &IoContext<NetworkIoMessage>) {
        if let (Some(udp_socket), Some(discovery)) = (
            self.udp_socket.lock().await.as_ref(),
            self.discovery.lock().await.as_mut(),
        ) {
            while let Some(data) = discovery.dequeue_send() {
                match udp_socket.send_to(&data.payload, &data.address) {
                    Ok(Some(size)) if size == data.payload.len() => {},
                    Ok(Some(_)) => {
                        warn!(target: "network", "UDP sent incomplete datagram");
                    },
                    Ok(None) => {
                        discovery.requeue_send(data);
                        return;
                    },
                    Err(e) => {
                        debug!(target: "network", "UDP send error: {:?}, address: {:?}", e, &data.address);
                        return;
                    },
                }
            }
            io.update_registration(DISCOVERY).unwrap_or_else(
                |e| debug!(target: "network", "Error updating discovery registration: {:?}", e),
            );
        }
    }

    async fn connection_timeout(&self, token: StreamToken) {
        trace!(target: "network", "Connection timeout: {}", token);
        self.kill_connection(token, true).await
    }

    async fn kill_connection(&self, token: StreamToken, remote: bool) {
        let mut to_disconnect: Vec<ProtocolId> = Vec::new();
        let mut failure_id = None;
        let mut deregister = false;
        let mut expired_session = None;
        if let FIRST_SESSION..=LAST_SESSION = token {
            let sessions = self.sessions.lock().await;
            if let Some(session) = sessions.get(token).cloned() {
                expired_session = Some(session.clone());
                let mut s = session.lock().await;
                if !s.expired() {
                    if s.is_ready() {
                        for (p, _) in self.handlers.lock().await.iter() {
                            if s.have_capability(*p) {
                                to_disconnect.push(*p);
                            }
                        }
                    }
                    s.set_expired();
                    failure_id = s.id().cloned();
                }
                deregister = remote || s.done();
            }
        }
        if let Some(id) = failure_id {
            if remote {
                self.nodes.lock().await.note_failure(&id);
            }
        }
        for p in to_disconnect {
            let reserved = self.reserved_nodes.lock().await.clone();
            if let Some(h) = self.handlers.lock().await.get(&p) {
                h.disconnected(
                    &NetworkContext::new(
                        p,
                        expired_session.clone(),
                        self.sessions.clone(),
                        reserved,
                    )
                    .await,
                    &token,
                );
            }
        }
        // @todo Kill connection stream
        if deregister {
            //     io.deregister_stream(token)
            //         .unwrap_or_else(|e| debug!("Error deregistering stream: {:?}", e));
        }
    }

    async fn update_nodes(&self, _io: &IoContext<NetworkIoMessage>, node_changes: TableUpdates) {
        let mut to_remove: Vec<PeerId> = Vec::new();
        {
            let sessions = self.sessions.lock().await;
            for c in sessions.iter() {
                let s = c.lock().await;
                if let Some(id) = s.id() {
                    if node_changes.removed.contains(id) {
                        to_remove.push(s.token());
                    }
                }
            }
        }
        for i in to_remove {
            trace!(target: "network", "Removed from node table: {}", i);
        }
        self.nodes
            .lock()
			.await
            .update(node_changes, &*self.reserved_nodes.lock().await);
    }

    pub async fn with_context<F>(&self, protocol: ProtocolId, action: F)
    where
        F: FnOnce(&dyn NetworkContextTrait),
    {
        let reserved = { self.reserved_nodes.lock().await.clone() };

        let context = NetworkContext::new(protocol, None, self.sessions.clone(), reserved).await;
        action(&context);
    }

    pub async fn with_context_eval<F, T>(&self, protocol: ProtocolId, action: F) -> T
    where
        F: FnOnce(&dyn NetworkContextTrait) -> T,
    {
        let reserved = { self.reserved_nodes.lock().await.clone() };

        let context = NetworkContext::new(protocol, None, self.sessions.clone(), reserved).await;
        action(&context)
    }

    pub async fn add_handler(
        &self,
        handler: &Arc<dyn NetworkProtocolHandler + Send + Sync>,
        protocol: &ProtocolId,
        // version id + packet count
        versions: &[(u8, u8)],
    ) -> Result<(), Error> {
        let h = handler.clone();
        let reserved = { self.reserved_nodes.lock().await.clone() };
        h.initialize(&NetworkContext::new(*protocol, None, self.sessions.clone(), reserved).await);
        self.handlers.lock().await.insert(*protocol, h);
        let mut info = self.info.lock().await;
        for &(version, packet_count) in versions {
            info.capabilities.push(CapabilityInfo {
                protocol: *protocol,
                version,
                packet_count,
            });
        }
        Ok(())
    }

    pub async fn disable_peer(&self, peer: &PeerId) {
        let session = { self.sessions.lock().await.get(*peer).cloned() };
        if let Some(session) = session {
            {
                let mut s = session.lock().await;
                s.disconnect(DisconnectReason::DisconnectRequested).await;
            }
            if let Some(id) = session.lock().await.id() {
                let mut nodes = self.nodes.lock().await;
                nodes.note_failure(&id);
                nodes.mark_as_useless(id);
            }
        }
        trace!(target: "network", "Disabling peer {}", peer);
        self.kill_connection(*peer, false).await;
    }

    pub async fn disconnect_peer(&self, peer: &PeerId) {
        let session = { self.sessions.lock().await.get(*peer).cloned() };
        if let Some(session) = session {
            {
                let mut s = session.lock().await;
                s.disconnect(DisconnectReason::DisconnectRequested).await;
            }
        }
        trace!(target: "network", "Disconnect requested {}", peer);
        self.kill_connection(*peer, false).await;
    }
}

// #[async_trait]
// impl IoHandler<NetworkIoMessage> for Host {
//     /// Initialize networking
//     async fn initialize(&self, io: &IoContext<NetworkIoMessage>) {
//         io.register_timer(IDLE, MAINTENANCE_TIMEOUT)
//             .expect("Error registering Network idle timer");
//         io.message(NetworkIoMessage::InitPublicInterface)
//             .unwrap_or_else(|e| warn!("Error sending IO notification: {:?}", e));

// 		self.maintain_network(io).await;
//     }

//     fn stream_hup(&self, stream: StreamToken) {
//         trace!(target: "network", "Hup: {}", stream);
//         match stream {
//             FIRST_SESSION..=LAST_SESSION => self.connection_closed(stream),
//             _ => warn!(target: "network", "Unexpected hup"),
//         };
//     }

//     async fn stream_readable(&self, io: &IoContext<NetworkIoMessage>, stream: StreamToken) {
//         if self.stopping.load(AtomicOrdering::Acquire) {
//             return;
//         }
// 		// @todo Implement
//         match stream {
//             FIRST_SESSION..=LAST_SESSION => {
// 				self.session_readable(stream, io).await;
// 			},
//             DISCOVERY => {
// 				self.discovery_readable(io);
// 			},
//             TCP_ACCEPT => {
// 				self.accept(io).await;
// 			},
//             _ => panic!("Received unknown readable token"),
//         }
//     }

//     async fn stream_writable(&self, io: &IoContext<NetworkIoMessage>, stream: StreamToken) {
//         if self.stopping.load(AtomicOrdering::Acquire) {
//             return;
//         }
// 		// @todo Implement
//         match stream {
//             FIRST_SESSION..=LAST_SESSION => {
// 				self.session_writable(stream, io).await;
// 			},
//             DISCOVERY => {
// 				self.discovery_writable(io);
// 			},
//             _ => panic!("Received unknown writable token"),
//         }
//     }

//     async fn timeout(&self, io: &IoContext<NetworkIoMessage>, token: TimerToken) {
//         if self.stopping.load(AtomicOrdering::Acquire) {
//             return;
//         }
//         match token {
//             IDLE => {
// 				self.maintain_network(io).await;
// 			},
//             FIRST_SESSION..=LAST_SESSION => self.connection_timeout(token),
//             DISCOVERY_REFRESH => {
//                 // Run the _slow_ discovery if enough peers are connected
//                 if !self.has_enough_peers() {
//                     return;
//                 }
//                 self.discovery.await.lock().as_mut().map(|d| d.refresh());
//                 io.update_registration(DISCOVERY)
//                     .unwrap_or_else(|e| debug!("Error updating discovery registration: {:?}", e));
//             },
//             FAST_DISCOVERY_REFRESH => {
//                 // Run the fast discovery if not enough peers are connected
//                 if self.has_enough_peers() {
//                     return;
//                 }
//                 self.discovery.await.lock().as_mut().map(|d| d.refresh());
//                 io.update_registration(DISCOVERY)
//                     .unwrap_or_else(|e| debug!("Error updating discovery registration: {:?}", e));
//             },
//             DISCOVERY_ROUND => {
//                 self.discovery.lock().await.as_mut().map(|d| d.round());
//                 io.update_registration(DISCOVERY)
//                     .unwrap_or_else(|e| debug!("Error updating discovery registration: {:?}", e));
//             },
//             NODE_TABLE => {
//                 trace!(target: "network", "Refreshing node table");
//                 self.nodes.lock().await.clear_useless();
//                 self.nodes.lock().await.save();
//             },
//             _ => match self.timers.lock().await.get(&token).cloned() {
//                 Some(timer) => match self.handlers.lock().await.get(&timer.protocol).cloned() {
//                     None => {
//                         warn!(target: "network", "No handler found for protocol: {:?}", timer.protocol)
//                     },
//                     Some(h) => {
//                         let reserved = self.reserved_nodes.lock().await;
//                         h.timeout(
//                             &NetworkContext::new(
//                                 timer.protocol,
//                                 None,
//                                 self.sessions.clone(),
//                                 &reserved,
//                             ),
//                             timer.token,
//                         );
//                     },
//                 },
//                 None => {
//                     warn!("Unknown timer token: {}", token);
//                 }, // timer is not registerd through us
//             },
//         }
//     }

//     fn message(&self, io: &IoContext<NetworkIoMessage>, message: &NetworkIoMessage) {
//         if self.stopping.load(AtomicOrdering::Acquire) {
//             return;
//         }
//         match *message {
//             NetworkIoMessage::AddHandler { .. } => {
// 				// self.add_handler(handler, protocol, versions);
//             },
//             NetworkIoMessage::AddTimer {
//                 ref protocol,
//                 ref delay,
//                 ref token,
//             } => {
//                 let handler_token = {
//                     let mut timer_counter = self.timer_counter.lock().await;
//                     let counter = &mut *timer_counter;
//                     let handler_token = *counter;
//                     *counter += 1;
//                     handler_token
//                 };
//                 self.timers.lock().await.insert(
//                     handler_token,
//                     ProtocolTimer {
//                         protocol: *protocol,
//                         token: *token,
//                     },
//                 );
//                 io.register_timer(handler_token, *delay)
//                     .unwrap_or_else(|e| debug!("Error registering timer {}: {:?}", token, e));
//             },
//             NetworkIoMessage::Disconnect(_) => {
//             },
//             NetworkIoMessage::DisablePeer(_) => {
//             },
//             NetworkIoMessage::InitPublicInterface => self
//                 .init_public_interface(io)
//                 .unwrap_or_else(|e| warn!("Error initializing public interface: {:?}", e)),
//             _ => {}, // ignore others.
//         }
//     }

//     fn register_stream(
//         &self,
//         stream: StreamToken,
//         reg: Token,
//         event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
//     ) {
//         match stream {
//             FIRST_SESSION..=LAST_SESSION => {
//                 let session = { self.sessions.lock().await.get(stream).cloned() };
//                 if let Some(session) = session {
//                     session
//                         .lock()
//                         .register_socket(reg, event_loop)
//                         .expect("Error registering socket");
//                 }
//             },
//             DISCOVERY => match self.udp_socket.lock().as_ref() {
//                 Some(udp_socket) => {
//                     event_loop
//                         .register(udp_socket, reg, Ready::all(), PollOpt::edge())
//                         .expect("Error registering UDP socket");
//                 },
//                 _ => panic!("Error registering discovery socket"),
//             },
//             TCP_ACCEPT => {
// 				// @todo Maybe?
// 				// event_loop
// 				// 	.register(
// 				// 		&*self.tcp_listener.lock(),
// 				// 		Token(TCP_ACCEPT),
// 				// 		Ready::all(),
// 				// 		PollOpt::edge(),
// 				// 	)
// 				// 	.expect("Error registering stream");
// 			},
//             _ => warn!("Unexpected stream registration"),
//         }
//     }

//     fn deregister_stream(
//         &self,
//         stream: StreamToken,
//         event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
//     ) {
//         match stream {
//             FIRST_SESSION..=LAST_SESSION => {
//                 let mut connections = self.sessions.lock().await;
//                 if let Some(connection) = connections.get(stream).cloned() {
//                     let c = connection.lock();
//                     if c.expired() {
//                         // make sure it is the same connection that the event was generated for
//                         c.deregister_socket(event_loop)
//                             .expect("Error deregistering socket");
//                         connections.remove(stream);
//                     }
//                 }
//             },
//             DISCOVERY => (),
//             _ => warn!("Unexpected stream deregistration"),
//         }
//     }

//     fn update_stream(
//         &self,
//         stream: StreamToken,
//         reg: Token,
//         event_loop: &mut EventLoop<IoManager<NetworkIoMessage>>,
//     ) {
//         match stream {
//             FIRST_SESSION..=LAST_SESSION => {
//                 let connection = { self.sessions.lock().await.get(stream).cloned() };
//                 if let Some(connection) = connection {
//                     connection
//                         .lock()
//                         .update_socket(reg, event_loop)
//                         .expect("Error updating socket");
//                 }
//             },
//             DISCOVERY => match (
//                 self.udp_socket.lock().as_ref(),
//                 self.discovery.lock().as_ref(),
//             ) {
//                 (Some(udp_socket), Some(discovery)) => {
//                     let registration = if discovery.any_sends_queued() {
//                         Ready::readable() | Ready::writable()
//                     } else {
//                         Ready::readable()
//                     };
//                     event_loop
//                         .reregister(udp_socket, reg, registration, PollOpt::edge())
//                         .expect("Error reregistering UDP socket");
//                 },
//                 _ => panic!("Error reregistering discovery socket"),
//             },
//             TCP_ACCEPT => {
// 				// @todo Maybe?
// 				// event_loop
// 				// 	.reregister(
// 				// 		&*self.tcp_listener.lock(),
// 				// 		Token(TCP_ACCEPT),
// 				// 		Ready::all(),
// 				// 		PollOpt::edge(),
// 				// 	)
// 				// 	.expect("Error reregistering stream");
// 			},
//             _ => warn!("Unexpected stream update"),
//         }
//     }
// }

fn save_key(path: &Path, key: &Secret) {
    let mut path_buf = PathBuf::from(path);
    if let Err(e) = fs::create_dir_all(path_buf.as_path()) {
        warn!("Error creating key directory: {:?}", e);
        return;
    };
    path_buf.push("key");
    let path = path_buf.as_path();
    let mut file = match fs::File::create(&path) {
        Ok(file) => file,
        Err(e) => {
            warn!("Error creating key file: {:?}", e);
            return;
        },
    };
    if let Err(e) = restrict_permissions_owner(path, true, false) {
        warn!(target: "network", "Failed to modify permissions of the file ({})", e);
    }
    if let Err(e) = file.write(&key.to_hex().into_bytes()) {
        warn!("Error writing key file: {:?}", e);
    }
}

fn load_key(path: &Path) -> Option<Secret> {
    let mut path_buf = PathBuf::from(path);
    path_buf.push("key");
    let mut file = match fs::File::open(path_buf.as_path()) {
        Ok(file) => file,
        Err(e) => {
            debug!("Error opening key file: {:?}", e);
            return None;
        },
    };
    let mut buf = String::new();
    match file.read_to_string(&mut buf) {
        Ok(_) => {},
        Err(e) => {
            warn!("Error reading key file: {:?}", e);
            return None;
        },
    }
    match Secret::from_str(&buf) {
        Ok(key) => Some(key),
        Err(e) => {
            warn!("Error parsing key file: {:?}", e);
            None
        },
    }
}

#[test]
fn key_save_load() {
    use tempdir::TempDir;

    let tempdir = TempDir::new("").unwrap();
    let key = H256::random().into();
    save_key(tempdir.path(), &key);
    let r = load_key(tempdir.path());
    assert_eq!(key, r.unwrap());
}

#[test]
fn host_client_url() {
    let mut config = NetworkConfiguration::new_local();
    let key = "6f7b0d801bc7b5ce7bbd930b84fd0369b3eb25d09be58d64ba811091046f3aa2"
        .parse()
        .unwrap();
    config.use_secret = Some(key);
    let host: Host = Host::new(config, None).unwrap();
    assert!(host.local_url().starts_with("enode://101b3ef5a4ea7a1c7928e24c4c75fd053c235d7b80c22ae5c03d145d0ac7396e2a4ffff9adee3133a7b05044a5cee08115fd65145e5165d646bde371010d803c@"));
}
