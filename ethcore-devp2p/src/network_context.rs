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

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ethcore_io::{StreamToken, TimerToken};
use futures::lock::Mutex;
use log::trace;
use network::{
    client_version::ClientVersion, Error, NetworkContext as NetworkContextTrait, PacketId, PeerId,
    ProtocolId, SessionInfo,
};
use parking_lot::RwLock;

use crate::{connection::PAYLOAD_SOFT_LIMIT, node_table::*, session::Session};

pub type Slab<T> = ::slab::Slab<T, usize>;
pub type SharedSession = Arc<Mutex<Session>>;

/// IO access point. This is passed to all IO handlers and provides an interface to the IO subsystem.
pub struct NetworkContext {
    protocol: ProtocolId,
    sessions: Arc<Mutex<Slab<SharedSession>>>,
    session: Option<SharedSession>,
    session_id: Option<StreamToken>,
    reserved_peers: HashSet<NodeId>,
}

impl NetworkContext {
    /// Create a new network IO access point. Takes references to all the data that can be updated within the IO handler.
    pub async fn new(
        protocol: ProtocolId,
        session: Option<SharedSession>,
        sessions: Arc<Mutex<Slab<SharedSession>>>,
        reserved_peers: HashSet<NodeId>,
    ) -> NetworkContext {
        let id = if let Some(s) = session.as_ref() {
            Some(s.lock().await.token())
        } else {
            None
        };
        NetworkContext {
            protocol,
            session_id: id,
            session,
            sessions,
            reserved_peers: reserved_peers,
        }
    }

    async fn resolve_session(&self, peer: PeerId) -> Option<SharedSession> {
        match self.session_id {
            Some(id) if id == peer => self.session.clone(),
            _ => self.sessions.lock().await.get(peer).cloned(),
        }
    }
}

#[async_trait]
impl<'s> NetworkContextTrait for NetworkContext {
    async fn send(&self, peer: PeerId, packet_id: PacketId, data: Vec<u8>) -> Result<(), Error> {
        self.send_protocol(self.protocol, peer, packet_id, data)
            .await
    }

    async fn send_protocol(
        &self,
        protocol: ProtocolId,
        peer: PeerId,
        packet_id: PacketId,
        data: Vec<u8>,
    ) -> Result<(), Error> {
        let session = self.resolve_session(peer).await;
        if let Some(session) = session {
            let mut s = session.lock().await;
            s.send_packet(Some(protocol), packet_id as u8, &data)
                .await?;
        } else {
            trace!(target: "network", "Send: Peer no longer exist")
        }
        Ok(())
    }

    async fn respond(&self, packet_id: PacketId, data: Vec<u8>) -> Result<(), Error> {
        let has_session = self.session.is_some();
        assert!(has_session, "Respond called without network context");
        if let Some(id) = self.session_id {
            self.send(id, packet_id, data).await
        } else {
            Err(Error::Expired)
        }
    }

    fn disable_peer(&self, _peer: PeerId) {
        // @todo Implement
    }

    fn disconnect_peer(&self, _peer: PeerId) {
        // @todo Implement
    }

    async fn is_expired(&self) -> bool {
        if let Some(s) = self.session.as_ref() {
            s.lock().await.expired()
        } else {
            false
        }
    }

    fn register_timer(&self, _token: TimerToken, _delay: Duration) -> Result<(), Error> {
        // @todo Implement Timers
        // self.io
        //     .message(NetworkIoMessage::AddTimer {
        //         token,
        //         delay,
        //         protocol: self.protocol,
        //     })
        //     .unwrap_or_else(|e| warn!("Error sending network IO message: {:?}", e));
        Ok(())
    }

    async fn peer_client_version(&self, peer: PeerId) -> ClientVersion {
        if let Some(s) = self.resolve_session(peer).await {
            s.lock().await.info.client_version.clone()
        } else {
            ClientVersion::from("unknown").to_owned()
        }
    }

    async fn session_info(&self, peer: PeerId) -> Option<SessionInfo> {
        if let Some(s) = self.resolve_session(peer).await {
            Some(s.lock().await.info.clone())
        } else {
            None
        }
    }

    async fn protocol_version(&self, protocol: ProtocolId, peer: PeerId) -> Option<u8> {
        if let Some(session) = self.resolve_session(peer).await {
            session.lock().await.capability_version(protocol)
        } else {
            None
        }
    }

    fn subprotocol_name(&self) -> ProtocolId {
        self.protocol
    }

    async fn is_reserved_peer(&self, peer: PeerId) -> bool {
        self.session_info(peer)
            .await
            .and_then(|info| info.id)
            .map(|node| self.reserved_peers.contains(&node))
            .unwrap_or(false)
    }

    fn payload_soft_limit(&self) -> usize {
        PAYLOAD_SOFT_LIMIT
    }
}
