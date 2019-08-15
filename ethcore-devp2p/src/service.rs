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

use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;

use ansi_term::Colour;
use futures::lock::Mutex;
use log::info;
use parking_lot::RwLock;

use ethcore_io::{IoContext, IoHandler};
use network::{
    ConnectionFilter, Error, NetworkConfiguration, NetworkContext, NetworkIoMessage,
    NetworkProtocolHandlerWrapper, NonReservedPeerMode, PeerId, ProtocolId,
};

use crate::host::Host;

struct HostHandler {
    public_url: RwLock<Option<String>>,
}

impl IoHandler<NetworkIoMessage> for HostHandler {
    fn message(&self, _io: &IoContext<NetworkIoMessage>, message: &NetworkIoMessage) {
        if let NetworkIoMessage::NetworkStarted(ref public_url) = *message {
            let mut url = self.public_url.write();
            if url.as_ref().map_or(true, |uref| uref != public_url) {
                info!(target: "network", "Public node URL: {}", Colour::White.bold().paint(AsRef::<str>::as_ref(public_url)));
            }
            *url = Some(public_url.to_owned());
        }
    }
}

/// IO Service with networking
/// `Message` defines a notification data type.
pub struct NetworkService {
    host_info: String,
    host: Option<Arc<Mutex<Host>>>,
    host_handler: Arc<HostHandler>,
    config: NetworkConfiguration,
    filter: Option<Arc<dyn ConnectionFilter>>,
}

impl NetworkService {
    /// Starts IO event loop
    pub fn new(
        config: NetworkConfiguration,
        filter: Option<Arc<dyn ConnectionFilter>>,
    ) -> Result<NetworkService, Error> {
        let host_handler = Arc::new(HostHandler {
            public_url: RwLock::new(None),
        });

        Ok(NetworkService {
            host_info: config.client_version.clone(),
            host: None,
            config,
            host_handler,
            filter,
        })
    }

    /// Register a new protocol handler with the event loop.
    pub async fn register_protocol(
        &self,
        handler: NetworkProtocolHandlerWrapper,
        protocol: ProtocolId,
        // version id + packet count
        versions: &[(u8, u8)],
    ) -> Result<(), Error> {
        if let Some(ref host) = self.host {
			let host = &*host.lock().await;
            host.add_handler(&handler.0, &protocol, versions).await?;
        }
        Ok(())
    }

    /// Returns host identifier string as advertised to other peers
    pub fn host_info(&self) -> String {
        self.host_info.clone()
    }

    /// Returns the number of peers allowed.
    pub fn num_peers_range(&self) -> RangeInclusive<u32> {
        self.config.min_peers..=self.config.max_peers
    }

    /// Returns external url if available.
    pub async fn external_url(&self) -> Option<String> {
		if let Some(ref host) = self.host {
			let host = host.lock().await;
			host.external_url().await
		} else {
			None
		}
    }

    /// Returns external url if available.
    pub async fn local_url(&self) -> Option<String> {
		if let Some(ref host) = self.host {
			let host = host.lock().await;
			Some(host.local_url().await)
		} else {
			None
		}
    }

    /// Start network IO.
    ///
    /// In case of error, also returns the listening address for better error reporting.
    pub async fn start(&mut self) -> Result<(), (Error, Option<SocketAddr>)> {
        let listen_addr = self.config.listen_address;
        {
            if self.host.is_none() {
                let h = Host::new(self.config.clone(), self.filter.clone())
					.await
					.map_err(|err| (err, listen_addr))?;
                // self.io_service
                //     .register_handler(h.clone())
                //     .map_err(|err| (err.into(), listen_addr))?;
                self.host = Some(h);
            }
        }

        if self.host_handler.public_url.read().is_none() {
            // self.io_service
            //     .register_handler(self.host_handler.clone())
            //     .map_err(|err| (err.into(), listen_addr))?;
        }

        Ok(())
    }

    /// Stop network IO.
    pub async fn stop(&mut self) {
        if let Some(ref host) = self.host {
	        let host = host.lock().await;
            host.stop().await;
        }
        self.host = None;
    }

    /// Get a list of all connected peers by id.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        if let Some(ref host) = self.host {
        	let host = host.lock().await;
			host.connected_peers().await
		} else {
			Vec::new()
		}
    }

    /// Try to add a reserved peer.
    pub async fn add_reserved_peer(&self, peer: &str) -> Result<(), Error> {
        if let Some(ref host) = self.host {
        	let host = host.lock().await;
            host.add_reserved_node(peer).await
        } else {
            Ok(())
        }
    }

    /// Try to remove a reserved peer.
    pub async fn remove_reserved_peer(&self, peer: &str) -> Result<(), Error> {
        if let Some(ref host) = self.host {
        	let host = host.lock().await;
            host.remove_reserved_node(peer).await
        } else {
            Ok(())
        }
    }

    /// Set the non-reserved peer mode.
    pub async fn set_non_reserved_mode(&self, mode: NonReservedPeerMode) {
        if let Some(ref host) = self.host {
        	let host = host.lock().await;
            host.set_non_reserved_mode(mode).await;
        }
    }

    /// Executes action in the network context
    pub async fn with_context<F>(&self, protocol: ProtocolId, action: F)
    where
        F: FnOnce(&dyn NetworkContext),
    {
        if let Some(ref host) = self.host {
        	let host = host.lock().await;
            host.with_context(protocol, action).await;
        };
    }

    /// Evaluates function in the network context
    pub async fn with_context_eval<F, T>(&self, protocol: ProtocolId, action: F) -> Option<T>
    where
        F: FnOnce(&dyn NetworkContext) -> T,
    {
        if let Some(ref host) = self.host {
        	let host = host.lock().await;
            Some(host.with_context_eval(protocol, action).await)
        } else {
            None
        }
    }
}
