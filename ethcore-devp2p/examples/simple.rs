#![feature(async_await)]
#![feature(async_closure)]

use std::sync::Arc;
use std::time::Duration;

use ethcore_devp2p::NetworkService;
// use futures::executor::block_on;
use network::{
    NetworkConfiguration, NetworkContext, NetworkProtocolHandler, NetworkProtocolHandlerWrapper,
    PeerId,
};

struct MyHandler;

impl NetworkProtocolHandler for MyHandler {
    fn initialize(&self, io: &dyn NetworkContext) {
        io.register_timer(0, Duration::from_secs(1))
            .expect("Error registering Timer");
    }

    fn read(&self, _io: &dyn NetworkContext, peer: &PeerId, packet_id: u8, data: &[u8]) {
        println!(
            "Received {} ({} bytes) from {}",
            packet_id,
            data.len(),
            peer
        );
    }

    fn connected(&self, _io: &dyn NetworkContext, peer: &PeerId) {
        println!("Connected {}", peer);
    }

    fn disconnected(&self, _io: &dyn NetworkContext, peer: &PeerId) {
        println!("Disconnected {}", peer);
    }
}

#[runtime::main]
async fn main() {
    env_logger::init();

    let mut host_service = NetworkService::new(NetworkConfiguration::new_with_port(30305), None)
        .expect("Error creating network service");
    host_service.start().await.expect("Error starting service");
    host_service
        .register_protocol(
            NetworkProtocolHandlerWrapper(Arc::new(MyHandler)),
            *b"myp",
            &[(1u8, 1u8)],
        )
        .await
        .expect("Error registering protocol");

    println!("Host info: {}", host_service.host_info());
    println!("Host local URL: {:?}", host_service.local_url().await);

    let mut peer_service = NetworkService::new(NetworkConfiguration::new_with_port(30303), None)
        .expect("Error creating network service");
    peer_service.start().await.expect("Error starting service");
    peer_service
        .register_protocol(
            NetworkProtocolHandlerWrapper(Arc::new(MyHandler)),
            *b"myp",
            &[(1u8, 1u8)],
        )
        .await
        .expect("Error registering protocol");

    println!("Peer info: {}", peer_service.host_info());
    println!("Peer local URL: {:?}", peer_service.local_url().await);

	let peer_address = host_service.local_url().await.unwrap();
    peer_service
        .add_reserved_peer(&peer_address)
    	.await
        .expect("Failed to add reserved peer");

    let handler = std::thread::spawn(async move || loop {
        std::thread::sleep(Duration::from_secs(2));
        println!(
            "[Host] Connected peers: {:?}",
            host_service.connected_peers().await.len()
        );
        println!(
            "[Peer] Connected peers: {:?}",
            peer_service.connected_peers().await.len()
        );
    });

    handler.join().unwrap().await;
    // Wait for quit condition
    // ...
    // Drop the service
}
