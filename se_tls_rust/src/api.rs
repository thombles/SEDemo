use crate::cert::create_csr_and_get_cert;
use crate::client::send_message_to_server;
use crate::server::listen_for_first_message;

#[swift_bridge::bridge]
pub mod ffi {
    // Swift provides these callback functions using Secure Enclave
    extern "Swift" {
        #[swift_bridge(swift_name = "signDataCallback")]
        fn sign_data_callback(data: Vec<u8>) -> Vec<u8>;
        #[swift_bridge(swift_name = "getPublicKeyCallback")]
        fn get_public_key_callback() -> Vec<u8>;
    }

    extern "Rust" {
        async fn listen_for_message(pem_chain: String, port: u16) -> String;
        async fn send_message(pem_chain: String, hostname_port: String, message: Vec<u8>);
        async fn get_certificate(ca_hostname_port: String) -> String;
    }
}

/// Listen for a TLS connection and return the first message received
pub async fn listen_for_message(pem_chain: String, port: u16) -> String {
    match listen_for_first_message(port, &pem_chain).await {
        Ok(message) => message,
        Err(e) => {
            eprintln!("Failed to listen for message: {e}");
            "-".to_string()
        }
    }
}

/// Send a message to a TLS server
pub async fn send_message(pem_chain: String, hostname_port: String, message: Vec<u8>) {
    if let Err(e) = send_message_to_server(&hostname_port, &pem_chain, &message).await {
        eprintln!("Failed to send message: {e}");
    }
}

/// Get a certificate from the CA by creating and signing a CSR
pub async fn get_certificate(ca_hostname_port: String) -> String {
    match create_csr_and_get_cert(&ca_hostname_port).await {
        Ok(pem_chain) => pem_chain,
        Err(e) => {
            eprintln!("Failed to get certificate: {e}");
            String::new()
        }
    }
}
