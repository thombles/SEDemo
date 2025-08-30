use crate::cert::parse_cert_chain;
use crate::signer::CallbackSigningKey;
use anyhow::{Context, Error};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[derive(Debug)]
struct SecureEnclaveServerCertResolver {
    certified_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SecureEnclaveServerCertResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.clone())
    }
}

/// Start a one-off TCP/TLS server and return the first line sent by a client
pub async fn listen_for_first_message(port: u16, pem_chain: &str) -> Result<String, Error> {
    let (leaf_cert_pem, ca_cert_pem) = parse_cert_chain(pem_chain)?;
    let leaf_cert = CertificateDer::from(leaf_cert_pem.into_contents());
    let ca_cert = CertificateDer::from(ca_cert_pem.into_contents());

    let signing_key = Arc::new(CallbackSigningKey::new()?);
    let certified_key = Arc::new(CertifiedKey {
        cert: vec![leaf_cert],
        key: signing_key,
        ocsp: None,
    });

    let cert_resolver = Arc::new(SecureEnclaveServerCertResolver { certified_key });
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(ca_cert.clone())
        .context("Failed to add CA certificate to root store")?;
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .context("Failed to create client certificate verifier")?;

    let config = Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(cert_resolver),
    );
    let listener = TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    let acceptor = TlsAcceptor::from(config);

    // Accept one connection
    let (tcp_stream, _client_addr) = listener.accept().await?;
    let tls_stream = acceptor
        .accept(tcp_stream)
        .await
        .context("TLS handshake failed")?;

    // Read the first line then close connection
    let mut reader = BufReader::new(tls_stream);
    let mut message = String::new();
    let _ = reader.read_line(&mut message).await?;

    Ok(message)
}
