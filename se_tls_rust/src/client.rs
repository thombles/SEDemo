use crate::cert::parse_cert_chain;
use crate::signer::CallbackSigningKey;
use anyhow::{Context, Error};
use rustls::client::ResolvesClientCert;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct SecureEnclaveClientCertResolver {
    certified_key: Arc<CertifiedKey>,
}

impl ResolvesClientCert for SecureEnclaveClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

pub async fn send_message_to_server(
    hostname_port: &str,
    pem_chain: &str,
    message: &[u8],
) -> Result<(), Error> {
    let (leaf_cert_pem, ca_cert_pem) = parse_cert_chain(pem_chain)?;

    // Set up root certificate store with our CA
    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(ca_cert_pem.into_contents()))
        .context("Failed to add CA certificate to root store")?;

    // Create client configuration with mutual TLS
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_cert_resolver(Arc::new(SecureEnclaveClientCertResolver {
                certified_key: Arc::new(CertifiedKey {
                    cert: vec![CertificateDer::from(leaf_cert_pem.into_contents())],
                    key: Arc::new(CallbackSigningKey::new()?),
                    ocsp: None,
                }),
            })),
    );

    let tcp_stream = TcpStream::connect(hostname_port).await?;
    let mut tls_stream = TlsConnector::from(config)
        .connect(
            ServerName::try_from("SETLS").context("Invalid server name")?,
            tcp_stream,
        )
        .await
        .context("TLS handshake failed")?;

    tls_stream.write_all(message).await?;
    tls_stream.flush().await?;

    // Let server drop connection after received
    let mut response = vec![0u8; 1024];
    let _ = tls_stream.read(&mut response).await?;

    Ok(())
}
