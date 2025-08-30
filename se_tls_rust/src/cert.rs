use crate::signer::CallbackSigningKey;
use anyhow::{Context, Error};
use pem::{parse_many, Pem};
use rcgen::{CertificateParams, DistinguishedName, DnType};
use reqwest::Client;

/// Generate a CSR and send it to the CA
pub async fn create_csr_and_get_cert(ca_ip_port: &str) -> Result<String, Error> {
    // CA expects CN=SETLS
    let mut csr_params = CertificateParams::new(vec![])?;
    csr_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "SETLS");
        dn
    };

    // Ask Swift to sign it using the Secure Enclave
    let signing_key = CallbackSigningKey::new()?;
    let csr_pem = csr_params.serialize_request(&signing_key)?.pem()?;

    // Send CSR to CA
    let full_ca_url = format!("http://{ca_ip_port}/authenticate");
    let response = Client::new()
        .post(&full_ca_url)
        .header("Content-Type", "application/x-pem-file")
        .body(csr_pem)
        .send()
        .await?;

    if response.status().is_success() {
        Ok(response.text().await?)
    } else {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        Err(Error::msg(format!("CA rejected CSR: {error_text}")))
    }
}

/// Parse a PEM certificate chain into individual certificates
pub fn parse_cert_chain(pem_chain: &str) -> Result<(Pem, Pem), Error> {
    let pem_blocks = parse_many(pem_chain).context("Failed to parse PEM chain")?;
    if pem_blocks.len() < 2 {
        return Err(Error::msg("Expected two certificates"));
    }
    Ok((pem_blocks[0].clone(), pem_blocks[1].clone()))
}
