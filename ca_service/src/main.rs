use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
};
use rustls_pki_types::CertificateSigningRequestDer;
use std::sync::Arc;
use x509_parser::{certification_request::X509CertificationRequest, prelude::FromDer};

struct CertificateAuthority {
    ca_cert: Certificate,
    ca_key_pair: KeyPair,
}

impl CertificateAuthority {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        println!("Generating P-256 ECDSA key and CA certificate...");
        let key_pair = KeyPair::generate()?;
        let mut ca_params = CertificateParams::new(vec!["SETLS-CA".to_string()])?;
        ca_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "SETLS-CA");
            dn
        };
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&key_pair)?;

        Ok(CertificateAuthority {
            ca_cert,
            ca_key_pair: key_pair,
        })
    }

    /// Attempt to sign a CSR.
    ///
    /// Returns a PEM chain with the issue leaf certificate followed by the CA.
    fn sign_csr(&self, csr_pem: &str) -> Result<String, Box<dyn std::error::Error>> {
        let csr_pem = pem::parse(csr_pem)?;

        if !csr_pem.tag().contains("CERTIFICATE REQUEST") {
            return Err("Not a certificate request".into());
        }

        let csr_der = csr_pem.contents();
        let (_, csr_x509) = X509CertificationRequest::from_der(csr_der)?;

        if !csr_x509
            .certification_request_info
            .subject
            .to_string()
            .contains("CN=SETLS")
        {
            return Err("Invalid DN: must be CN=SETLS".into());
        }

        match csr_x509.verify_signature() {
            Ok(()) => println!("Incoming CSR signature verification passed"),
            Err(e) => {
                println!("Incoming CSR signature verification failed: {e:?}");
                return Err(format!("signature verification error: {e:?}").into());
            }
        }

        // Extract the public key from the CSR
        let csr_der_wrapped = CertificateSigningRequestDer::from(csr_der);
        let csr = rcgen::CertificateSigningRequestParams::from_der(&csr_der_wrapped)?;

        let mut cert_params = CertificateParams::new(vec!["SETLS".to_string()])?;
        cert_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "SETLS");
            dn
        };
        cert_params.not_before = time::OffsetDateTime::now_utc();
        cert_params.not_after = cert_params.not_before + time::Duration::days(180);

        // Sign the certificate using the public key from the CSR and the CA as the issuer
        let cert = cert_params.signed_by(&csr.public_key, &self.ca_cert, &self.ca_key_pair)?;
        let cert_pem = cert.pem();
        let ca_cert_pem = self.ca_cert.pem();

        println!("Certificate issued successfully");
        Ok(format!("{cert_pem}\n{ca_cert_pem}"))
    }
}

#[tokio::main]
async fn main() {
    let ca = CertificateAuthority::new().unwrap();
    let state = Arc::new(ca);

    let app = Router::new()
        .route("/authenticate", post(authenticate))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("CA service listening on port 3000");
    println!("POST /authenticate endpoint ready to accept CSRs");

    axum::serve(listener, app).await.unwrap();
}

async fn authenticate(State(state): State<Arc<CertificateAuthority>>, body: String) -> Response {
    match state.sign_csr(&body) {
        Ok(chain) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/x-pem-file")
            .body(chain.into())
            .unwrap(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
    use x509_parser::{certificate::X509Certificate, prelude::FromDer};

    #[test]
    fn test_csr_signing_workflow() {
        // Create a CSR as a client
        let leaf_key_pair = KeyPair::generate().unwrap();
        let mut csr_params = CertificateParams::new(vec![]).unwrap();
        csr_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, "SETLS");
            dn
        };
        let csr = csr_params.serialize_request(&leaf_key_pair).unwrap();
        let csr_pem = csr.pem().unwrap();

        // Get a CA to sign it
        let ca = CertificateAuthority::new().unwrap();
        let chain_pem = ca.sign_csr(&csr_pem).unwrap();

        // Client gets result and verifies signature
        let pem_blocks = pem::parse_many(&chain_pem).expect("Failed to parse returned PEM chain");
        assert_eq!(pem_blocks.len(), 2, "Should return exactly 2 certificates");

        let leaf_cert_der = &pem_blocks[0].contents();
        let ca_cert_der = &pem_blocks[1].contents();

        let (_, leaf_cert) =
            X509Certificate::from_der(leaf_cert_der).expect("Failed to parse leaf certificate");
        let (_, ca_cert) =
            X509Certificate::from_der(ca_cert_der).expect("Failed to parse CA certificate");

        assert!(
            leaf_cert
                .verify_signature(Some(&ca_cert.public_key()))
                .is_ok(),
            "Leaf certificate should be verified by CA certificate"
        );
        assert!(
            leaf_cert.subject().to_string().contains("CN=SETLS"),
            "Leaf certificate should have CN=SETLS"
        );
        assert!(
            ca_cert.subject().to_string().contains("CN=SETLS-CA"),
            "CA certificate should have CN=SETLS-CA"
        );
        assert!(
            ca_cert
                .verify_signature(Some(&ca_cert.public_key()))
                .is_ok(),
            "CA certificate should be self-signed"
        );
    }
}
