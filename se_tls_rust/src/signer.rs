use anyhow::{Context, Error};
use rustls::sign::{Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm};
use rustls_pki_types::SubjectPublicKeyInfoDer;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CallbackSigner {
    scheme: rustls::SignatureScheme,
}

impl CallbackSigner {
    pub fn new() -> Self {
        CallbackSigner {
            scheme: rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        }
    }

    pub fn get_public_key_der() -> Result<Vec<u8>, Error> {
        // Get the public key from the Secure Enclave via Swift callback
        // This comes in SEC#1 format
        let public_key_raw = crate::api::ffi::get_public_key_callback();
        if public_key_raw.is_empty() {
            return Err(Error::msg("Public key callback returned empty key"));
        }
        Ok(public_key_raw)
    }
}

impl Signer for CallbackSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        // Swift will sign it with the key protected by the Secure Enclave
        let signature = crate::api::ffi::sign_data_callback(message.to_vec());
        if signature.is_empty() {
            Err(RustlsError::General(
                "Signature callback returned empty signature".to_string(),
            ))
        } else {
            Ok(signature)
        }
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        self.scheme
    }
}

#[derive(Debug)]
pub struct CallbackSigningKey {
    signer: Arc<CallbackSigner>,
    public_key_der: Vec<u8>,
}

impl CallbackSigningKey {
    pub fn new() -> Result<Self, Error> {
        let signer = Arc::new(CallbackSigner::new());

        Ok(CallbackSigningKey {
            public_key_der: CallbackSigner::get_public_key_der()?,
            signer,
        })
    }

    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_der
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.signer.sign(msg).context("Signing failed")
    }
}

impl rcgen::PublicKeyData for CallbackSigningKey {
    fn der_bytes(&self) -> &[u8] {
        self.public_key_bytes()
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        // Type of key supported by Secure Enclave
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for CallbackSigningKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        CallbackSigningKey::sign(self, msg).map_err(|e| {
            println!("CSR signing error: {e}");
            rcgen::Error::RemoteKeyError
        })
    }
}

impl SigningKey for CallbackSigningKey {
    fn choose_scheme(&self, offered: &[rustls::SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&rustls::SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(Box::new(self.signer.as_ref().clone()))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(
            self.public_key_der.as_slice(),
        ))
    }
}
