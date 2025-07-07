use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::result;
use std::sync::Arc;

use rand::Rng;
use rcgen::{
    Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
    SerialNumber,
};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature};
use rustls_pemfile::{certs, private_key};
use thiserror::Error;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    self, ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig,
};

use crate::error::{EncodingError, FileError, KeyError};

const CERT_NAME: &str = "cert.pem";
const KEY_NAME: &str = "key.pem";

/// Client config
pub fn client_config(tls_verify: bool) -> ClientConfig {
    let mut config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();

    if !tls_verify {
        config
            .dangerous()
            .set_certificate_verifier(NoCertificateVerification::new());
    }

    config
}

/// Server config
pub fn server_config(
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_file = File::open(cert_path).map_err(|err| FileError::Open(cert_path.clone(), err))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| FileError::Open(cert_path.clone(), err))?;

    let key_file = File::open(key_path).map_err(|err| FileError::Open(key_path.clone(), err))?;
    let mut key_reader = BufReader::new(key_file);
    let Some(private_key) =
        private_key(&mut key_reader).map_err(|err| FileError::Read(key_path.clone(), err))?
    else {
        return Err(KeyError::PrivateKeyDecode(EncodingError::Pem).into());
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    Ok(Arc::new(config))
}

/// Generate ephemeral x.509 certificate and private key pair. They're written to the -datadir
pub fn generate_self_signed_cert_and_key(
    tls_data_dir: &PathBuf,
) -> Result<(PathBuf, PathBuf), TlsError> {
    // build the certificate
    let mut params = CertificateParams::default();
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = IsCa::ExplicitNoCa;
    let serial_number = rand::rng().random_range(0..u64::MAX);
    params.serial_number = Some(SerialNumber::from(serial_number));
    // remove the default CN
    params.distinguished_name.remove(DnType::CommonName);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "cruzbit client");
    params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let cert = Certificate::from_params(params)?;

    // create the cert
    let certificate_pem = cert.serialize_pem()?;
    let cert_path = Path::new(".").join(tls_data_dir).join(CERT_NAME);
    fs::write(&cert_path, certificate_pem)
        .map_err(|err| FileError::Write(cert_path.clone(), err))?;

    // create the key
    let private_key_pem = cert.serialize_private_key_pem();
    let key_path = Path::new(".").join(tls_data_dir).join(KEY_NAME);
    fs::write(&key_path, private_key_pem)
        .map_err(|err| FileError::Write(cert_path.clone(), err))?;

    Ok((cert_path, key_path))
}

#[derive(Debug)]
pub struct NoCertificateVerification;

impl NoCertificateVerification {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("file")]
    File(#[from] FileError),
    #[error("key")]
    Key(#[from] KeyError),

    #[error("rcgen")]
    Rcgen(#[from] rcgen::Error),
    #[error("rustls")]
    Rustls(#[from] tokio_rustls::rustls::Error),
    #[error("rustls pemfile")]
    RustlsPemfinle(#[from] std::io::Error),
}
