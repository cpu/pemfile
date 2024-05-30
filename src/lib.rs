//! # rustls-pemfile
//! A basic parser for .pem files containing cryptographic keys and certificates.
//!
//! The input to this crate is a .pem file containing potentially many sections,
//! and the output is those sections as alleged DER-encodings.  This crate does
//! not decode the actual DER-encoded keys/certificates.
//!
//! ## Quick start
//! Starting with an `io::BufRead` containing the file to be read:
//! - Use `read_all()` to ingest the whole file, then work through the contents in-memory, or,
//! - Use `read_one()` to stream through the file, processing the items as found, or,
//! - Use `certs()` to extract just the certificates (silently discarding other sections), and
//!   similarly for `rsa_private_keys()` and `pkcs8_private_keys()`.
//!
//! # no-std support
//!
//! The opt-out "std" Cargo feature can be disabled to put this crate in no-std mode.
//!
//! In no-std mode, the `read_one_from_slice` API can be used to parse a .pem file that has already
//! been loaded into memory.
//!
//! ## Example code
#![cfg_attr(feature = "std", doc = "```")]
#![cfg_attr(not(feature = "std"), doc = "```ignore")]
//! use std::iter;
//! use rustls_pemfile::{Item, read_one};
//! # let mut reader = std::io::BufReader::new(&b"junk\n-----BEGIN RSA PRIVATE KEY-----\nqw\n-----END RSA PRIVATE KEY-----\n"[..]);
//! // Assume `reader` is any std::io::BufRead implementor
//! for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
//!     match item.unwrap() {
//!         Item::X509Certificate(cert) => println!("certificate {:?}", cert),
//!         Item::Crl(crl) => println!("certificate revocation list: {:?}", crl),
//!         Item::Csr(csr) => println!("certificate signing request: {:?}", csr),
//!         Item::Pkcs1Key(key) => println!("rsa pkcs1 key {:?}", key),
//!         Item::Pkcs8Key(key) => println!("pkcs8 key {:?}", key),
//!         Item::Sec1Key(key) => println!("sec1 ec key {:?}", key),
//!         _ => println!("unhandled item"),
//!     }
//! }
//! ```

// Require docs for public APIs, deny unsafe code, etc.
#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]
#![no_std]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(test)]
#[cfg(feature = "std")]
mod tests;

/// --- Main crate APIs:
mod pemfile;

#[cfg(feature = "std")]
pub use pemfile::{read_all, read_one};
pub use pemfile::{read_one_from_slice, Error, Item};
#[cfg(feature = "std")]
use pki_types::PrivateKeyDer;
#[cfg(feature = "std")]
use pki_types::{
    CertificateDer, CertificateRevocationListDer, CertificateSigningRequestDer, EchConfigListBytes,
    PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};

#[cfg(feature = "std")]
use core::iter;
/// --- Legacy APIs:
#[cfg(feature = "std")]
use std::io;

/// Return an iterator over certificates from `rd`.
///
/// Filters out any PEM sections that are not certificates and yields errors if a problem
/// occurs while trying to extract a certificate.
#[cfg(feature = "std")]
pub fn certs(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<CertificateDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::X509Certificate(cert)) => Some(Ok(cert)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return the first private key found in `rd`.
///
/// Yields the first PEM section describing a private key (of any type), or an error if a
/// problem occurs while trying to read PEM sections.
#[cfg(feature = "std")]
pub fn private_key(rd: &mut dyn io::BufRead) -> Result<Option<PrivateKeyDer<'static>>, io::Error> {
    for result in iter::from_fn(move || read_one(rd).transpose()) {
        match result? {
            Item::Pkcs1Key(key) => return Ok(Some(key.into())),
            Item::Pkcs8Key(key) => return Ok(Some(key.into())),
            Item::Sec1Key(key) => return Ok(Some(key.into())),
            Item::X509Certificate(_) | Item::Crl(_) | Item::Csr(_) | Item::EchConfigs(_) => {
                continue
            }
        }
    }

    Ok(None)
}

/// Return the first certificate signing request (CSR) found in `rd`.
///
/// Yields the first PEM section describing a certificate signing request, or an error if a
/// problem occurs while trying to read PEM sections.
#[cfg(feature = "std")]
pub fn csr(
    rd: &mut dyn io::BufRead,
) -> Result<Option<CertificateSigningRequestDer<'static>>, io::Error> {
    for result in iter::from_fn(move || read_one(rd).transpose()) {
        match result? {
            Item::Csr(csr) => return Ok(Some(csr)),
            Item::Pkcs1Key(_)
            | Item::Pkcs8Key(_)
            | Item::Sec1Key(_)
            | Item::X509Certificate(_)
            | Item::Crl(_)
            | Item::EchConfigs(_) => continue,
        }
    }

    Ok(None)
}

/// Return an iterator certificate revocation lists (CRLs) from `rd`.
///
/// Filters out any PEM sections that are not CRLs and yields errors if a problem occurs
/// while trying to extract a CRL.
#[cfg(feature = "std")]
pub fn crls(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<CertificateRevocationListDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Crl(crl)) => Some(Ok(crl)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over RSA private keys from `rd`.
///
/// Filters out any PEM sections that are not RSA private keys and yields errors if a problem
/// occurs while trying to extract an RSA private key.
#[cfg(feature = "std")]
pub fn rsa_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivatePkcs1KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Pkcs1Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over PKCS8-encoded private keys from `rd`.
///
/// Filters out any PEM sections that are not PKCS8-encoded private keys and yields errors if a
/// problem occurs while trying to extract an RSA private key.
#[cfg(feature = "std")]
pub fn pkcs8_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivatePkcs8KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Pkcs8Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over SEC1-encoded EC private keys from `rd`.
///
/// Filters out any PEM sections that are not SEC1-encoded EC private keys and yields errors if a
/// problem occurs while trying to extract a SEC1-encoded EC private key.
#[cfg(feature = "std")]
pub fn ec_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivateSec1KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Sec1Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return a PKCS#8 private key and Encrypted Client Hello (ECH) config list from `rd`.
///
/// Both are mandatory and must be present in the input. The file should begin with the PEM
/// encoded PKCS#8 private key, followed by the PEM encoded ECH config list.
///
/// See [draft-farrell-tls-pemesni.txt] and [draft-ietf-tls-esni §4][draft-ietf-tls-esni]
/// for more information.
///
/// [draft-farrell-tls-pemesni.txt]: https://github.com/sftcd/pemesni/blob/44bcf7259f204a60421ea05be02a1e2859cadaa9/draft-farrell-tls-pemesni.txt
/// [draft-ietf-tls-esni]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-4
#[cfg(feature = "std")]
pub fn server_ech_configs(
    rd: &mut dyn io::BufRead,
) -> Result<(PrivatePkcs8KeyDer<'static>, EchConfigListBytes<'static>), io::Error> {
    // draft-farrell-tls-pemesni specifies the PEM format for a server's ECH config as the PEM
    // delimited base64 encoding of a PKCS#8 private key, and then subsequently the PEM
    // delimited base64 encoding of a TLS encoded ECH config. Both are mandatory.

    let Ok(Some(Item::Pkcs8Key(private_key))) = read_one(rd) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Missing mandatory PKCS#8 private key",
        ));
    };

    let Ok(Some(Item::EchConfigs(ech_configs))) = read_one(rd) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Missing mandatory ECH config",
        ));
    };

    Ok((private_key, ech_configs))
}

/// Return an iterator over Encrypted Client Hello (ECH) configs from `rd`.
///
/// Each ECH config is expected to be a PEM-delimited ("-----BEGIN ECH CONFIG-----") BASE64
/// encoding of a TLS encoded ECHConfigList structure, as described in
/// [draft-ietf-tls-esni §4][draft-ietf-tls-esni].
///
/// For server configurations that require both a private key and a config, prefer
/// [server_ech_config].
///
/// [draft-ietf-tls-esni]: https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-18#section-4
#[cfg(feature = "std")]
pub fn ech_configs(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<EchConfigListBytes<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::EchConfigs(ech_configs)) => Some(Ok(ech_configs)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}
