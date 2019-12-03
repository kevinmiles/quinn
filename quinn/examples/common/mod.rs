//! Commonly used code in most examples.

use quinn::{
    Certificate, CertificateChain, ClientConfig, ClientConfigBuilder, Endpoint, EndpointDriver,
    Incoming, PrivateKey, ServerConfig, ServerConfigBuilder, TransportConfig,
};
use std::{error::Error, net::ToSocketAddrs, sync::Arc};

/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
///
/// - server_certs: list of trusted certificates.
#[allow(unused)]
pub fn make_client_endpoint<A: ToSocketAddrs>(
    bind_addr: A,
    server_certs: &[&[u8]],
) -> Result<(Endpoint, EndpointDriver), Box<dyn Error>> {
    let config = configure_client(server_certs)?;

    let mut builder = Endpoint::builder();
    builder.default_client_config(config);

    let (driver, endpoint, _) = builder.bind(&bind_addr.to_socket_addrs()?.next().unwrap())?;

    Ok((endpoint, driver))
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - UDP socket driver
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
#[allow(unused)]
pub fn make_server_endpoint<A: ToSocketAddrs>(
    bind_addr: A,
) -> Result<(EndpointDriver, Incoming, Vec<u8>), Box<dyn Error>> {
    let (server_config, server_certificate) = configure_server()?;

    let mut builder = Endpoint::builder();
    builder.listen(server_config);

    let (driver, _endpoint, incoming) = builder
        .bind(&bind_addr.to_socket_addrs()?.next().unwrap())?;

    Ok((driver, incoming, server_certificate))
}

/// Builds default quinn client config and trusts given certificates.
///
/// ## Args
///
/// - server_certs: a list of trusted certificates in DER format.
fn configure_client(server_certs: &[&[u8]]) -> Result<ClientConfig, Box<dyn Error>> {
    let mut config_builder = ClientConfigBuilder::default();

    for cert in server_certs {
        config_builder.add_certificate_authority(Certificate::from_der(&cert)?)?;
    }

    Ok(config_builder.build())
}

/// Returns default server configuration along with its certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate_der = certificate.serialize_der().unwrap();
    let private_key = certificate.serialize_private_key_der();
    let private_key = PrivateKey::from_der(&private_key)?;

    let server_config = ServerConfig {
        transport: Arc::new(TransportConfig {
            stream_window_uni: 0,
            ..Default::default()
        }),
        ..Default::default()
    };

    let certificate = Certificate::from_der(&certificate_der)?;

    let mut config_builder = ServerConfigBuilder::new(server_config);
    config_builder.certificate(CertificateChain::from_certs(vec![certificate]), private_key)?;

    Ok((config_builder.build(), certificate_der))
}

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-24"];
