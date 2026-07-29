use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::transport::{Channel, Endpoint};

use self::rvps_api::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

use super::{Result, RvpsApi};

pub mod rvps_api {
    tonic::include_proto!("reference");
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct RvpsRemoteConfig {
    /// Address of remote RVPS. If this field is given, a remote RVPS will be connected to.
    /// If this field is not given, a built-in RVPS will be used.
    #[serde(default = "default_address")]
    pub address: String,
}

fn default_address() -> String {
    "127.0.0.1:50003".into()
}

#[derive(Error, Debug)]
pub enum GrpcRvpsError {
    #[error("Returned status: {0}")]
    Status(#[from] tonic::Status),

    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),

    #[error("timed out connecting to remote RVPS at {address} after {timeout:?}")]
    ConnectionTimeout { address: String, timeout: Duration },
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_WINDOW: Duration = Duration::from_secs(30);
const RETRY_INTERVAL: Duration = Duration::from_millis(250);

pub struct Agent {
    client: Mutex<ReferenceValueProviderServiceClient<Channel>>,
}

impl Agent {
    pub async fn new(addr: &str) -> Result<Self> {
        let channel =
            connect_with_retry(addr, CONNECT_WINDOW, CONNECT_TIMEOUT, RETRY_INTERVAL).await?;
        Ok(Self {
            client: Mutex::new(ReferenceValueProviderServiceClient::new(channel)),
        })
    }
}

async fn connect_with_retry(
    addr: &str,
    connect_window: Duration,
    connect_timeout: Duration,
    retry_interval: Duration,
) -> Result<Channel> {
    let endpoint = Endpoint::new(addr.to_string())?.connect_timeout(connect_timeout);
    let deadline = Instant::now() + connect_window;

    loop {
        match tokio::time::timeout_at(deadline, endpoint.connect()).await {
            Ok(Ok(channel)) => return Ok(channel),
            Ok(Err(_)) if Instant::now() < deadline => {
                tokio::time::sleep_until((Instant::now() + retry_interval).min(deadline)).await;
            }
            Ok(Err(_)) | Err(_) => {
                return Err(anyhow::Error::new(GrpcRvpsError::ConnectionTimeout {
                    address: addr.to_string(),
                    timeout: connect_window,
                })
                .into());
            }
        }
    }
}
#[async_trait::async_trait]
impl RvpsApi for Agent {
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let req = tonic::Request::new(ReferenceValueRegisterRequest {
            message: message.to_string(),
        });
        let _ = self
            .client
            .lock()
            .await
            .register_reference_value(req)
            .await?;
        Ok(())
    }

    async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        let req = tonic::Request::new(ReferenceValueQueryRequest {
            reference_value_id: reference_value_id.to_string(),
        });
        let res = self
            .client
            .lock()
            .await
            .query_reference_value(req)
            .await?
            .into_inner()
            .reference_value_results;

        match res {
            Some(reference_value) => {
                let reference_value = serde_json::from_str(&reference_value)?;
                Ok(Some(reference_value))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tokio::net::TcpListener;

    use super::connect_with_retry;

    #[tokio::test]
    async fn connection_retries_until_remote_rvps_is_ready() {
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);

        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let listener = TcpListener::bind(address).await.unwrap();
            listener.accept().await.unwrap();
        });

        connect_with_retry(
            &format!("http://{address}"),
            Duration::from_millis(250),
            Duration::from_millis(10),
            Duration::from_millis(10),
        )
        .await
        .expect("RVPS connection should recover during the retry window");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connection_fails_after_retry_budget_is_exhausted() {
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let started = Instant::now();
        let connect_window = Duration::from_millis(40);

        let result = connect_with_retry(
            &format!("http://{address}"),
            connect_window,
            Duration::from_millis(10),
            Duration::from_millis(1),
        )
        .await;

        assert!(result.is_err());
        assert!(started.elapsed() >= connect_window);
    }
}
