use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProducerError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("request failed with status {0}: {1}")]
    RequestFailed(reqwest::StatusCode, String),
}

#[derive(Clone)]
pub struct ProducerClient {
    base_url: String,
    token: String,
    #[cfg(feature = "blocking")]
    client: reqwest::blocking::Client,
    #[cfg(feature = "async")]
    async_client: reqwest::Client,
}

impl ProducerClient {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            token: token.into(),
            #[cfg(feature = "blocking")]
            client: reqwest::blocking::Client::new(),
            #[cfg(feature = "async")]
            async_client: reqwest::Client::new(),
        }
    }
}

// Manually implement Debug to redact the token
impl std::fmt::Debug for ProducerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProducerClient")
            .field("base_url", &self.base_url)
            .field("token", &"***")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_redacts_token() {
        let client = ProducerClient::new("http://localhost:8788", "my-secret-token");
        let debug_output = format!("{:?}", client);
        assert!(debug_output.contains("token: \"***\""));
        assert!(!debug_output.contains("my-secret-token"));
    }
}

#[cfg(feature = "blocking")]
impl ProducerClient {
    pub fn send_one<T: Serialize>(&self, event: &T) -> Result<(), ProducerError> {
        let line = serde_json::to_string(event)? + "\n";
        let url = format!("{}/v1/ingest", self.base_url.trim_end_matches('/'));
        let res = self.client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .header("X-Auth", &self.token)
            .body(line)
            .send()?;

        if !res.status().is_success() {
             let status = res.status();
             let text = res.text().unwrap_or_default();
             return Err(ProducerError::RequestFailed(status, text));
        }
        Ok(())
    }

    pub fn send_iter<T, I>(&self, events: I) -> Result<(), ProducerError>
    where
        T: Serialize,
        I: IntoIterator<Item = T>,
    {
        let mut ndjson = String::new();
        for e in events {
            ndjson.push_str(&serde_json::to_string(&e)?);
            ndjson.push('\n');
        }
        let url = format!("{}/v1/ingest", self.base_url.trim_end_matches('/'));
        let res = self.client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .header("X-Auth", &self.token)
            .body(ndjson)
            .send()?;

        if !res.status().is_success() {
             let status = res.status();
             let text = res.text().unwrap_or_default();
             return Err(ProducerError::RequestFailed(status, text));
        }
        Ok(())
    }
}

#[cfg(feature = "async")]
mod r#async {
    use super::{ProducerClient, ProducerError};
    use bytes::Bytes;
    use futures_util::stream::{Stream, StreamExt};
    use http_body_util::StreamBody;
    use http_body::Frame;
    use reqwest::Body;
    use serde::Serialize;

    impl ProducerClient {
        pub async fn send_one_async<T: Serialize>(&self, event: &T) -> Result<(), ProducerError> {
            let line = serde_json::to_string(event)? + "\n";
            let url = format!("{}/v1/ingest", self.base_url.trim_end_matches('/'));
            let res = self.async_client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
                .header("X-Auth", &self.token)
                .body(line)
                .send()
                .await?;

            if !res.status().is_success() {
                 let status = res.status();
                 let text = res.text().await.unwrap_or_default();
                 return Err(ProducerError::RequestFailed(status, text));
            }
            Ok(())
        }

        pub async fn send_iter_async<T, S>(&self, events: S) -> Result<(), ProducerError>
        where
            T: Serialize,
            S: Stream<Item = T> + Send + Sync + 'static,
        {
            let url = format!("{}/v1/ingest", self.base_url.trim_end_matches('/'));

            // Map the stream of items to Frame<Bytes>
            let stream = events.map(|item| -> Result<Frame<Bytes>, Box<dyn std::error::Error + Send + Sync>> {
                 let mut line = match serde_json::to_vec(&item) {
                     Ok(v) => v,
                     Err(e) => return Err(Box::new(e)),
                 };
                 line.push(b'\n');
                 Ok(Frame::data(Bytes::from(line)))
            });

            // Wrap in StreamBody, then in reqwest::Body
            let body = Body::wrap(StreamBody::new(stream));

            let res = self.async_client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
                .header("X-Auth", &self.token)
                .body(body)
                .send()
                .await?;

            if !res.status().is_success() {
                 let status = res.status();
                 let text = res.text().await.unwrap_or_default();
                 return Err(ProducerError::RequestFailed(status, text));
            }
            Ok(())
        }
    }
}
