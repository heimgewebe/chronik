use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProducerError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug)]
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

#[cfg(feature = "blocking")]
impl ProducerClient {
    pub fn send_one<T: Serialize>(&self, event: &T) -> Result<(), ProducerError> {
        let line = serde_json::to_string(event)? + "\n";
        let url = format!("{}/v1/ingest", self.base_url.trim_end_matches('/'));
        self.client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .header("X-Auth", &self.token)
            .body(line)
            .send()?
            .error_for_status()?;
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
        self.client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .header("X-Auth", &self.token)
            .body(ndjson)
            .send()?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(feature = "async")]
mod r#async {
    use super::{ProducerClient, ProducerError};
    use bytes::Bytes;
    use futures_util::stream::{Stream, StreamExt};
    use reqwest::Body;
    use serde::Serialize;

    impl ProducerClient {
        pub async fn send_one_async<T: Serialize>(&self, event: &T) -> Result<(), ProducerError> {
            let line = serde_json::to_string(event)? + "\n";
            let url = format!("{}/v1/ingest", self.base_url.trim_end_matches('/'));
            self.async_client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
                .header("X-Auth", &self.token)
                .body(line)
                .send()
                .await?
                .error_for_status()?;
            Ok(())
        }

        pub async fn send_iter_async<T, S>(&self, events: S) -> Result<(), ProducerError>
        where
            T: Serialize,
            S: Stream<Item = T> + Send + Sync + 'static,
        {
            let url = format!("{}/v1/ingest", self.base_url.trim_end_matches('/'));
            let body = Body::wrap_stream(events.map(|item| -> Result<Bytes, _> {
                let mut line = serde_json::to_vec(&item)?;
                line.push(b'\n');
                Ok(line.into())
            }));

            self.async_client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
                .header("X-Auth", &self.token)
                .body(body)
                .send()
                .await?
                .error_for_status()?;
            Ok(())
        }
    }
}
