//! GraphQL subscriptions over WebSocket (`graphql-transport-ws`).
//!
//! Rust port of the TypeScript SDK's `WillowSubscriptions`. Opens a
//! WebSocket to `{apiUrl}/graphql/ws` on the validator (default) or an
//! indexer (`SubscribeSource::Indexer`), drives the
//! [graphql-transport-ws](https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md)
//! handshake, and delivers each `next` payload to the caller via an
//! `mpsc::Receiver`.
//!
//! See `docs/QUERY_ROUTING.md` for the validator vs indexer trust model.
//!
//! # Example
//!
//! ```rust,no_run
//! use willow_sdk::subscriptions::{SubscribeOptions, SubscribeSource};
//! use willow_sdk::WillowClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = WillowClient::new("http://validator:3031").await?;
//! let mut handle = client
//!     .subscriptions()
//!     .subscribe(
//!         "my-subgrove",
//!         "subscription { blockFinalized { height appHash } }",
//!         SubscribeOptions::default(),
//!     )
//!     .await?;
//!
//! while let Some(payload) = handle.recv().await {
//!     println!("got event: {:?}", payload);
//! }
//! // Drop `handle` or call `handle.unsubscribe().await` to close.
//! # Ok(()) }
//! ```

use crate::errors::{Result, WillowError};
use crate::indexers::WillowIndexers;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;
use url::Url;

/// Which backend to open the subscription WebSocket against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeSource {
    /// `{apiUrl}/graphql/ws` — consensus-verified chain-tip events
    /// (`BlockFinalized`). This is the default.
    Validator,
    /// `{indexer.query_endpoint}/graphql/ws` selected via discovery (or
    /// the explicit `indexer_url` override). Useful for `VerifyOnly`
    /// subgroves where the validator has no tail data.
    Indexer,
}

impl Default for SubscribeSource {
    fn default() -> Self {
        SubscribeSource::Validator
    }
}

/// Optional subscription parameters.
#[derive(Debug, Default, Clone)]
pub struct SubscribeOptions {
    /// GraphQL variables passed to the subscription.
    pub variables: Option<serde_json::Value>,
    /// GraphQL operation name (when the document contains multiple).
    pub operation_name: Option<String>,
    /// Payload for the `connection_init` frame (e.g. auth tokens).
    pub connection_payload: Option<serde_json::Value>,
    /// Where to open the WebSocket. Defaults to
    /// [`SubscribeSource::Validator`].
    pub source: SubscribeSource,
}

/// A single payload pushed by the server over a `next` frame.
///
/// Mirrors the wire shape: `{ data?, errors? }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<serde_json::Value>,
}

/// Handle returned by [`WillowSubscriptions::subscribe`].
///
/// Receive events via [`Self::recv`]; close the subscription by calling
/// [`Self::unsubscribe`] or dropping the handle.
pub struct SubscriptionHandle {
    rx: mpsc::Receiver<SubscriptionPayload>,
    cancel: Arc<Mutex<Option<mpsc::Sender<()>>>>,
    task: Option<JoinHandle<()>>,
}

impl SubscriptionHandle {
    /// Await the next payload. Returns `None` when the subscription
    /// completes (server sent `complete`, connection dropped, or
    /// [`Self::unsubscribe`] was called).
    pub async fn recv(&mut self) -> Option<SubscriptionPayload> {
        self.rx.recv().await
    }

    /// Gracefully close: send `complete` to the server and drop the
    /// socket. Safe to call multiple times.
    pub async fn unsubscribe(&mut self) {
        if let Some(tx) = self.cancel.lock().await.take() {
            let _ = tx.send(()).await;
        }
    }
}

impl Drop for SubscriptionHandle {
    fn drop(&mut self) {
        // Best-effort: signal cancel. The task will see `None` from its
        // select! and send `complete` before closing the socket.
        if let Ok(mut guard) = self.cancel.try_lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.try_send(());
            }
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Subscription client, wired to the same discovery layer as queries.
#[derive(Clone)]
pub struct WillowSubscriptions {
    api_url: Url,
    indexers: WillowIndexers,
}

impl WillowSubscriptions {
    pub fn new(api_url: Url, indexers: WillowIndexers) -> Self {
        Self { api_url, indexers }
    }

    /// Open a subscription. Blocks until the handshake completes
    /// (`connection_init` → `connection_ack` → `subscribe`), then returns
    /// a handle that receives `next` payloads asynchronously.
    ///
    /// For `SubscribeSource::Indexer`, the discovery round-trip happens
    /// inside this call; surface errors reach the caller before any
    /// socket is opened.
    pub async fn subscribe(
        &self,
        subgrove_id: &str,
        query: &str,
        options: SubscribeOptions,
    ) -> Result<SubscriptionHandle> {
        let ws_url = self.resolve_ws_url(subgrove_id, options.source).await?;
        self.open_and_subscribe(ws_url, query, options).await
    }

    async fn resolve_ws_url(
        &self,
        subgrove_id: &str,
        source: SubscribeSource,
    ) -> Result<String> {
        match source {
            SubscribeSource::Validator => Ok(http_to_ws(self.api_url.as_str()) + "graphql/ws"),
            SubscribeSource::Indexer => {
                let candidates = self.indexers.for_subgrove(subgrove_id).await?;
                if candidates.is_empty() {
                    return Err(WillowError::Custom(format!(
                        "No indexer serves subgrove {} — cannot open indexer subscription",
                        subgrove_id
                    )));
                }
                // Highest-performance candidate. Failover on disconnect is
                // tracked as follow-up; see QUERY_ROUTING.md.
                let endpoint = candidates[0]
                    .effective_query_endpoint()
                    .trim_end_matches('/')
                    .to_string();
                Ok(http_to_ws(&endpoint) + "/graphql/ws")
            }
        }
    }

    async fn open_and_subscribe(
        &self,
        ws_url: String,
        query: &str,
        options: SubscribeOptions,
    ) -> Result<SubscriptionHandle> {
        let request = ws_url
            .clone()
            .into_client_request()
            .map_err(|e| WillowError::Config(format!("Invalid WebSocket URL {}: {}", ws_url, e)))?;
        // Protocol negotiation happens via the Sec-WebSocket-Protocol
        // header below — tungstenite's connect_async accepts this on the
        // client request.
        let mut request = request;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            "graphql-transport-ws".parse().unwrap(),
        );

        let (ws_stream, _) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(|e| WillowError::Custom(format!("WebSocket connect failed: {}", e)))?;

        let (payload_tx, payload_rx) = mpsc::channel::<SubscriptionPayload>(64);
        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(1);

        // Use a short ID — only meaningful within this socket's scope.
        let sub_id = format!(
            "sub-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        let query = query.to_string();

        let task = tokio::spawn(async move {
            let (mut sink, mut stream) = ws_stream.split();

            // 1. connection_init
            let init = serde_json::json!({
                "type": "connection_init",
                "payload": options.connection_payload.unwrap_or(serde_json::json!({})),
            });
            if sink.send(Message::Text(init.to_string())).await.is_err() {
                return;
            }

            let mut initialized = false;

            loop {
                tokio::select! {
                    _ = cancel_rx.recv() => {
                        // Caller asked us to stop. Send `complete` if
                        // we're past the handshake, then drop the socket.
                        if initialized {
                            let complete = serde_json::json!({
                                "type": "complete",
                                "id": sub_id,
                            });
                            let _ = sink.send(Message::Text(complete.to_string())).await;
                        }
                        let _ = sink.close().await;
                        return;
                    }
                    frame = stream.next() => {
                        let Some(Ok(frame)) = frame else {
                            // Server closed or transport error — drop
                            // the tx; the receiver will see `None`.
                            return;
                        };
                        let text = match frame {
                            Message::Text(t) => t,
                            Message::Close(_) => return,
                            Message::Ping(p) => {
                                let _ = sink.send(Message::Pong(p)).await;
                                continue;
                            }
                            _ => continue,
                        };
                        let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) else {
                            continue;
                        };
                        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        match msg_type {
                            "connection_ack" => {
                                initialized = true;
                                let mut sub_payload = serde_json::json!({ "query": query });
                                if let Some(v) = &options.variables {
                                    sub_payload["variables"] = v.clone();
                                }
                                if let Some(op) = &options.operation_name {
                                    sub_payload["operationName"] = serde_json::Value::String(op.clone());
                                }
                                let subscribe_msg = serde_json::json!({
                                    "type": "subscribe",
                                    "id": sub_id,
                                    "payload": sub_payload,
                                });
                                if sink.send(Message::Text(subscribe_msg.to_string())).await.is_err() {
                                    return;
                                }
                            }
                            "next" => {
                                if msg.get("id").and_then(|v| v.as_str()) != Some(sub_id.as_str()) {
                                    continue;
                                }
                                let payload = msg
                                    .get("payload")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null);
                                let parsed: SubscriptionPayload = serde_json::from_value(payload)
                                    .unwrap_or(SubscriptionPayload {
                                        data: None,
                                        errors: None,
                                    });
                                if payload_tx.send(parsed).await.is_err() {
                                    // Receiver dropped — nothing more to deliver.
                                    return;
                                }
                            }
                            "complete" => {
                                if msg.get("id").and_then(|v| v.as_str()) == Some(sub_id.as_str()) {
                                    return;
                                }
                            }
                            "ping" => {
                                let pong = serde_json::json!({ "type": "pong" });
                                let _ = sink.send(Message::Text(pong.to_string())).await;
                            }
                            _ => {
                                // Ignore unknown message types.
                            }
                        }
                    }
                }
            }
        });

        Ok(SubscriptionHandle {
            rx: payload_rx,
            cancel: Arc::new(Mutex::new(Some(cancel_tx))),
            task: Some(task),
        })
    }
}

/// Convert `http://host/` or `https://host/` to `ws://host/` or `wss://host/`.
/// Returns with a trailing slash so callers can concatenate path segments.
fn http_to_ws(url: &str) -> String {
    let s = if let Some(rest) = url.strip_prefix("https://") {
        format!("wss://{}", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        format!("ws://{}", rest)
    } else {
        url.to_string()
    };
    if s.ends_with('/') {
        s
    } else {
        format!("{}/", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_to_ws_https() {
        assert_eq!(http_to_ws("https://x:3031"), "wss://x:3031/");
        assert_eq!(http_to_ws("https://x:3031/"), "wss://x:3031/");
    }

    #[test]
    fn http_to_ws_http() {
        assert_eq!(http_to_ws("http://x:3031"), "ws://x:3031/");
    }

    #[test]
    fn http_to_ws_passthrough_when_already_ws() {
        // Useful if callers pre-convert.
        assert_eq!(http_to_ws("ws://x:3031"), "ws://x:3031/");
    }

    #[test]
    fn subscribe_source_default_is_validator() {
        assert_eq!(SubscribeSource::default(), SubscribeSource::Validator);
    }

    #[test]
    fn subscription_payload_roundtrips() {
        let json = serde_json::json!({
            "data": { "blockFinalized": { "height": 42 } },
        });
        let p: SubscriptionPayload = serde_json::from_value(json.clone()).unwrap();
        assert!(p.data.is_some());
        assert!(p.errors.is_none());
        // Serialize back; errors: None should be skipped.
        let out = serde_json::to_value(&p).unwrap();
        assert_eq!(out.get("data"), json.get("data"));
        assert!(out.get("errors").is_none());
    }
}
