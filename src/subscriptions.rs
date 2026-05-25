//! GraphQL subscriptions over WebSocket (`graphql-transport-ws`).
//!
//! Rust port of the TypeScript SDK's `WillowSubscriptions`. Opens a
//! WebSocket to `{apiUrl}/graphql/ws` on the validator (default) or an
//! indexer (`SubscribeSource::Indexer`), drives the
//! [graphql-transport-ws](https://github.com/enisdenjo/graphql-ws/blob/master/PROTOCOL.md)
//! handshake, and delivers each `next` payload to the caller via an
//! `mpsc::Receiver`.
//!
//! On unexpected disconnect the SDK auto-reconnects by default (exponential
//! backoff, capped). For `SubscribeSource::Indexer` the failing indexer is
//! evicted from the discovery cache and a different one is tried on the
//! next attempt, so a dead indexer fails over without caller intervention.
//! Pass `reconnect: false` on `SubscribeOptions` to opt out.
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
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
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

/// Default initial reconnect delay before the first retry.
pub const DEFAULT_RECONNECT_BACKOFF: Duration = Duration::from_millis(500);
/// Default cap on the reconnect backoff. Doubling from the initial value
/// tops out here.
pub const DEFAULT_MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(30);

/// Optional subscription parameters.
#[derive(Debug, Clone)]
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

    /// Automatically reconnect on unexpected disconnect. Defaults to
    /// `true`. Set to `false` for the classic "subscription ends on
    /// close" behavior.
    ///
    /// Reconnect-only: messages that were in flight when the socket
    /// dropped are not replayed, and the new connection may redeliver
    /// events the old one already emitted. Callers that need
    /// exactly-once should dedupe by a stable field (e.g., block number
    /// or entity id) themselves.
    pub reconnect: bool,

    /// Maximum number of reconnection attempts before giving up.
    /// `None` (the default) means retry forever.
    pub max_reconnect_attempts: Option<usize>,

    /// Initial reconnect delay. Doubles on each failed attempt up to
    /// [`Self::max_reconnect_backoff`]. Default
    /// [`DEFAULT_RECONNECT_BACKOFF`] (500ms).
    pub reconnect_backoff: Duration,

    /// Maximum reconnect delay. Default [`DEFAULT_MAX_RECONNECT_BACKOFF`]
    /// (30 seconds).
    pub max_reconnect_backoff: Duration,
}

impl Default for SubscribeOptions {
    fn default() -> Self {
        Self {
            variables: None,
            operation_name: None,
            connection_payload: None,
            source: SubscribeSource::default(),
            reconnect: true,
            max_reconnect_attempts: None,
            reconnect_backoff: DEFAULT_RECONNECT_BACKOFF,
            max_reconnect_backoff: DEFAULT_MAX_RECONNECT_BACKOFF,
        }
    }
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
    /// completes: server sent `complete`, [`Self::unsubscribe`] was
    /// called, reconnect is disabled and the connection dropped, or
    /// `max_reconnect_attempts` was exhausted.
    pub async fn recv(&mut self) -> Option<SubscriptionPayload> {
        self.rx.recv().await
    }

    /// Gracefully close: send `complete` to the server (if connected)
    /// and drop the socket. Safe to call multiple times.
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
    /// socket is opened. Subsequent reconnects after a disconnect happen
    /// asynchronously inside the task that backs the handle.
    pub async fn subscribe(
        &self,
        subgrove_id: &str,
        query: &str,
        options: SubscribeOptions,
    ) -> Result<SubscriptionHandle> {
        let (ws_url, initial_indexer_did) = resolve_ws_url(
            &self.api_url,
            &self.indexers,
            subgrove_id,
            options.source,
            None, // no indexer to evict on the first attempt
        )
        .await?;

        // Stable across reconnects — the graphql-ws `id` is per-socket
        // but there's no harm in reusing the same string on each new
        // subscribe frame. The server treats each as a fresh
        // subscription; filtering on our side stays consistent.
        let sub_id = format!(
            "sub-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        // First connect — surface errors to the caller.
        let initial_stream = connect_and_handshake(&ws_url, &sub_id, query, &options).await?;

        let (payload_tx, payload_rx) = mpsc::channel::<SubscriptionPayload>(64);
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>(1);

        let task_state = TaskState {
            api_url: self.api_url.clone(),
            indexers: self.indexers.clone(),
            subgrove_id: subgrove_id.to_string(),
            query: query.to_string(),
            options,
            sub_id,
            current_indexer_did: initial_indexer_did,
            payload_tx,
            cancel_rx,
        };

        let task = tokio::spawn(subscription_loop(initial_stream, task_state));

        Ok(SubscriptionHandle {
            rx: payload_rx,
            cancel: Arc::new(Mutex::new(Some(cancel_tx))),
            task: Some(task),
        })
    }
}

// ── Internal state & loop ────────────────────────────────────────────

struct TaskState {
    api_url: Url,
    indexers: WillowIndexers,
    subgrove_id: String,
    query: String,
    options: SubscribeOptions,
    sub_id: String,
    /// DID of the indexer we're currently connected to, if any. Used to
    /// evict from the discovery cache on reconnect so the failover picks
    /// a different indexer.
    current_indexer_did: Option<String>,
    payload_tx: mpsc::Sender<SubscriptionPayload>,
    cancel_rx: mpsc::Receiver<()>,
}

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Outcome of pumping a single socket until it's done.
enum PumpExit {
    /// Caller-initiated stop. Send `complete`, close, exit task.
    Cancelled,
    /// Server sent a `complete` frame for our subscription ID. Definitive
    /// end — don't reconnect.
    ServerComplete,
    /// Socket closed or transport errored. Candidate for reconnect.
    ///
    /// `delivered_payload` reflects whether we saw at least one `next`
    /// frame before the drop. It gates whether the reconnect-loop should
    /// reset its attempt counter: resetting only after real data flow
    /// (rather than after a bare handshake) stops a server that accepts
    /// connections but immediately drops them from driving an infinite
    /// reconnect loop.
    Disconnected { delivered_payload: bool },
}

/// The task entry point: pumps the current socket, then reconnects as
/// long as options and attempt counters allow.
async fn subscription_loop(initial_stream: WsStream, mut state: TaskState) {
    let mut current_stream = Some(initial_stream);
    let mut attempts: usize = 0;
    let max_attempts = state.options.max_reconnect_attempts.unwrap_or(usize::MAX);

    loop {
        // Pump the current socket if we have one.
        if let Some(stream) = current_stream.take() {
            let exit = pump_socket(stream, &mut state).await;
            match exit {
                PumpExit::Cancelled | PumpExit::ServerComplete => return,
                PumpExit::Disconnected { delivered_payload } => {
                    // Reset the attempt counter only if we saw real
                    // data this round. Otherwise a server accepting
                    // connections and immediately dropping them would
                    // loop forever at attempts=0 (each reconnect
                    // resetting before any payload arrives).
                    if delivered_payload {
                        attempts = 0;
                    }
                }
            }
        }

        if !state.options.reconnect {
            return;
        }
        if attempts >= max_attempts {
            return;
        }
        attempts += 1;

        // Exponential backoff, capped. `attempts` is 1-indexed so the
        // first retry uses `reconnect_backoff` (no doubling yet).
        let delay = std::cmp::min(
            state
                .options
                .reconnect_backoff
                .saturating_mul(1u32 << (attempts - 1).min(30)),
            state.options.max_reconnect_backoff,
        );

        // Sleep, watching for cancel so unsubscribe() during the backoff
        // cuts the retry cleanly.
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = state.cancel_rx.recv() => return,
        }

        // Resolve a new endpoint. Passing the current DID tells the
        // helper to evict that indexer from discovery first, so we
        // fail over to a different one when multiple are registered.
        let resolve = resolve_ws_url(
            &state.api_url,
            &state.indexers,
            &state.subgrove_id,
            state.options.source,
            state.current_indexer_did.as_deref(),
        )
        .await;

        let (ws_url, new_did) = match resolve {
            Ok(r) => r,
            Err(_) => {
                // Discovery failed (validator unreachable, empty list,
                // etc.). Keep retrying — `attempts` increments each
                // iteration so we'll eventually honor
                // `max_reconnect_attempts`.
                continue;
            }
        };

        match connect_and_handshake(&ws_url, &state.sub_id, &state.query, &state.options).await {
            Ok(stream) => {
                // Connection + handshake succeeded; data-flow determines
                // whether to reset the attempt counter. See
                // `PumpExit::Disconnected.delivered_payload`.
                state.current_indexer_did = new_did;
                current_stream = Some(stream);
            }
            Err(_) => {
                // Connect / handshake failed. Back off and retry.
                continue;
            }
        }
    }
}

/// Resolve the WebSocket URL for a given source. For indexer mode,
/// optionally evicts `skip_indexer_did` from the discovery cache first
/// — pass this on reconnect to fail over to a different indexer.
///
/// Returns `(ws_url, maybe_indexer_did)`. The `indexer_did` is `Some`
/// iff the source is `Indexer` and the resolve succeeded.
async fn resolve_ws_url(
    api_url: &Url,
    indexers: &WillowIndexers,
    subgrove_id: &str,
    source: SubscribeSource,
    skip_indexer_did: Option<&str>,
) -> Result<(String, Option<String>)> {
    match source {
        SubscribeSource::Validator => Ok((http_to_ws(api_url.as_str()) + "graphql/ws", None)),
        SubscribeSource::Indexer => {
            if let Some(did) = skip_indexer_did {
                indexers.evict(did);
            }
            let candidates = indexers.for_subgrove(subgrove_id).await?;
            if candidates.is_empty() {
                return Err(WillowError::Custom(format!(
                    "No indexer serves subgrove {} — cannot open indexer subscription",
                    subgrove_id
                )));
            }
            let chosen = &candidates[0];
            let did = chosen.indexer_did.clone();
            let endpoint = chosen
                .effective_query_endpoint()
                .trim_end_matches('/')
                .to_string();
            Ok((http_to_ws(&endpoint) + "/graphql/ws", Some(did)))
        }
    }
}

/// Dial the WebSocket, send `connection_init`, wait for `connection_ack`,
/// send `subscribe`. Returns the ready-to-pump stream on success.
async fn connect_and_handshake(
    ws_url: &str,
    sub_id: &str,
    query: &str,
    options: &SubscribeOptions,
) -> Result<WsStream> {
    let mut request = ws_url
        .to_string()
        .into_client_request()
        .map_err(|e| WillowError::Config(format!("Invalid WebSocket URL {}: {}", ws_url, e)))?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        "graphql-transport-ws".parse().unwrap(),
    );

    let (mut ws_stream, _) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| WillowError::Custom(format!("WebSocket connect failed: {}", e)))?;

    // connection_init
    let init = serde_json::json!({
        "type": "connection_init",
        "payload": options.connection_payload.clone().unwrap_or(serde_json::json!({})),
    });
    ws_stream
        .send(Message::Text(init.to_string()))
        .await
        .map_err(|e| WillowError::Custom(format!("send connection_init: {}", e)))?;

    // Wait for connection_ack. Tolerate ping/pong during handshake.
    loop {
        let frame = ws_stream
            .next()
            .await
            .ok_or_else(|| WillowError::Custom("socket closed during handshake".to_string()))?
            .map_err(|e| WillowError::Custom(format!("read during handshake: {}", e)))?;

        let text = match frame {
            Message::Text(t) => t,
            Message::Ping(p) => {
                let _ = ws_stream.send(Message::Pong(p)).await;
                continue;
            }
            Message::Close(_) => {
                return Err(WillowError::Custom(
                    "server closed during handshake".to_string(),
                ));
            }
            _ => continue,
        };

        let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        match msg.get("type").and_then(|v| v.as_str()) {
            Some("connection_ack") => break,
            Some("ping") => {
                let pong = serde_json::json!({ "type": "pong" });
                let _ = ws_stream.send(Message::Text(pong.to_string())).await;
            }
            Some("connection_error") => {
                return Err(WillowError::Custom(format!(
                    "server refused connection: {:?}",
                    msg.get("payload")
                )));
            }
            _ => continue,
        }
    }

    // subscribe
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
    ws_stream
        .send(Message::Text(subscribe_msg.to_string()))
        .await
        .map_err(|e| WillowError::Custom(format!("send subscribe: {}", e)))?;

    Ok(ws_stream)
}

/// Read frames from a single socket until cancel / server complete /
/// transport close. Delivers `next` frames to `state.payload_tx` and
/// transparently responds to `ping` / `connection_ack`.
async fn pump_socket(stream: WsStream, state: &mut TaskState) -> PumpExit {
    let (mut sink, mut read) = stream.split();
    let mut delivered_payload = false;

    loop {
        tokio::select! {
            _ = state.cancel_rx.recv() => {
                // Send `complete` if the server is still listening,
                // then close.
                let complete = serde_json::json!({
                    "type": "complete",
                    "id": state.sub_id,
                });
                let _ = sink.send(Message::Text(complete.to_string())).await;
                let _ = sink.close().await;
                return PumpExit::Cancelled;
            }
            frame = read.next() => {
                let Some(frame) = frame else {
                    return PumpExit::Disconnected { delivered_payload };
                };
                let Ok(frame) = frame else {
                    return PumpExit::Disconnected { delivered_payload };
                };
                let text = match frame {
                    Message::Text(t) => t,
                    Message::Close(_) => return PumpExit::Disconnected { delivered_payload },
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
                    "next" => {
                        if msg.get("id").and_then(|v| v.as_str())
                            != Some(state.sub_id.as_str())
                        {
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
                        if state.payload_tx.send(parsed).await.is_err() {
                            // Receiver dropped — end the subscription
                            // outright (no reconnect) since there's no
                            // consumer.
                            return PumpExit::Cancelled;
                        }
                        delivered_payload = true;
                    }
                    "complete" => {
                        if msg.get("id").and_then(|v| v.as_str())
                            == Some(state.sub_id.as_str())
                        {
                            return PumpExit::ServerComplete;
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
    fn subscribe_options_defaults_enable_reconnect() {
        let opts = SubscribeOptions::default();
        assert!(opts.reconnect);
        assert!(opts.max_reconnect_attempts.is_none());
        assert_eq!(opts.reconnect_backoff, DEFAULT_RECONNECT_BACKOFF);
        assert_eq!(opts.max_reconnect_backoff, DEFAULT_MAX_RECONNECT_BACKOFF);
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
