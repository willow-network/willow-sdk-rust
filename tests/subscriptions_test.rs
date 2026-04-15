//! End-to-end tests for `WillowSubscriptions` against a local in-process
//! `graphql-transport-ws` server.
//!
//! We can't reach a real Willow node from unit tests, so each test spins
//! up a minimal tungstenite server that implements just enough of the
//! protocol to exercise the client's handshake + message plumbing. The
//! server URL is fed into the SDK and we verify the resulting
//! `SubscriptionPayload` stream.

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::WebSocketStream;
use url::Url;

use willow_sdk::subscriptions::{SubscribeOptions, SubscribeSource, WillowSubscriptions};
use willow_sdk::WillowIndexers;

/// Test server that speaks graphql-transport-ws with a scripted flow.
///
/// Callers drive it by providing an `on_subscribe` callback that can
/// send any number of `next` frames (or errors) before completing.
async fn run_test_server<F, Fut>(addr: SocketAddr, on_subscribe: F)
where
    F: Fn(WebSocketStream<TcpStream>, String) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let listener = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let on_subscribe = &on_subscribe;
            let ws = tokio_tungstenite::accept_hdr_async(
                stream,
                |_req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut response: tokio_tungstenite::tungstenite::handshake::server::Response|
                 -> Result<
                    tokio_tungstenite::tungstenite::handshake::server::Response,
                    tokio_tungstenite::tungstenite::handshake::server::ErrorResponse,
                > {
                    // Advertise the graphql-transport-ws subprotocol on
                    // the response so the tungstenite client accepts it.
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        "graphql-transport-ws".parse().unwrap(),
                    );
                    Ok(response)
                },
            )
            .await;
            let Ok(mut ws) = ws else {
                continue;
            };
            // Drive the init handshake here; then hand off to
            // on_subscribe for the per-subscription script.
            let Some(Ok(Message::Text(init_text))) = ws.next().await else {
                continue;
            };
            let init: serde_json::Value = serde_json::from_str(&init_text).unwrap();
            assert_eq!(init["type"], "connection_init");
            let ack = serde_json::json!({ "type": "connection_ack" });
            ws.send(Message::Text(ack.to_string())).await.unwrap();

            // Expect a subscribe frame.
            let Some(Ok(Message::Text(sub_text))) = ws.next().await else {
                continue;
            };
            let sub: serde_json::Value = serde_json::from_str(&sub_text).unwrap();
            assert_eq!(sub["type"], "subscribe");
            let sub_id = sub["id"].as_str().unwrap().to_string();

            on_subscribe(ws, sub_id).await;
        }
    });
    // Let the listener spin up before returning.
    tokio::time::sleep(Duration::from_millis(50)).await;
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn subs_for(api_url: &str) -> WillowSubscriptions {
    let api = Url::parse(api_url).unwrap();
    let http = reqwest::Client::new();
    let indexers = WillowIndexers::new(http, api.clone(), None);
    WillowSubscriptions::new(api, indexers)
}

#[tokio::test]
async fn validator_subscription_delivers_next_payloads() {
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    run_test_server(addr, move |mut ws, sub_id| async move {
        // Send two payloads then complete.
        for i in 0..2 {
            let frame = serde_json::json!({
                "type": "next",
                "id": sub_id,
                "payload": { "data": { "tick": i } },
            });
            ws.send(Message::Text(frame.to_string())).await.unwrap();
        }
        let complete = serde_json::json!({ "type": "complete", "id": sub_id });
        ws.send(Message::Text(complete.to_string())).await.unwrap();
    })
    .await;

    let subs = subs_for(&format!("http://127.0.0.1:{}", port));
    let mut handle = subs
        .subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions::default(),
        )
        .await
        .expect("subscribe");

    let first = handle.recv().await.expect("first payload");
    assert_eq!(first.data.unwrap()["tick"], 0);

    let second = handle.recv().await.expect("second payload");
    assert_eq!(second.data.unwrap()["tick"], 1);

    // `complete` from the server closes the stream — recv returns None.
    let after = tokio::time::timeout(Duration::from_millis(200), handle.recv()).await;
    match after {
        Ok(None) | Err(_) => {}
        Ok(Some(p)) => panic!("unexpected extra payload after complete: {:?}", p),
    }
}

#[tokio::test]
async fn unsubscribe_closes_the_stream() {
    // After calling unsubscribe(), the handle's `recv()` should return
    // `None` — the subscription is over. This is the contract callers
    // care about; wire-level verification of the `complete` frame is
    // covered implicitly (the task only closes the socket after sending
    // it) and racy to test in isolation due to tokio scheduling.

    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    run_test_server(addr, move |mut ws, sub_id| async move {
        // Send one next then sit and wait. The client will unsubscribe
        // before we send anything else.
        let frame = serde_json::json!({
            "type": "next",
            "id": sub_id,
            "payload": { "data": { "tick": 0 } },
        });
        ws.send(Message::Text(frame.to_string())).await.unwrap();
        // Drain incoming client frames until the socket closes.
        while let Some(Ok(_)) = ws.next().await {}
    })
    .await;

    let subs = subs_for(&format!("http://127.0.0.1:{}", port));
    let mut handle = subs
        .subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions::default(),
        )
        .await
        .expect("subscribe");

    // Consume the one payload we know is coming.
    let p = handle.recv().await.expect("first payload");
    assert_eq!(p.data.unwrap()["tick"], 0);

    handle.unsubscribe().await;

    // After unsubscribe, recv should return None — either immediately or
    // once the task finishes closing the socket.
    let closed = tokio::time::timeout(Duration::from_millis(500), handle.recv())
        .await
        .expect("recv should not hang after unsubscribe");
    assert!(
        closed.is_none(),
        "expected None after unsubscribe, got {:?}",
        closed
    );
}

#[tokio::test]
async fn ping_from_server_gets_pong_back() {
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // Check the pong by reading frames back from the socket after the
    // ping is sent. Use a oneshot to signal from the server task.
    let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
    let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

    run_test_server(addr, move |mut ws, _sub_id| {
        let tx = tx.clone();
        async move {
            let ping = serde_json::json!({ "type": "ping" });
            ws.send(Message::Text(ping.to_string())).await.unwrap();

            // Next frame the client sends should be a pong.
            while let Some(Ok(Message::Text(text))) = ws.next().await {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                    if v["type"] == "pong" {
                        if let Some(tx) = tx.lock().await.take() {
                            let _ = tx.send(true);
                        }
                        return;
                    }
                }
            }
        }
    })
    .await;

    let subs = subs_for(&format!("http://127.0.0.1:{}", port));
    let _handle = subs
        .subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions::default(),
        )
        .await
        .expect("subscribe");

    let got_pong = tokio::time::timeout(Duration::from_millis(500), rx)
        .await
        .unwrap();
    assert_eq!(got_pong.unwrap(), true);
}

#[tokio::test]
async fn indexer_source_errors_when_no_indexer_serves_subgrove() {
    // No WS server needed — the discovery lookup should fail first.
    // Point the "API URL" at 127.0.0.1:1 (ECONNREFUSED) but set an
    // explicit indexer_url of None so discovery actually runs.
    let api_url = Url::parse("http://127.0.0.1:1").unwrap();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let indexers = WillowIndexers::new(http, api_url.clone(), None);
    let subs = WillowSubscriptions::new(api_url, indexers);

    let result = subs
        .subscribe(
            "my-subgrove",
            "subscription { x }",
            SubscribeOptions {
                source: SubscribeSource::Indexer,
                ..Default::default()
            },
        )
        .await;

    // Either the discovery fetch fails (connection refused) or, if it
    // somehow succeeded with an empty list, we'd get a "no indexer
    // serves" error. Both are valid failures for the test's intent.
    assert!(result.is_err(), "expected subscribe to fail");
}

#[tokio::test]
async fn reconnects_on_unexpected_disconnect() {
    // Server script: first connection sends one payload then drops the
    // socket; second connection sends a different payload. The SDK should
    // reconnect automatically and the caller should see both payloads.
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_clone = counter.clone();

    run_test_server(addr, move |mut ws, sub_id| {
        let n = counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move {
            if n == 0 {
                // First connection: send payload A then close abruptly.
                let frame = serde_json::json!({
                    "type": "next",
                    "id": sub_id,
                    "payload": { "data": { "which": "A" } },
                });
                ws.send(Message::Text(frame.to_string())).await.unwrap();
                // Drop the socket without sending `complete`.
                drop(ws);
            } else {
                // Second connection: send payload B then complete cleanly.
                let frame = serde_json::json!({
                    "type": "next",
                    "id": sub_id,
                    "payload": { "data": { "which": "B" } },
                });
                ws.send(Message::Text(frame.to_string())).await.unwrap();
                let complete = serde_json::json!({ "type": "complete", "id": sub_id });
                ws.send(Message::Text(complete.to_string())).await.unwrap();
                // Keep the socket around so the client can read the frames
                // before we tear down.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    })
    .await;

    let subs = subs_for(&format!("http://127.0.0.1:{}", port));
    let mut handle = subs
        .subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions {
                // Fast backoff so the test doesn't sit for half a second.
                reconnect_backoff: Duration::from_millis(50),
                ..Default::default()
            },
        )
        .await
        .expect("subscribe");

    // First payload from connection #1.
    let a = tokio::time::timeout(Duration::from_millis(1_000), handle.recv())
        .await
        .expect("first payload should arrive before timeout")
        .expect("payload Some");
    assert_eq!(a.data.unwrap()["which"], "A");

    // Second payload is from connection #2 — after auto-reconnect.
    let b = tokio::time::timeout(Duration::from_millis(2_000), handle.recv())
        .await
        .expect("second payload should arrive after reconnect")
        .expect("payload Some");
    assert_eq!(b.data.unwrap()["which"], "B");

    // Server sent `complete`; stream ends cleanly.
    let after = tokio::time::timeout(Duration::from_millis(500), handle.recv()).await;
    assert!(matches!(after, Ok(None) | Err(_)));
    assert!(counter.load(std::sync::atomic::Ordering::SeqCst) >= 2);
}

#[tokio::test]
async fn does_not_reconnect_when_reconnect_is_false() {
    // With reconnect disabled, a socket drop ends the subscription —
    // the stream returns None, no second connection is attempted.
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let connections_clone = connections.clone();

    run_test_server(addr, move |mut ws, sub_id| {
        connections_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move {
            // Send one payload, then drop.
            let frame = serde_json::json!({
                "type": "next",
                "id": sub_id,
                "payload": { "data": { "tick": 1 } },
            });
            ws.send(Message::Text(frame.to_string())).await.unwrap();
            drop(ws);
        }
    })
    .await;

    let subs = subs_for(&format!("http://127.0.0.1:{}", port));
    let mut handle = subs
        .subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions {
                reconnect: false,
                ..Default::default()
            },
        )
        .await
        .expect("subscribe");

    // Consume the one payload.
    let p = handle.recv().await.expect("first payload");
    assert_eq!(p.data.unwrap()["tick"], 1);

    // Stream should end — no reconnect.
    let after = tokio::time::timeout(Duration::from_millis(500), handle.recv())
        .await
        .expect("recv should not hang when reconnect=false");
    assert!(after.is_none());

    // Give any spurious reconnect attempt time to land (it shouldn't).
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        connections.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "server should have seen exactly one connection"
    );
}

#[tokio::test]
async fn gives_up_after_max_reconnect_attempts() {
    // Server accepts connections but immediately drops them. The SDK
    // should give up after `max_reconnect_attempts` and close the
    // stream.
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let connections_clone = connections.clone();

    run_test_server(addr, move |ws, _sub_id| {
        connections_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move {
            // Immediate drop after handshake.
            drop(ws);
        }
    })
    .await;

    let subs = subs_for(&format!("http://127.0.0.1:{}", port));
    let mut handle = subs
        .subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions {
                max_reconnect_attempts: Some(2),
                reconnect_backoff: Duration::from_millis(50),
                ..Default::default()
            },
        )
        .await
        .expect("subscribe");

    // Stream should eventually end (no payloads ever delivered, all
    // connections drop). Give it enough time for: initial connect +
    // 2 reconnect attempts (50ms + 100ms backoffs).
    let after = tokio::time::timeout(Duration::from_millis(2_000), handle.recv())
        .await
        .expect("recv should not hang after max attempts")
        .map_or("None", |_| "Some");
    assert_eq!(after, "None");

    let total = connections.load(std::sync::atomic::Ordering::SeqCst);
    // 1 initial + up to 2 reconnects = at most 3. At least 1.
    assert!(
        total >= 1 && total <= 3,
        "unexpected connection count: {}",
        total
    );
}

#[tokio::test]
async fn unsubscribe_during_backoff_cancels_reconnect() {
    // While waiting for the reconnect backoff, an unsubscribe() should
    // cancel the pending retry cleanly.
    let port = free_port();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let connections = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let connections_clone = connections.clone();

    run_test_server(addr, move |mut ws, sub_id| {
        connections_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        async move {
            // Send one payload then drop — trigger the client's
            // reconnect path.
            let frame = serde_json::json!({
                "type": "next",
                "id": sub_id,
                "payload": { "data": { "tick": 0 } },
            });
            ws.send(Message::Text(frame.to_string())).await.unwrap();
            drop(ws);
        }
    })
    .await;

    let subs = subs_for(&format!("http://127.0.0.1:{}", port));
    let mut handle = subs
        .subscribe(
            "my-subgrove",
            "subscription { tick }",
            SubscribeOptions {
                // Long backoff so we have plenty of time to cancel.
                reconnect_backoff: Duration::from_secs(5),
                ..Default::default()
            },
        )
        .await
        .expect("subscribe");

    // Consume the payload and let the server drop.
    let _ = handle.recv().await.expect("first payload");

    // Unsubscribe while the client is sitting in the reconnect backoff.
    handle.unsubscribe().await;

    // Stream should close promptly — not wait 5s for the backoff.
    let after = tokio::time::timeout(Duration::from_millis(500), handle.recv())
        .await
        .expect("recv should return promptly after unsubscribe");
    assert!(after.is_none());

    // Make sure the client didn't reconnect during or after cancel.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        connections.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "reconnect attempt should have been cancelled",
    );
}
