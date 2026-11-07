use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Request,
    http::StatusCode,
    response::Response,
};
use std::sync::{Arc, Mutex};
use threat_classifier_proxy::{
    model::{CategoryScore, ClassificationError, Classifier, NORMAL_LABEL, Verdict},
    proxy::{ProxyState, serve},
};
use tokio::net::TcpListener;

#[derive(Clone)]
struct FixedClassifier(bool);

impl Classifier for FixedClassifier {
    fn classify(&self, _: &str) -> Result<Verdict, ClassificationError> {
        Ok(Verdict {
            label: if self.0 {
                "66 - SQL Injection"
            } else {
                NORMAL_LABEL
            }
            .into(),
            score: 0.9,
            categories: std::iter::once(CategoryScore {
                category: NORMAL_LABEL.into(),
                score: 0.1,
            })
            .chain(std::iter::once(CategoryScore {
                category: "66 - SQL Injection".into(),
                score: 0.9,
            }))
            .chain((2..14).map(|index| CategoryScore {
                category: format!("Test category {index}"),
                score: 0.01,
            }))
            .collect(),
        })
    }
}

struct CapturingClassifier(Arc<Mutex<Vec<String>>>);

impl Classifier for CapturingClassifier {
    fn classify(&self, text: &str) -> Result<Verdict, ClassificationError> {
        self.0.lock().unwrap().push(text.to_owned());
        Ok(Verdict {
            label: NORMAL_LABEL.into(),
            score: 0.9,
            categories: vec![],
        })
    }
}

#[tokio::test]
async fn multipart_and_binary_reach_classifier_and_are_forwarded_unchanged() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let (proxy, seen) = start_with(Arc::new(CapturingClassifier(captured.clone())), 4).await;
    let client = reqwest::Client::new();
    let cases: Vec<(&str, Option<&str>, Vec<u8>)> = vec![
        (
            "multipart/form-data; boundary=x",
            None,
            b"--x\r\ncontent\r\n--x--".to_vec(),
        ),
        ("application/octet-stream", None, vec![0xff, 0x00, b'a']),
        ("text/plain", Some("gzip"), b"compressed payload".to_vec()),
    ];
    for (content_type, encoding, body) in &cases {
        let mut request = client
            .post(&proxy)
            .header("content-type", *content_type)
            .body(body.clone());
        if let Some(encoding) = encoding {
            request = request.header("content-encoding", *encoding);
        }
        assert_eq!(request.send().await.unwrap().status(), StatusCode::CREATED);
    }
    let records = seen.lock().unwrap();
    assert_eq!(records.len(), cases.len());
    for (record, (_, _, body)) in records.iter().zip(&cases) {
        assert_eq!(&record.body, body);
    }
    let inputs = captured.lock().unwrap();
    assert_eq!(inputs.len(), 3);
    assert!(inputs[0].contains("body: --x\r\ncontent\r\n--x--"));
    assert!(inputs[1].contains("body: \u{fffd}\0a"));
    assert!(inputs[2].contains("body: compressed payload"));
}

#[derive(Debug)]
struct Seen {
    method: String,
    path: String,
    body: Vec<u8>,
    host: String,
    hop_header: bool,
}

async fn start(attack: bool, _previous_limit: usize) -> (String, Arc<Mutex<Vec<Seen>>>) {
    start_with(Arc::new(FixedClassifier(attack)), _previous_limit).await
}

async fn start_with(
    classifier: Arc<dyn Classifier>,
    _previous_limit: usize,
) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let records = seen.clone();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let app = Router::new().fallback(move |request: Request| {
        let records = records.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = to_bytes(body, usize::MAX).await.unwrap();
            records.lock().unwrap().push(Seen {
                method: parts.method.to_string(),
                path: parts.uri.path_and_query().unwrap().to_string(),
                body: body.to_vec(),
                host: parts
                    .headers
                    .get("host")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string(),
                hop_header: parts.headers.contains_key("x-hop"),
            });
            Response::builder()
                .status(StatusCode::CREATED)
                .header("connection", "x-response-hop")
                .header("x-response-hop", "not-end-to-end")
                .header("x-kept", "yes")
                .body(Body::from("upstream response"))
                .unwrap()
        }
    });
    tokio::spawn(async move {
        axum::serve(upstream, app).await.unwrap();
    });

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = ProxyState::new(
        format!("http://{upstream_addr}").parse().unwrap(),
        classifier,
        1,
    )
    .unwrap();
    tokio::spawn(async move {
        serve(listener, state).await.unwrap();
    });
    (format!("http://{address}"), seen)
}

#[tokio::test]
async fn forwards_allowed_requests_and_preserves_upstream_response() {
    let (proxy, seen) = start(false, 1024).await;
    let response = reqwest::Client::new()
        .post(format!("{proxy}/path?x=%27"))
        .header("host", "example.test")
        .header("connection", "x-hop")
        .header("x-hop", "not-end-to-end")
        .header("content-type", "application/json")
        .body("{\"hello\":\"world\"}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers().get("x-kept").unwrap(), "yes");
    assert!(response.headers().get("x-response-hop").is_none());
    assert_eq!(response.text().await.unwrap(), "upstream response");
    let records = seen.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].method, "POST");
    assert_eq!(records[0].path, "/path?x=%27");
    assert_eq!(records[0].body, b"{\"hello\":\"world\"}");
    assert_eq!(records[0].host, "example.test");
    assert!(!records[0].hop_header);
}

#[tokio::test]
async fn blocks_detected_attacks_before_the_upstream() {
    let (proxy, seen) = start(true, 1024).await;
    let response = reqwest::get(format!("{proxy}/?id=%27%20OR%201%3D1"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response.headers()["content-type"], "application/json");
    let payload: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(payload["category"], "66 - SQL Injection");
    assert_eq!(payload["score"], 0.9_f32 as f64);
    assert_eq!(payload["categories"].as_array().unwrap().len(), 14);
    assert_eq!(payload["categories"][0]["category"], "000 - Normal");
    assert_eq!(payload["categories"][1]["category"], "66 - SQL Injection");
    assert_eq!(payload["categories"][1]["score"], 0.9_f32 as f64);
    assert!(seen.lock().unwrap().is_empty());
}

struct FailedClassifier;

impl Classifier for FailedClassifier {
    fn classify(&self, _: &str) -> Result<Verdict, ClassificationError> {
        Err(ClassificationError::Unavailable)
    }
}

#[tokio::test]
async fn forwards_bodies_larger_than_the_previous_limit() {
    let (proxy, seen) = start(false, 4).await;
    let client = reqwest::Client::new();
    let body = vec![b'a'; 1_048_577];
    let response = client.post(&proxy).body(body.clone()).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(seen.lock().unwrap()[0].body, body);
}

#[tokio::test]
async fn classifier_errors_never_reach_the_upstream() {
    let (proxy, seen) = start_with(Arc::new(FailedClassifier), 1024).await;
    let response = reqwest::get(&proxy).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unreachable_upstream_is_reported_as_bad_gateway() {
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = unused.local_addr().unwrap();
    drop(unused);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = ProxyState::new(
        format!("http://{upstream_addr}").parse().unwrap(),
        Arc::new(FixedClassifier(false)),
        1,
    )
    .unwrap();
    tokio::spawn(async move {
        serve(listener, state).await.unwrap();
    });
    let response = reqwest::get(format!("http://{address}/")).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn protocol_upgrades_are_rejected_without_forwarding() {
    let (proxy, seen) = start(false, 1024).await;
    let response = reqwest::Client::new()
        .get(proxy)
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn returns_upstream_redirect_without_following_it() {
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let app = Router::new().fallback(|| async {
        Response::builder()
            .status(StatusCode::FOUND)
            .header("location", "http://example.invalid/should-not-be-fetched")
            .body(Body::empty())
            .unwrap()
    });
    tokio::spawn(async move {
        axum::serve(upstream, app).await.unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = ProxyState::new(
        format!("http://{upstream_addr}").parse().unwrap(),
        Arc::new(FixedClassifier(false)),
        1,
    )
    .unwrap();
    tokio::spawn(async move {
        serve(listener, state).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = client
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()["location"],
        "http://example.invalid/should-not-be-fetched"
    );
}
