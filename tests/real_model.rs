use axum::{Router, routing::any};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use threat_classifier_proxy::{
    model::{ClassificationError, Classifier, CpuClassifier, Verdict, assets::Assets},
    proxy::{ProxyState, serve},
};
use tokio::net::TcpListener;

struct RecordingClassifier {
    model: CpuClassifier,
    observations: Arc<Mutex<Vec<String>>>,
}

impl Classifier for RecordingClassifier {
    fn classify(&self, text: &str) -> Result<Verdict, ClassificationError> {
        let verdict = self.model.classify(text)?;
        let scores = self.model.labeled_scores(text)?;
        self.observations
            .lock()
            .unwrap()
            .push(format!("{text}\n{scores:?}"));
        Ok(verdict)
    }
}

async fn start_real_proxy() -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<String>>>) {
    let observations = Arc::new(Mutex::new(Vec::new()));
    let classifier = Arc::new(RecordingClassifier {
        model: CpuClassifier::load(&Assets::download(None).unwrap(), 1).unwrap(),
        observations: observations.clone(),
    });
    let count = Arc::new(AtomicUsize::new(0));
    let requests = count.clone();
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let app = Router::new().fallback(any(move || {
        let requests = requests.clone();
        async move {
            requests.fetch_add(1, Ordering::SeqCst);
            "upstream ok"
        }
    }));
    tokio::spawn(async move {
        axum::serve(upstream, app).await.unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let state = ProxyState::new(
        format!("http://{upstream_addr}").parse().unwrap(),
        classifier,
        1,
    )
    .unwrap();
    tokio::spawn(async move {
        serve(listener, state).await.unwrap();
    });
    (format!("http://{proxy_addr}"), count, observations)
}

#[tokio::test]
#[ignore = "downloads and loads the full CPU model"]
async fn cpu_model_forwards_normal_and_blocks_union_injection() {
    let (proxy, count, observations) = start_real_proxy().await;
    let client = reqwest::Client::new();
    let normal = client.get(format!("{proxy}/"))
        .header("host", "test-site.com")
        .header("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36")
        .header("accept", "*/*")
        .header("accept-encoding", "gzip, deflate")
        .send().await.unwrap();
    assert_eq!(normal.status(), 200);
    assert_eq!(normal.text().await.unwrap(), "upstream ok");
    let attack = client
        .get(format!("{proxy}/?id=1%27%20UNION%20SELECT%20NULL%2CNULL--"))
        .header("host", "test-site.com")
        .header(
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        attack.status(),
        401,
        "live model input and scores: {}",
        observations.lock().unwrap().last().unwrap()
    );
    let response: serde_json::Value =
        serde_json::from_slice(&attack.bytes().await.unwrap()).unwrap();
    let categories = response["categories"].as_array().unwrap();
    assert_eq!(categories.len(), 14);
    assert_eq!(categories[0]["category"], "000 - Normal");
    assert!(
        categories
            .iter()
            .any(|entry| entry["category"] == response["category"]
                && entry["score"] == response["score"])
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "known false negative in the published model with live metadata"]
async fn sql_sleep_fixture_should_be_blocked_with_live_metadata() {
    let (proxy, count, observations) = start_real_proxy().await;
    let attack = reqwest::Client::new().get(format!("{proxy}/blog/wp-content/uploads/2020/04/b476e717-efec-3b0d-80e9-13c6400a7702-300x240.png%27%3Bsleep+15%3B%27"))
        .header("host", "test-site.com")
        .header("user-agent", "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0")
        .send().await.unwrap();
    assert_eq!(
        attack.status(),
        401,
        "live model input and scores: {}",
        observations.lock().unwrap().last().unwrap()
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
}
