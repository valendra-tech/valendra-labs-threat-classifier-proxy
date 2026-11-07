//! Model-only replay of CVE request shapes, bypassing all proxy policies.
//!
//! Run with: cargo run --release --example classify_cve
//!
//! Each case is serialized exactly as the proxy would serialize it, then sent
//! directly to the classifier. The tokenizer truncates to 2,048 tokens as in
//! the source project's inference pipeline.

use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};
use threat_classifier_proxy::{
    model::{ClassificationError, CpuClassifier, NORMAL_LABEL, assets::Assets},
    request::RequestFields,
};

const TIMESTAMP: &str = "21/Oct/2026:12:00:00 +0000";
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0";
const HOST: &str = "test-site.com";

fn request(method: &str, path: &str, body: String, extra: &[(&str, &str)]) -> RequestFields {
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", HeaderValue::from_static(USER_AGENT));
    headers.insert("host", HeaderValue::from_static(HOST));
    headers.insert("accept", HeaderValue::from_static("*/*"));
    for (name, value) in extra {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
            HeaderValue::from_str(value).expect("valid header value"),
        );
    }
    RequestFields {
        timestamp: TIMESTAMP.into(),
        source: "172.26.0.1:40000".parse().expect("valid source address"),
        destination: "172.26.0.4:80".parse().expect("valid destination address"),
        method: method.into(),
        path: path.into(),
        protocol: "HTTP/1.1".into(),
        headers,
        body,
    }
}

fn multipart_part(boundary: &str, headers: &[String], payload: &str) -> String {
    format!(
        "--{boundary}\r\n{}\r\n\r\n{payload}\r\n",
        headers.join("\r\n")
    )
}

fn multipart_close(boundary: &str) -> String {
    format!("--{boundary}--\r\n")
}

fn oom_multipart(header_count: usize, empty_files: usize) -> (String, String) {
    let boundary = "----model-109618";
    let mut headers = vec!["Content-Disposition: form-data; name=\"a[b][c][d]\"".to_string()];
    for index in 0..header_count {
        headers.push(format!("X-Probe-{index}: {}", "A".repeat(32)));
    }
    let mut parts = vec![multipart_part(boundary, &headers, "x")];
    for index in 0..empty_files {
        parts.push(multipart_part(
            boundary,
            &[
                format!("Content-Disposition: form-data; name=\"f{index}\"; filename=\"\""),
                "Content-Type: application/octet-stream".to_string(),
            ],
            "",
        ));
    }
    parts.push(multipart_close(boundary));
    (parts.concat(), boundary.to_string())
}

fn upload_progress_multipart() -> (String, String) {
    let boundary = "----model-109619";
    let body = [
        multipart_part(
            boundary,
            &["Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"".to_string()],
            "probe",
        ),
        multipart_part(
            boundary,
            &[
                "Content-Disposition: form-data; name=\"file\"; filename=\"probe.txt\"".to_string(),
                "Content-Type: text/plain".to_string(),
            ],
            "probe",
        ),
        multipart_close(boundary),
    ]
    .concat();
    (body, boundary.to_string())
}

fn benign_multipart() -> (String, String) {
    let boundary = "----model-benign";
    let body = [
        multipart_part(
            boundary,
            &[
                "Content-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"".to_string(),
                "Content-Type: text/plain".to_string(),
            ],
            "hello",
        ),
        multipart_close(boundary),
    ]
    .concat();
    (body, boundary.to_string())
}

fn soap(depth: usize) -> String {
    let nested = "<a>".repeat(depth) + &"</a>".repeat(depth);
    format!(
        "<?xml version=\"1.0\"?><SOAP-ENV:Envelope \
         xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">\
         <SOAP-ENV:Body>{nested}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )
}

fn multipart_request(
    path: &str,
    body: String,
    boundary: &str,
    extra: &[(&str, &str)],
) -> RequestFields {
    let content_type = format!("multipart/form-data; boundary={boundary}");
    let mut headers = vec![("content-type", content_type.as_str())];
    headers.extend_from_slice(extra);
    request("POST", path, body, &headers)
}

fn classify(model: &CpuClassifier, name: &str, request: &RequestFields, note: &str) -> Value {
    let text = request.serialize();
    match model.labeled_scores(&text) {
        Ok(scores) => {
            let mut best = 0;
            for index in 1..scores.len() {
                if scores[index].1 > scores[best].1 {
                    best = index;
                }
            }
            let (label, score) = &scores[best];
            json!({
                "case": name,
                "status": "classified",
                "winner": label,
                "score": score,
                "attack": label != NORMAL_LABEL,
                "note": note,
                "scores": scores
                    .iter()
                    .map(|(label, score)| json!({"label": label, "score": score}))
                    .collect::<Vec<_>>(),
            })
        }
        Err(ClassificationError::Unavailable) => json!({
            "case": name,
            "status": "unavailable",
            "note": note,
        }),
    }
}

fn main() -> anyhow::Result<()> {
    let assets = Assets::download(None)?;
    let model = CpuClassifier::load(&assets, 1)?;

    let form = "action=update&token=CSRF_TOKEN&socid=1&name=TestCompany&status=1\
                &localtax1assuj_value=1\
                &lt1=1%2Cnote_private%3D%28SELECT+pass_crypted+FROM+llx_user+WHERE+rowid%3D1%29\
                &client=1&typent_id=0";
    let (oom_compact, oom_compact_boundary) = oom_multipart(60, 10);
    let (oom_exact, oom_exact_boundary) = oom_multipart(400, 40);
    let (upload_body, upload_boundary) = upload_progress_multipart();
    let (benign_body, benign_boundary) = benign_multipart();

    let cases = vec![
        (
            "normal-get",
            request("GET", "/", String::new(), &[]),
            "baseline",
        ),
        (
            "php-fpm-xss-raw-path",
            request("GET", "/<script>alert()</script>", String::new(), &[]),
            "CVE-2026-6735; HTTP parser would reject this URI",
        ),
        (
            "yourls-path-traversal",
            request("GET", "/../../test", String::new(), &[]),
            "CVE-2026-62858",
        ),
        (
            "dolibarr-post-sqli",
            request(
                "POST",
                "/societe/card.php?socid=1",
                form.to_string(),
                &[
                    ("content-type", "application/x-www-form-urlencoded"),
                    ("cookie", "PHPSESSID=local-test-session"),
                ],
            ),
            "CVE-2026-33944",
        ),
        (
            "symfony-redos-control",
            request("GET", "/", String::new(), &[("cache-control", "a,b")]),
            "CVE-2026-108082 control; Cache-Control is not serialized",
        ),
        (
            "symfony-redos-attack",
            request(
                "GET",
                "/",
                String::new(),
                &[("cache-control", &format!("a{},b", " ".repeat(25)))],
            ),
            "CVE-2026-108082; same model input as control",
        ),
        (
            "soap-50000-levels",
            request(
                "POST",
                "/soap-endpoint.php",
                soap(50_000),
                &[("content-type", "text/xml")],
            ),
            "CVE-2026-91765 exact PoC; input is truncated to 2048 tokens",
        ),
        (
            "soap-700-levels",
            request(
                "POST",
                "/soap-endpoint.php",
                soap(700),
                &[("content-type", "text/xml")],
            ),
            "CVE-2026-91765 compact variant within the model window",
        ),
        (
            "multipart-benign",
            multipart_request(
                "/upload.php",
                benign_body,
                &benign_boundary,
                &[("cookie", "PHPSESSID=local-test-session")],
            ),
            "benign multipart upload",
        ),
        (
            "php109618-compact",
            multipart_request(
                "/index.php",
                oom_compact,
                &oom_compact_boundary,
                &[("cookie", "PHPSESSID=local-test-session")],
            ),
            "CVE-2026-109618 compact shape within the model window",
        ),
        (
            "php109618-exact",
            multipart_request(
                "/index.php",
                oom_exact,
                &oom_exact_boundary,
                &[("cookie", "PHPSESSID=local-test-session")],
            ),
            "CVE-2026-109618 synthetic 400-header shape; input is truncated to 2048 tokens",
        ),
        (
            "php109619-upload-progress",
            multipart_request(
                "/upload.php",
                upload_body,
                &upload_boundary,
                &[("cookie", "PHPSESSID=local-test-session")],
            ),
            "CVE-2026-109619 / CVE-2026-115560 upload-progress shape",
        ),
    ];

    for (name, request, note) in cases {
        println!("{}", classify(&model, name, &request, note));
    }
    Ok(())
}
