# Threat Classifier Proxy

An HTTP reverse-proxy proof of concept written in Rust. It runs Valendra's
[threat classifier](https://huggingface.co/valendra/threat-classifier-13082026)
on the CPU before forwarding a request to a configured upstream application.
When the highest-scoring class is an attack, the proxy returns **HTTP 401** and
does not contact the upstream. Otherwise, it forwards the request and returns the
upstream's status and response.

**This model has observed false negatives with live request metadata.** The PoC
shows what the model detects; it does not establish that an allowed request is
safe. See [Measured limitations](#measured-limitations) before using it to
protect real traffic.

## How inference works

The published Valendra model is a classification head, not a standalone
backbone. The proxy loads both components once at startup:

| Component | Source | Pinned revision |
| --- | --- | --- |
| EmbeddingGemma 300M, full-precision ONNX | [`onnx-community/embeddinggemma-300m-ONNX`](https://huggingface.co/onnx-community/embeddinggemma-300m-ONNX) | `5090578d9565bb06545b4552f76e6bc2c93e4a66` |
| Valendra linear head and label metadata | [`valendra/threat-classifier-13082026`](https://huggingface.co/valendra/threat-classifier-13082026) | `1308bba1f05b13e5f5e71b08f55e1486e0019bde` |

The ONNX graph runs locally through ONNX Runtime's CPU execution provider. It
produces a 768-dimensional embedding, then the Rust code applies the published
14-class linear head and sigmoid scores. `000 - Normal` permits forwarding;
any other winning class blocks the request. Scores are independent, are not
calibrated probabilities, and do not add up to one. The argmax rule is the
reference project's single-label evaluation convention, not a validated
multilabel blocking policy.

Each request is converted to the same newline-separated `field: value` format
and field order used by the [training project](https://github.com/valendra-tech/valendra-labs-threat-classifier).
The exact prefix is `task: classification | query: `. Empty fields are
omitted. The fields are:

```text
timestamp, src-ip, src-port, dst-ip, dst-port, method, path, protocol,
user-agent, referer, host, origin, cookie, content-type, accept,
accept-language, accept-encoding, do-not-track, connection, body
```

The path includes the original query string and percent encoding. Socket
addresses come from the direct connection, not from `X-Forwarded-For`.
Other headers, including `Authorization`, are forwarded when allowed but are
not model inputs. Response fields and raw HTTP framing are not inspected.

There are no manual attack-blocking rules or configured body-size limits.
Requests are buffered in memory. Multipart, binary and compressed bodies are
passed to the classifier; non-UTF-8 bytes are represented using UTF-8
replacement characters, and compressed bodies are not decompressed. Original
bytes are forwarded unchanged after a Normal decision.

The tokenizer right-truncates model input to **2,048 tokens**, including prompt
and special tokens, matching the source project's inference. The remainder is
not analyzed, even though the entire original request is forwarded if the model
allows it. This is a local PoC, not a production security boundary.

## Requirements

- Rust and Cargo, plus network access for the initial build and model download.
- A CPU with enough memory for EmbeddingGemma and ONNX Runtime. The ONNX
  weights alone require approximately **1.23 GB** of download and disk space.
  Each additional inference worker loads another model session.
- The backbone is subject to the [Gemma terms](https://ai.google.dev/gemma/terms).
  The ONNX conversion is public; Hugging Face credentials may be supplied via
  `HF_TOKEN` or the normal Hugging Face login when needed. The classifier head
  is MIT licensed.

Model files are cached using the Hugging Face cache. ONNX Runtime also stages
the graph and weights in a private temporary directory; it uses hard links when
possible and copies the files if the cache and temporary directory are on
different filesystems. No GPU or Python inference service is required.
The proxy handles Ctrl-C and SIGTERM gracefully and removes the staged files
after active requests finish.

## Run locally

Start a simple HTTP upstream in one terminal:

```bash
python3 -m http.server 9000 --bind 127.0.0.1
```

In another terminal, from this repository:

```bash
export UPSTREAM_URL=http://127.0.0.1:9000
cargo run --release
```

The proxy listens on `127.0.0.1:8080` after it has downloaded and loaded the
model. From a third terminal, send an ordinary request:

```bash
curl -i -H 'Host: test-site.com' \
  -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36' \
  'http://127.0.0.1:8080/'
```

The local upstream returns `200` if the model permits the request. The
following SQL-injection example was blocked with `401` in the live CPU test:

```bash
curl --path-as-is -i -H 'Host: test-site.com' \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0' \
  'http://127.0.0.1:8080/?id=1%27%20UNION%20SELECT%20NULL%2CNULL--'
```

Predictions can change with request headers, timestamps, addresses, or other
input fields. Logs contain the selected class, score, and elapsed inference
time, not the request body, cookie, query string, or credentials.

### Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `UPSTREAM_URL` | required | HTTP(S) origin, e.g. `http://127.0.0.1:9000`; no base path or query |
| `LISTEN_ADDR` | `127.0.0.1:8080` | HTTP listen address |
| `MODEL_CACHE_DIR` | Hugging Face cache | Override the Hugging Face model-cache directory |
| `INFERENCE_WORKERS` | `1` | Number of loaded CPU sessions and concurrent classifications |
| `HF_TOKEN` | existing Hugging Face login | Optional Hugging Face access token |
| `RUST_LOG` | `warn,threat_classifier_proxy=info` | Log filter |

For another machine to reach the proxy, set `LISTEN_ADDR=0.0.0.0:8080`.
Upstream responses are streamed back without following redirects. Hop-by-hop
headers are removed in both directions.

### HTTP responses

| Status | Meaning |
| --- | --- |
| Upstream status | The winning class was `000 - Normal`; the upstream processed the request |
| `401` | The model's highest-scoring class was an attack |
| `400` | The HTTP request could not be parsed or its body could not be read |
| `501` | CONNECT and protocol upgrades are not supported |
| `502` | The upstream connection failed |
| `503` | Classification could not be completed |

The model is loaded before the listener starts. A model download or startup
failure terminates the process instead of forwarding unclassified traffic.

A `401` response includes the winning category and all 14 independent model
scores in the label order from the head metadata:

```json
{
  "category": "66 - SQL Injection",
  "score": 0.91,
  "categories": [
    { "category": "000 - Normal", "score": 0.02 },
    { "category": "66 - SQL Injection", "score": 0.91 }
  ]
}
```

The example shows only two entries for brevity; an actual response contains all
14. Scores are independent sigmoid outputs, not calibrated probabilities.

## Measured limitations

On the reference SQL-injection fixture, Rust serialization matched the source
project byte for byte and the tokenizer produced the exact same token IDs as
the original Python tokenizer. With the original 2020 timestamp and fixture
addresses, the original Python implementation scored SQL Injection **0.8835**
and Normal **0.1273**. Rust/ONNX scored **0.8804** and **0.1326**, respectively;
both selected SQL Injection. The largest absolute score difference across the
14 classes in these two reference fixtures was about **0.0053**.
The comparison used source-project revision `68294f0`, the original
EmbeddingGemma revision `57c266a740f537b4dc058e1b0cda161fd15afa75`,
SentenceTransformers 5.7.0, and PyTorch 2.13.0 on CPU. The ignored reference
test checks the token IDs and all scores with a `0.01` absolute tolerance.

When the same encoded `sleep` payload was sent as a real HTTP request using the
actual 2026 timestamp and local socket addresses, the model selected Normal
(approximately **0.89** versus **0.10** for SQL Injection), and the proxy
returned **200** from the upstream. The original Python model also selected
Normal when given the corresponding live metadata. The ignored test
`sql_sleep_fixture_should_be_blocked_with_live_metadata` preserves this known
failure. A separate `UNION SELECT` request was detected and blocked with `401`.
These individual observations are not a representative performance benchmark.

One local run on an Apple M5 with cached models took about 2.8 seconds to start;
the normal, `UNION SELECT`, and `sleep` requests took approximately 81 ms,
54 ms, and 65 ms end to end, respectively. These figures are illustrative,
not a throughput or latency benchmark.

The model may miss attacks in both trained and untrained fields, and it can
block legitimate traffic. Validate it against representative traffic and
calibrate the policy before considering deployment alongside other controls.

## PHP CVE replay

`tests/cve_probe.py` replays published request shapes from recent PHP and
PHP-application advisories through the proxy to an inert loopback upstream. It
does **not** target a vulnerable application: the HTTP status is the proxy's
decision, not proof of exploitation. Run it with cached models after a release
build:

```bash
cargo build --release
python3 tests/cve_probe.py
```

| Advisory | Probe | Result | Explanation |
| --- | --- | --- | --- |
| [CVE-2026-6735](https://github.com/php/php-src/security/advisories/GHSA-7qg2-v9fj-4mwv) | Raw `/<script>alert()</script>` URI | `400` | Rejected by the HTTP parser before classification; not a model decision |
| CVE-2026-6735 | Percent-encoded variant | Allowed | XSS is not one of the model's 14 CAPEC classes |
| CVE-2026-6735 | `GET /status?full&html` | Allowed | The reflected URI is in FPM state, not this request |
| [CVE-2026-62858](https://github.com/YOURLS/YOURLS/security/advisories/GHSA-f8ff-652m-j5rx) | `GET /../../test` | Allowed, Normal ~0.98-0.99 | Path traversal missed even though the path was preserved and inspected |
| [CVE-2026-33944](https://github.com/Dolibarr/dolibarr/security/advisories/GHSA-v5fq-cf5m-vwv7) | Authenticated POST `lt1=1,note_private=(SELECT ...)` | Allowed, Normal ~0.55-0.65 | Numeric-context SQL injection in the body missed; Normal score did drop versus the control request |
| [CVE-2026-91765](https://github.com/php/php-src/security/advisories/GHSA-rgrp-mwpx-f6rm) | 50,000-level SOAP XML, 350,150 bytes | `401` | The model classified the truncated prefix as Code Injection |
| [CVE-2026-108082](https://github.com/symfony/symfony/security/advisories/GHSA-r925-mgvr-h9cc) | `Cache-Control: a` + 25 spaces + `,b` | Allowed, Normal ~0.99 | `Cache-Control` is not one of the 20 model input fields, so it is never inspected |
| [INCIBE-2026-762](https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-php) / [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | Synthetic multipart with 400 part headers, 40 empty file controls and nested names | `401`, Code Injection 0.962 | Model decision on the truncated prefix; upstream not reached |
| CVE-2026-109618 | Same synthetic multipart, chunked without `Content-Length` | `401`, Code Injection 0.965 | Model decision on the truncated prefix; upstream not reached |
| [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) / CVE-2026-115560 | Chunked multipart with `PHP_SESSION_UPLOAD_PROGRESS` and a session cookie | `401`, HTTP Request Smuggling 0.607 | Model decision for this request shape; a stateful producer/consumer sequence was not tested |
| CVE-2026-109618 control | Benign multipart file upload | `200`, Normal 0.791 | Forwarded unchanged |

These are individual measurements, not validated detection rates. Scores vary
with timestamps and socket ports; the model's winning attack label need not
match the CVE. The raw `<script>` rejection is an HTTP parser outcome, not a
model detection. A per-request classifier cannot establish whether a stateful
multi-request PHP exploit succeeds. Update PHP and apply the vendor's controls.

### Model-only replay

To separate model decisions from proxy policies, `examples/classify_cve.rs`
serializes each request exactly as the proxy does and sends it directly to the
classifier, bypassing the HTTP parser. The same 2,048-token truncation applies:

```bash
cargo run --release --example classify_cve
```

Results with a fixed 21/Oct/2026 timestamp, `172.26.0.1:40000` to
`172.26.0.4:80`, the Firefox 70 user agent, and `host: test-site.com`:

| Case | Model winner | Model decision |
| --- | --- | --- |
| Normal GET | `000 - Normal` 0.970 | Allow |
| CVE-2026-6735 raw `<script>` path | `000 - Normal` 0.949 | Allow; XSS is not a class |
| CVE-2026-62858 `GET /../../test` | `000 - Normal` 0.934 | Allow; traversal missed |
| CVE-2026-33944 Dolibarr POST SQLi | `000 - Normal` 0.406 | Allow; OS Command Injection 0.395, Protocol Manipulation 0.364, SQL Injection 0.204 |
| CVE-2026-108082 `Cache-Control` ReDoS | `000 - Normal` 0.970 | Identical to control; `Cache-Control` is not serialized |
| CVE-2026-91765 SOAP, 700 levels | `242 - Code Injection` 0.987 | Block |
| CVE-2026-91765 SOAP, exact 50,000 levels | `242 - Code Injection` 0.998 | Block after truncation to 2,048 tokens |
| CVE-2026-109618 multipart, compact 60 headers + 10 empty files | `126 - Path Traversal` 0.663 | Block, but fragile: HTTP Request Smuggling 0.619, Code Injection 0.496, OS Command Injection 0.478 |
| CVE-2026-109618 synthetic multipart, 400 headers + 40 empty files | `242 - Code Injection` 0.841 | Block after truncation to 2,048 tokens |
| CVE-2026-109619 / CVE-2026-115560 upload progress | `66 - SQL Injection` 0.499 | Block; Protocol Manipulation 0.413, Normal 0.301 |
| Benign multipart upload | `000 - Normal` 0.768 | Allow |

The reference `predict` implementation also truncates to 2,048 tokens. In a
separate run without an `Accept` header, it selected SQL Injection at 0.995
for SOAP and Code Injection at 0.979 for the synthetic multipart request.
Those differing request inputs are not a score-parity comparison.

Two conclusions matter. First, the model does detect some memory-corruption and
parser attack shapes, but the winning labels (SQL Injection, Code Injection,
Path Traversal) are incidental and unstable; several classes score within a few
points of each other. Second, XSS, the short traversal, the numeric-context
Dolibarr SQL injection, and the header-only ReDoS are not detected by this model
at all. The results need representative validation.

## Tests

The default suite tests serialization, the classifier head, model-only routing,
and real HTTP forwarding with a deterministic classifier. It does not download
the large model:

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Run the CPU model checks explicitly; the first run may download the models:

```bash
cargo test model::tests::real_model_classifies_reference_examples_on_cpu -- --ignored --nocapture
cargo test --test real_model cpu_model_forwards_normal_and_blocks_union_injection -- --ignored --nocapture
```

To reproduce the known false negative, run the following test. It currently
**fails** because it asserts that the `sleep` request should be blocked:

```bash
cargo test --test real_model sql_sleep_fixture_should_be_blocked_with_live_metadata -- --ignored --nocapture
```
