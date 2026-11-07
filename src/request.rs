use http::HeaderMap;
use std::net::SocketAddr;

const MODEL_HEADERS: [(&str, &str); 11] = [
    ("user-agent", "user-agent"),
    ("referer", "referer"),
    ("host", "host"),
    ("origin", "origin"),
    ("cookie", "cookie"),
    ("content-type", "content-type"),
    ("accept", "accept"),
    ("accept-language", "accept-language"),
    ("accept-encoding", "accept-encoding"),
    ("dnt", "do-not-track"),
    ("connection", "connection"),
];

pub struct RequestFields {
    pub timestamp: String,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub headers: HeaderMap,
    pub body: String,
}

impl RequestFields {
    pub fn serialize(&self) -> String {
        let mut lines = Vec::new();
        let mut push = |name: &str, value: &str| {
            if !value.is_empty() {
                lines.push(format!("{name}: {value}"));
            }
        };
        push("timestamp", &self.timestamp);
        push("src-ip", &self.source.ip().to_string());
        push("src-port", &self.source.port().to_string());
        push("dst-ip", &self.destination.ip().to_string());
        push("dst-port", &self.destination.port().to_string());
        push("method", &self.method);
        push("path", &self.path);
        push("protocol", &self.protocol);
        for (header, label) in MODEL_HEADERS {
            let separator = if header == "cookie" { "; " } else { ", " };
            let value = self
                .headers
                .get_all(header)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join(separator);
            push(label, &value);
        }
        push("body", &self.body);
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::header::HOST;

    fn example() -> RequestFields {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "example.test".parse().unwrap());
        RequestFields {
            timestamp: "01/Jan/2026:00:00:00 +0000".into(),
            source: "127.0.0.1:1234".parse().unwrap(),
            destination: "127.0.0.1:8080".parse().unwrap(),
            method: "GET".into(),
            path: "/search?q=%27".into(),
            protocol: "HTTP/1.1".into(),
            headers,
            body: String::new(),
        }
    }

    #[test]
    fn serializes_request_in_training_order() {
        assert_eq!(
            example().serialize(),
            concat!(
                "timestamp: 01/Jan/2026:00:00:00 +0000\n",
                "src-ip: 127.0.0.1\n",
                "src-port: 1234\n",
                "dst-ip: 127.0.0.1\n",
                "dst-port: 8080\n",
                "method: GET\n",
                "path: /search?q=%27\n",
                "protocol: HTTP/1.1\n",
                "host: example.test"
            )
        );
    }

    #[test]
    fn serializes_model_headers_and_body_without_dropping_duplicates() {
        let mut request = example();
        request
            .headers
            .append("user-agent", "first".parse().unwrap());
        request
            .headers
            .append("user-agent", "second".parse().unwrap());
        request.headers.append("cookie", "a=1".parse().unwrap());
        request.headers.append("cookie", "b=2".parse().unwrap());
        request.headers.insert("dnt", "1".parse().unwrap());
        request.body = "name=José".into();
        let serialized = request.serialize();
        assert!(serialized.contains("user-agent: first, second\n"));
        assert!(serialized.contains("cookie: a=1; b=2\n"));
        assert!(serialized.contains("do-not-track: 1\nbody: name=José"));
        assert!(!serialized.contains("referer:"));
    }

    #[test]
    fn matches_original_project_sql_fixture_byte_for_byte() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "user-agent",
            "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"
                .parse()
                .unwrap(),
        );
        headers.insert("host", "test-site.com".parse().unwrap());
        let request = RequestFields {
            timestamp: "18/Jul/2020:05:26:36 +0200".into(),
            source: "172.26.0.1:57628".parse().unwrap(),
            destination: "172.26.0.4:80".parse().unwrap(),
            method: "GET".into(),
            path: "/blog/wp-content/uploads/2020/04/b476e717-efec-3b0d-80e9-13c6400a7702-300x240.png%27%3Bsleep+15%3B%27".into(),
            protocol: "HTTP/1.1".into(),
            headers,
            body: String::new(),
        };
        assert_eq!(
            request.serialize(),
            include_str!("../tests/fixtures/sql-injection.txt").trim_end_matches('\n')
        );
    }
}
