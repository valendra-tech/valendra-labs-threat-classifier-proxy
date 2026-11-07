use std::{net::SocketAddr, path::PathBuf};

pub struct Config {
    pub listen: SocketAddr,
    pub upstream: http::Uri,
    pub model_cache: Option<PathBuf>,
    pub workers: usize,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::parse(|name| std::env::var(name).ok())
    }

    fn parse(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        use anyhow::Context;
        let listen = get("LISTEN_ADDR")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .context("invalid LISTEN_ADDR")?;
        let upstream = get("UPSTREAM_URL")
            .context("UPSTREAM_URL is required")?
            .parse()
            .context("invalid UPSTREAM_URL")?;
        crate::proxy::validate_upstream(&upstream)?;
        let workers: usize = get("INFERENCE_WORKERS")
            .unwrap_or_else(|| "1".into())
            .parse()
            .context("invalid INFERENCE_WORKERS")?;
        anyhow::ensure!(workers > 0, "worker count must be positive");
        let model_cache = get("MODEL_CACHE_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Ok(Self {
            listen,
            upstream,
            model_cache,
            workers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn parse(values: &[(&str, &str)]) -> anyhow::Result<Config> {
        let values: HashMap<_, _> = values.iter().copied().collect();
        Config::parse(|name| values.get(name).map(|value| (*value).to_string()))
    }

    #[test]
    fn requires_upstream_and_sets_sensible_defaults() {
        assert!(parse(&[]).is_err());
        let config = parse(&[("UPSTREAM_URL", "http://127.0.0.1:3000")]).unwrap();
        assert_eq!(config.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(config.workers, 1);
        assert!(config.model_cache.is_none());
    }

    #[test]
    fn rejects_invalid_addresses_and_zero_limits() {
        for values in [
            vec![
                ("UPSTREAM_URL", "http://example.test"),
                ("LISTEN_ADDR", "no"),
            ],
            vec![
                ("UPSTREAM_URL", "http://example.test"),
                ("INFERENCE_WORKERS", "0"),
            ],
            vec![
                ("UPSTREAM_URL", "http://example.test"),
                ("INFERENCE_WORKERS", "no"),
            ],
            vec![("UPSTREAM_URL", "ftp://example.test")],
            vec![("UPSTREAM_URL", "http://example.test/base")],
            vec![("UPSTREAM_URL", "http://user:pass@example.test")],
            vec![("UPSTREAM_URL", "http://example.test?secret=1")],
        ] {
            assert!(parse(&values).is_err());
        }
    }
}
