use anyhow::{Context, Result};
use hf_hub::{Repo, RepoType, api::sync::ApiBuilder};
use std::path::PathBuf;

const BACKBONE: &str = "onnx-community/embeddinggemma-300m-ONNX";
const BACKBONE_REVISION: &str = "5090578d9565bb06545b4552f76e6bc2c93e4a66";
const HEAD: &str = "valendra/threat-classifier-13082026";
const HEAD_REVISION: &str = "1308bba1f05b13e5f5e71b08f55e1486e0019bde";

pub struct Assets {
    pub graph: PathBuf,
    pub weights: PathBuf,
    pub tokenizer: PathBuf,
    pub head: PathBuf,
    pub metadata: PathBuf,
}

impl Assets {
    pub fn download(cache: Option<PathBuf>) -> Result<Self> {
        let mut builder = ApiBuilder::from_env().with_progress(false);
        if let Some(cache) = cache {
            builder = builder.with_cache_dir(cache);
        }
        if let Ok(token) = std::env::var("HF_TOKEN") {
            builder = builder.with_token(Some(token));
        }
        let api = builder
            .build()
            .context("initializing Hugging Face client")?;
        let backbone = api.repo(Repo::with_revision(
            BACKBONE.into(),
            RepoType::Model,
            BACKBONE_REVISION.into(),
        ));
        let head = api.repo(Repo::with_revision(
            HEAD.into(),
            RepoType::Model,
            HEAD_REVISION.into(),
        ));
        let graph = backbone
            .get("onnx/model.onnx")
            .context("downloading embedding model graph")?;
        let weights = backbone
            .get("onnx/model.onnx_data")
            .context("downloading embedding model weights")?;
        Ok(Self {
            graph,
            weights,
            tokenizer: backbone
                .get("tokenizer.json")
                .context("downloading tokenizer")?,
            head: head
                .get("model.safetensors")
                .context("downloading classifier head")?,
            metadata: head
                .get("meta.json")
                .context("downloading classifier metadata")?,
        })
    }
}

pub fn stage_graph(
    graph: &std::path::Path,
    weights: &std::path::Path,
) -> Result<tempfile::TempDir> {
    let directory = tempfile::Builder::new()
        .prefix("threat-classifier-model-")
        .tempdir()?;
    for (source, name) in [(graph, "model.onnx"), (weights, "model.onnx_data")] {
        let source = source
            .canonicalize()
            .context("resolving cached model file")?;
        let target = directory.path().join(name);
        if std::fs::hard_link(&source, &target).is_err() {
            std::fs::copy(&source, &target).context("staging model file for ONNX Runtime")?;
        }
    }
    Ok(directory)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn stages_external_data_inside_the_model_directory_even_for_cache_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source");
        let snapshot = root.path().join("snapshot");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&snapshot).unwrap();
        std::fs::write(source.join("graph"), b"graph").unwrap();
        std::fs::write(source.join("weights"), b"weights").unwrap();
        symlink(source.join("graph"), snapshot.join("model.onnx")).unwrap();
        symlink(source.join("weights"), snapshot.join("model.onnx_data")).unwrap();
        let stage = stage_graph(
            &snapshot.join("model.onnx"),
            &snapshot.join("model.onnx_data"),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(stage.path().join("model.onnx")).unwrap(),
            b"graph"
        );
        assert_eq!(
            std::fs::read(stage.path().join("model.onnx_data")).unwrap(),
            b"weights"
        );
        assert_eq!(
            stage
                .path()
                .join("model.onnx_data")
                .canonicalize()
                .unwrap()
                .parent()
                .unwrap(),
            stage.path().canonicalize().unwrap()
        );
    }

    #[test]
    #[ignore = "downloads the full pinned model into an empty cache"]
    fn downloads_pinned_artifacts_into_an_empty_cache() {
        let cache = tempfile::tempdir().unwrap();
        let assets = Assets::download(Some(cache.path().to_path_buf())).unwrap();
        assert_eq!(
            std::fs::metadata(assets.weights).unwrap().len(),
            1_234_521_088
        );
        assert!(assets.graph.exists());
        assert!(assets.tokenizer.exists());
        assert!(assets.head.exists());
        assert!(assets.metadata.exists());
    }
}
