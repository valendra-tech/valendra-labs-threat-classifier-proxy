pub mod assets;
pub mod head;

use anyhow::{Context, Result};
use ort::{
    session::{Session, builder::AutoDevicePolicy},
    value::Tensor,
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use tokenizers::Tokenizer;

use self::head::Head;

pub const NORMAL_LABEL: &str = "000 - Normal";

#[derive(Debug, Clone)]
pub struct Verdict {
    pub label: String,
    pub score: f32,
    pub categories: Vec<CategoryScore>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CategoryScore {
    pub category: String,
    pub score: f32,
}

impl Verdict {
    pub fn is_attack(&self) -> bool {
        self.label != NORMAL_LABEL
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ClassificationError {
    Unavailable,
}

pub trait Classifier: Send + Sync {
    fn classify(&self, text: &str) -> Result<Verdict, ClassificationError>;
}

const PROMPT: &str = "task: classification | query: ";
const MAX_TOKENS: usize = 2048;

fn prepare_tokens(
    tokenizer: &tokenizers::Tokenizer,
    text: &str,
) -> Result<Vec<i64>, ClassificationError> {
    let encoding = tokenizer
        .encode(format!("{PROMPT}{text}"), true)
        .map_err(|_| ClassificationError::Unavailable)?;
    Ok(encoding.get_ids().iter().map(|id| i64::from(*id)).collect())
}

fn configure_tokenizer(tokenizer: &mut Tokenizer) -> Result<()> {
    tokenizer
        .with_truncation(Some(tokenizers::TruncationParams {
            max_length: MAX_TOKENS,
            ..Default::default()
        }))
        .map_err(|e| anyhow::anyhow!("configuring tokenizer truncation: {e}"))?;
    tokenizer.with_padding(None);
    Ok(())
}

pub struct CpuClassifier {
    tokenizer: Tokenizer,
    head: Head,
    sessions: Vec<Mutex<Session>>,
    next: AtomicUsize,
    _staged_graph: tempfile::TempDir,
}

impl CpuClassifier {
    pub fn load(assets: &assets::Assets, workers: usize) -> Result<Self> {
        anyhow::ensure!(workers > 0, "inference workers must be greater than zero");
        let mut tokenizer = Tokenizer::from_file(&assets.tokenizer)
            .map_err(|e| anyhow::anyhow!("loading tokenizer: {e}"))?;
        configure_tokenizer(&mut tokenizer)?;
        let head = Head::load(
            &std::fs::read(&assets.metadata)?,
            &std::fs::read(&assets.head)?,
        )
        .map_err(anyhow::Error::msg)
        .context("loading classifier head")?;
        let environment = ort::init().with_name("threat-classifier").build()?;
        let staged_graph = assets::stage_graph(&assets.graph, &assets.weights)?;
        let mut sessions = Vec::with_capacity(workers);
        for _ in 0..workers {
            let session = Session::builder(&environment)?
                .with_auto_device(AutoDevicePolicy::PreferCPU)
                .map_err(|e| anyhow::anyhow!("configuring CPU inference: {e}"))?
                .commit_from_file(staged_graph.path().join("model.onnx"))
                .context("loading ONNX embedding model")?;
            sessions.push(Mutex::new(session));
        }
        Ok(Self {
            tokenizer,
            head,
            sessions,
            next: AtomicUsize::new(0),
            _staged_graph: staged_graph,
        })
    }

    fn embedding(&self, text: &str) -> Result<Vec<f32>, ClassificationError> {
        let ids = prepare_tokens(&self.tokenizer, text)?;
        let len = ids.len();
        let input = Tensor::from_array(([1usize, len], ids))
            .map_err(|_| ClassificationError::Unavailable)?;
        let mask = Tensor::from_array(([1usize, len], vec![1i64; len]))
            .map_err(|_| ClassificationError::Unavailable)?;
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.sessions.len();
        let mut session = self.sessions[index]
            .lock()
            .map_err(|_| ClassificationError::Unavailable)?;
        let output = session
            .run(ort::inputs!["input_ids" => input, "attention_mask" => mask])
            .map_err(|_| ClassificationError::Unavailable)?;
        let value = output
            .get("sentence_embedding")
            .ok_or(ClassificationError::Unavailable)?;
        let (shape, values) = value
            .try_extract_tensor::<f32>()
            .map_err(|_| ClassificationError::Unavailable)?;
        if **shape != [1, 768] || values.iter().any(|value| !value.is_finite()) {
            return Err(ClassificationError::Unavailable);
        }
        Ok(values.to_vec())
    }

    pub fn labeled_scores(&self, text: &str) -> Result<Vec<(String, f32)>, ClassificationError> {
        self.head
            .labeled_scores(&self.embedding(text)?)
            .map_err(|_| ClassificationError::Unavailable)
    }
}

impl Classifier for CpuClassifier {
    fn classify(&self, text: &str) -> Result<Verdict, ClassificationError> {
        self.head
            .verdict(&self.embedding(text)?)
            .map_err(|_| ClassificationError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenizers::{
        Tokenizer, models::wordlevel::WordLevel, pre_tokenizers::whitespace::WhitespaceSplit,
        processors::template::TemplateProcessing,
    };

    #[test]
    fn token_limit_includes_prompt_and_special_tokens_with_truncation() {
        let vocab = [("[UNK]", 0), ("[BOS]", 1), ("[EOS]", 2), ("x", 3)]
            .into_iter()
            .map(|(word, id)| (word.to_string(), id))
            .collect();
        let model = WordLevel::builder()
            .vocab(vocab)
            .unk_token("[UNK]".into())
            .build()
            .unwrap();
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_pre_tokenizer(Some(WhitespaceSplit));
        tokenizer.with_post_processor(Some(
            TemplateProcessing::builder()
                .try_single("[BOS] $A [EOS]")
                .unwrap()
                .special_tokens(vec![("[BOS]", 1), ("[EOS]", 2)])
                .build()
                .unwrap(),
        ));
        configure_tokenizer(&mut tokenizer).unwrap();
        let base = tokenizer.encode(PROMPT, true).unwrap().len();
        let permitted = "x ".repeat(MAX_TOKENS - base);
        assert_eq!(
            prepare_tokens(&tokenizer, &permitted).unwrap().len(),
            MAX_TOKENS
        );
        let too_long = "x ".repeat(MAX_TOKENS - base + 1);
        let truncated = prepare_tokens(&tokenizer, &too_long).unwrap();
        assert_eq!(truncated.len(), MAX_TOKENS);
        assert_eq!(truncated.last(), Some(&2));
    }

    #[test]
    #[ignore = "uses the pinned Hugging Face tokenizer"]
    fn truncated_token_ids_match_python_reference() {
        use sha2::{Digest, Sha256};
        let assets = assets::Assets::download(None).unwrap();
        let mut tokenizer = Tokenizer::from_file(assets.tokenizer).unwrap();
        configure_tokenizer(&mut tokenizer).unwrap();
        let ids = prepare_tokens(&tokenizer, &"hello ".repeat(2050)).unwrap();
        assert_eq!(ids.len(), 2048);
        assert_eq!(ids[0], 2);
        assert_eq!(ids[2047], 1);
        let joined = ids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            format!("{:x}", Sha256::digest(joined.as_bytes())),
            "ac68a30515805bfa528e3bb4784dcb99520a451c3818e2785d32e009bacd42a8"
        );
    }

    #[test]
    #[ignore = "downloads and loads the full CPU model"]
    fn real_model_classifies_reference_examples_on_cpu() {
        use sha2::{Digest, Sha256};
        let assets = assets::Assets::download(None).unwrap();
        let model = CpuClassifier::load(&assets, 1).unwrap();
        // Baselines come from the source project's 68294f0 revision using
        // SentenceTransformers 5.7.0 and PyTorch 2.13.0 on CPU, with the
        // pinned original EmbeddingGemma revision and published head.
        for (name, input, attack, token_count, expected_hash, reference) in [
            (
                "normal",
                include_str!("../../tests/fixtures/normal.txt"),
                false,
                191,
                "8cd3622f089c5122db362b28b7304b2575a7fb5cf7ac20094054928d547edb7d",
                [
                    0.99932563,
                    0.000773704,
                    0.001360634,
                    0.000308428,
                    0.000332515,
                    0.000182269,
                    0.0000018664,
                    0.0000758925,
                    0.000037261,
                    0.0000102609,
                    0.0000396373,
                    0.001046261,
                    0.001146048,
                    0.0000087304,
                ],
            ),
            (
                "sql",
                include_str!("../../tests/fixtures/sql-injection.txt"),
                true,
                231,
                "3479e95d084990d71e090c8ed79ae3d577c6c66b6bbfd76fd5eba47b6c913438",
                [
                    0.12734951,
                    0.023239223,
                    0.017461324,
                    0.008580179,
                    0.011405901,
                    0.88347644,
                    0.0000045048,
                    0.000460484,
                    0.0000273163,
                    0.0000111597,
                    0.0000751587,
                    0.000306741,
                    0.24718949,
                    0.0000534244,
                ],
            ),
        ] {
            let ids = prepare_tokens(&model.tokenizer, input.trim_end_matches('\n')).unwrap();
            let token_string = ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            assert_eq!(ids.len(), token_count);
            assert_eq!(
                format!("{:x}", Sha256::digest(token_string.as_bytes())),
                expected_hash,
                "token ids differ from the original tokenizer"
            );
            let scores = model.labeled_scores(input.trim_end_matches('\n')).unwrap();
            let best = scores
                .iter()
                .max_by(|left, right| left.1.total_cmp(&right.1))
                .unwrap();
            let max_difference = scores
                .iter()
                .zip(reference)
                .map(|((_, actual), expected)| (actual - expected).abs())
                .fold(0f32, f32::max);
            println!("{name}: max score difference vs Python = {max_difference:.8}; {scores:?}");
            assert!(
                max_difference < 0.01,
                "ONNX scores differ from the original CPU implementation"
            );
            assert_eq!(
                best.0 != NORMAL_LABEL,
                attack,
                "unexpected winner: {best:?}"
            );
        }
    }
}
