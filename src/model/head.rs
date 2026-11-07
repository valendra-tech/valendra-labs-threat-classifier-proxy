use super::{CategoryScore, NORMAL_LABEL, Verdict};
use std::collections::HashSet;

pub struct Head {
    labels: Vec<String>,
    dimension: usize,
    weights: Vec<f32>,
    bias: Vec<f32>,
}

impl Head {
    pub fn load(metadata: &[u8], tensors: &[u8]) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        struct Metadata {
            labels: Vec<String>,
            embedding_dim: usize,
            hidden: Option<usize>,
        }
        let metadata: Metadata = serde_json::from_slice(metadata).map_err(|e| e.to_string())?;
        if metadata.embedding_dim != 768 || metadata.labels.len() != 14 || metadata.hidden.is_some()
        {
            return Err("unsupported classifier metadata".into());
        }
        let tensors = safetensors::SafeTensors::deserialize(tensors).map_err(|e| e.to_string())?;
        let weight = tensors
            .tensor("head.head.weight")
            .map_err(|e| e.to_string())?;
        let bias = tensors
            .tensor("head.head.bias")
            .map_err(|e| e.to_string())?;
        if weight.dtype() != safetensors::Dtype::F32
            || bias.dtype() != safetensors::Dtype::F32
            || weight.shape() != [14, 768]
            || bias.shape() != [14]
        {
            return Err("unsupported classifier tensor dimensions or dtype".into());
        }
        let floats = |bytes: &[u8]| {
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| f32::from_le_bytes(*chunk))
                .collect()
        };
        Self::from_parts(
            metadata.labels,
            metadata.embedding_dim,
            floats(weight.data()),
            floats(bias.data()),
        )
    }
    pub fn from_parts(
        labels: Vec<String>,
        dimension: usize,
        weights: Vec<f32>,
        bias: Vec<f32>,
    ) -> Result<Self, String> {
        let unique: HashSet<_> = labels.iter().collect();
        if dimension == 0
            || labels.is_empty()
            || unique.len() != labels.len()
            || labels
                .iter()
                .filter(|label| label.as_str() == NORMAL_LABEL)
                .count()
                != 1
            || labels.iter().any(String::is_empty)
            || dimension.checked_mul(labels.len()) != Some(weights.len())
            || bias.len() != labels.len()
            || weights.iter().chain(&bias).any(|value| !value.is_finite())
        {
            return Err("invalid classifier head metadata or weights".into());
        }
        Ok(Self {
            labels,
            dimension,
            weights,
            bias,
        })
    }

    pub fn scores(&self, embedding: &[f32]) -> Result<Vec<f32>, String> {
        if embedding.len() != self.dimension || embedding.iter().any(|value| !value.is_finite()) {
            return Err("invalid embedding".into());
        }
        self.weights
            .chunks_exact(self.dimension)
            .zip(&self.bias)
            .map(|(row, bias)| {
                let logit = row
                    .iter()
                    .zip(embedding)
                    .fold(*bias, |sum, (weight, value)| sum + weight * value);
                if !logit.is_finite() {
                    return Err("non-finite classifier logit".into());
                }
                Ok(1.0 / (1.0 + (-logit).exp()))
            })
            .collect()
    }

    pub fn verdict(&self, embedding: &[f32]) -> Result<Verdict, String> {
        let scores = self.scores(embedding)?;
        let mut best = 0;
        for index in 1..scores.len() {
            if scores[index] > scores[best] {
                best = index;
            }
        }
        Ok(Verdict {
            label: self.labels[best].clone(),
            score: scores[best],
            categories: self
                .labels
                .iter()
                .cloned()
                .zip(scores)
                .map(|(category, score)| CategoryScore { category, score })
                .collect(),
        })
    }

    pub fn labeled_scores(&self, embedding: &[f32]) -> Result<Vec<(String, f32)>, String> {
        Ok(self
            .labels
            .iter()
            .cloned()
            .zip(self.scores(embedding)?)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NORMAL_LABEL;

    fn head() -> Head {
        Head::from_parts(
            vec![NORMAL_LABEL.into(), "66 - SQL Injection".into()],
            2,
            vec![1.0, 2.0, -1.0, 0.0],
            vec![0.0, 0.0],
        )
        .unwrap()
    }

    #[test]
    fn linear_sigmoid_scores_and_decisions_follow_label_order() {
        let head = head();
        let scores = head.scores(&[1.0, 0.0]).unwrap();
        assert!((scores[0] - 0.7310586).abs() < 1e-6);
        assert!((scores[1] - 0.2689414).abs() < 1e-6);
        assert!(!head.verdict(&[1.0, 0.0]).unwrap().is_attack());
        let verdict = head.verdict(&[-1.0, 0.0]).unwrap();
        assert_eq!(verdict.categories.len(), 2);
        assert_eq!(verdict.categories[0].category, NORMAL_LABEL);
        assert_eq!(verdict.categories[1].category, "66 - SQL Injection");
        assert_eq!(verdict.categories[1].score, verdict.score);
        assert_eq!(
            head.verdict(&[-1.0, 0.0]).unwrap().label,
            "66 - SQL Injection"
        );
        assert!(!head.verdict(&[0.0, 0.0]).unwrap().is_attack());
    }

    #[test]
    fn rejects_bad_dimensions_labels_and_non_finite_values() {
        assert!(Head::from_parts(vec!["attack".into()], 2, vec![1.0, 2.0], vec![0.0]).is_err());
        assert!(
            Head::from_parts(
                vec![NORMAL_LABEL.into(), NORMAL_LABEL.into()],
                1,
                vec![0.0, 0.0],
                vec![0.0, 0.0]
            )
            .is_err()
        );
        assert!(Head::from_parts(vec![NORMAL_LABEL.into()], 2, vec![0.0], vec![0.0]).is_err());
        assert!(Head::from_parts(vec![NORMAL_LABEL.into()], 1, vec![f32::NAN], vec![0.0]).is_err());
        assert!(head().scores(&[f32::NAN, 0.0]).is_err());
        assert!(head().scores(&[1.0]).is_err());
    }

    #[test]
    fn loads_published_safetensors_shape_and_rejects_mismatched_metadata() {
        use safetensors::tensor::{Dtype, TensorView, serialize};
        let labels: Vec<String> = std::iter::once(NORMAL_LABEL.to_string())
            .chain((1..14).map(|n| format!("{n} - Attack")))
            .collect();
        let metadata = serde_json::json!({"labels": labels, "embedding_dim": 768, "hidden": null});
        let weights = vec![0u8; 14 * 768 * 4];
        let mut biases = vec![0u8; 14 * 4];
        biases[4..8].copy_from_slice(&2f32.to_le_bytes());
        let data = serialize(
            [
                (
                    "head.head.weight",
                    TensorView::new(Dtype::F32, vec![14, 768], &weights).unwrap(),
                ),
                (
                    "head.head.bias",
                    TensorView::new(Dtype::F32, vec![14], &biases).unwrap(),
                ),
            ],
            None,
        )
        .unwrap();
        let head = Head::load(metadata.to_string().as_bytes(), &data).unwrap();
        assert_eq!(head.verdict(&vec![0.0; 768]).unwrap().label, "1 - Attack");
        let bad_meta =
            serde_json::json!({"labels": [NORMAL_LABEL], "embedding_dim": 768, "hidden": null});
        assert!(Head::load(bad_meta.to_string().as_bytes(), &data).is_err());
    }
}
