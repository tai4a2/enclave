//! Local retrieval-augmented generation (C1).
//!
//! Files are chunked and stored encrypted in the vault. Search works fully
//! offline: a BM25-style keyword scorer over the stored chunks, optionally
//! boosted by embeddings when they are available. Nothing leaves the machine
//! unless the user explicitly sends a retrieved chunk to a provider.
use std::collections::HashMap;
use std::path::Path;

use crate::privacy::RagChunk;

/// Split `text` into overlapping-free chunks of at most `max_chars` characters,
/// preferring to break on blank lines and then on whitespace.
pub fn chunk_text(text: &str, max_chars: usize) -> Vec<String> {
    fn flush(chunks: &mut Vec<String>, buf: &mut String) {
        let t = buf.trim();
        if !t.is_empty() {
            chunks.push(t.to_string());
        }
        buf.clear();
    }

    let max_chars = max_chars.max(200);
    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();
    for para in text.split("\n\n") {
        let para = para.trim();
        if para.is_empty() {
            continue;
        }
        if para.len() > max_chars {
            flush(&mut chunks, &mut current);
            // Hard-split an over-long paragraph on whitespace.
            let mut line = String::new();
            for word in para.split_whitespace() {
                if !line.is_empty() && line.len() + 1 + word.len() > max_chars {
                    flush(&mut chunks, &mut line);
                }
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
            }
            flush(&mut chunks, &mut line);
        } else {
            if !current.is_empty() && current.len() + para.len() + 2 > max_chars {
                flush(&mut chunks, &mut current);
            }
            if !current.is_empty() {
                current.push_str("\n\n");
            }
            current.push_str(para);
        }
    }
    flush(&mut chunks, &mut current);
    if chunks.is_empty() && !text.trim().is_empty() {
        chunks.push(text.trim().to_string());
    }
    chunks
}

/// Lowercase alphanumeric tokens.
pub fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_string())
        .collect()
}

/// A retrieval hit.
#[derive(Debug, Clone)]
pub struct Hit {
    pub source: String,
    pub text: String,
    pub score: f64,
}

/// BM25-style keyword search over the stored chunks (fully local).
pub fn keyword_search(query: &str, chunks: &[RagChunk], limit: usize) -> Vec<Hit> {
    let q_terms = tokenize(query);
    if q_terms.is_empty() {
        return Vec::new();
    }
    let n = chunks.len().max(1) as f64;
    // Document frequency per query term.
    let mut df: HashMap<&str, f64> = HashMap::new();
    let docs: Vec<Vec<String>> = chunks.iter().map(|c| tokenize(&c.text)).collect();
    for term in &q_terms {
        let count = docs
            .iter()
            .filter(|d| d.iter().any(|t| t == term))
            .count() as f64;
        df.insert(term.as_str(), count);
    }
    let avg_len = docs.iter().map(|d| d.len()).sum::<usize>() as f64 / n;
    let k1 = 1.5f64;
    let b = 0.75f64;

    let mut hits: Vec<Hit> = Vec::new();
    for (chunk, terms) in chunks.iter().zip(docs.iter()) {
        let dl = terms.len() as f64;
        let mut score = 0.0f64;
        for term in &q_terms {
            let tf = terms.iter().filter(|t| *t == term).count() as f64;
            if tf == 0.0 {
                continue;
            }
            let dfi = df.get(term.as_str()).copied().unwrap_or(0.0);
            let idf = (1.0 + (n - dfi + 0.5) / (dfi + 0.5)).ln();
            let denom = tf + k1 * (1.0 - b + b * dl / avg_len.max(1.0));
            score += idf * (tf * (k1 + 1.0)) / denom;
        }
        if score > 0.0 {
            hits.push(Hit {
                source: chunk.source.clone(),
                text: chunk.text.clone(),
                score,
            });
        }
    }
    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    hits.truncate(limit.max(1));
    hits
}

/// Cosine similarity between two vectors (0 when either is empty).
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na.sqrt() * nb.sqrt())
    }
}

/// Semantic search using embeddings; falls back to keyword search when the
/// chunks have no embeddings.
pub fn semantic_search(
    query_embedding: &[f32],
    query_text: &str,
    chunks: &[RagChunk],
    limit: usize,
) -> Vec<Hit> {
    let embedded: Vec<&RagChunk> = chunks.iter().filter(|c| c.embedding.is_some()).collect();
    if embedded.is_empty() || query_embedding.is_empty() {
        return keyword_search(query_text, chunks, limit);
    }
    let mut hits: Vec<Hit> = embedded
        .iter()
        .map(|c| {
            let score = cosine(query_embedding, c.embedding.as_ref().unwrap()) as f64;
            Hit {
                source: c.source.clone(),
                text: c.text.clone(),
                score,
            }
        })
        .filter(|h| h.score > 0.0)
        .collect();
    hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    hits.truncate(limit.max(1));
    hits
}

/// Whether a file is still readable by the current user (per-file ACL check
/// re-evaluated at search/return time).
pub fn is_readable(path: &Path) -> bool {
    std::fs::File::open(path).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(source: &str, text: &str) -> RagChunk {
        RagChunk {
            id: 0,
            source: source.to_string(),
            ord: 0,
            text: text.to_string(),
            embedding: None,
        }
    }

    #[test]
    fn chunking_splits_on_paragraphs() {
        let text = format!("{}\n\n{}", "a".repeat(300), "b".repeat(300));
        let chunks = chunk_text(&text, 400);
        assert_eq!(chunks.len(), 2);
    }

    #[test]
    fn keyword_search_ranks_the_matching_chunk_first() {
        let chunks = vec![
            chunk("cats.txt", "the cat sat on the mat"),
            chunk("dogs.txt", "a dog barked at the mailman"),
        ];
        let hits = keyword_search("dog", &chunks, 5);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].source, "dogs.txt");
    }

    #[test]
    fn cosine_is_one_for_identical_vectors() {
        let v = [1.0f32, 2.0, 3.0];
        assert!((cosine(&v, &v) - 1.0).abs() < 1e-6);
        assert_eq!(cosine(&v, &[]), 0.0);
    }
}