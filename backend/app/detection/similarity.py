import numpy as np


def calculate_similarity(embedding_a, embedding_b) -> float:
    """Cosine similarity between two vectors."""

    a = np.asarray(embedding_a, dtype=np.float32)
    b = np.asarray(embedding_b, dtype=np.float32)

    denominator = float(np.linalg.norm(a) * np.linalg.norm(b))

    if denominator == 0.0:
        return 0.0

    return float(np.dot(a, b) / denominator)


def similarity_matrix(queries, references) -> np.ndarray:
    """Cosine similarities of every query row against every reference row."""

    q = np.asarray(queries, dtype=np.float32)
    r = np.asarray(references, dtype=np.float32)

    q = q / np.maximum(np.linalg.norm(q, axis=1, keepdims=True), 1e-12)
    r = r / np.maximum(np.linalg.norm(r, axis=1, keepdims=True), 1e-12)

    return q @ r.T
