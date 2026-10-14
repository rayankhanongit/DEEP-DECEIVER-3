import os
import threading

import numpy as np

# Override with e.g. sentence-transformers/paraphrase-multilingual-mpnet-base-v2
# when non-English traffic matters. Re-check SENTRY_THRESHOLD after changing it.
DEFAULT_MODEL = "sentence-transformers/all-mpnet-base-v2"

_model = None
_lock = threading.Lock()


def model_name() -> str:
    return os.getenv("EMBEDDING_MODEL", DEFAULT_MODEL)


def get_model():
    """Load the embedding model on first use (not at import time), so the
    app can start, report health and degrade gracefully without it."""

    global _model

    if _model is None:
        with _lock:
            if _model is None:
                from sentence_transformers import SentenceTransformer

                _model = SentenceTransformer(model_name())

    return _model


def generate_embeddings(texts: list[str]) -> np.ndarray:
    """Normalised embeddings, one row per text."""

    return np.asarray(
        get_model().encode(list(texts), normalize_embeddings=True),
        dtype=np.float32,
    )


def generate_embedding(text: str) -> np.ndarray:
    """Convert text into a normalised semantic embedding."""

    return generate_embeddings([text])[0]
