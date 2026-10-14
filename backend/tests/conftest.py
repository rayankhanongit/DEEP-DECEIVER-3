import hashlib
import os

# CrewAI/OpenTelemetry telemetry stays off: security prompts never leave this host.
os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")
import sys
import types

import numpy as np

# Make `app` importable no matter where pytest is launched from.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Tests that exercise the full chat pipeline act as the operator.
os.environ["OPERATOR_TOKEN"] = "pytest-operator-token"
os.environ.setdefault("SESSION_SECRET", "pytest-session-secret")
os.environ.setdefault("GROQ_API_KEY", "test-key-not-used")
os.environ["CREW_TPM_LIMIT"] = "0"          # no local token throttling in tests
OPERATOR_HEADERS = {"X-Operator-Token": "pytest-operator-token"}


def _install_fake_sentence_transformers():
    """Offline, deterministic stand-in for sentence-transformers: hashed
    word uni/bi-gram vectors. Lexically similar texts get high cosine
    similarity, which is enough for the plumbing tests. Set
    DD_TEST_REAL_EMBEDDINGS=1 to use the real model instead."""

    class FakeSentenceTransformer:
        DIM = 768

        def __init__(self, *_args, **_kwargs):
            pass

        def _vec(self, text: str) -> np.ndarray:
            words = [w for w in "".join(c.lower() if c.isalnum() else " " for c in text).split()]
            grams = words + [" ".join(p) for p in zip(words, words[1:])]
            vec = np.zeros(self.DIM, dtype=np.float32)

            for gram in grams:
                index = int(hashlib.md5(gram.encode()).hexdigest()[:8], 16) % self.DIM
                vec[index] += 1.0

            norm = np.linalg.norm(vec)

            return vec / norm if norm else vec

        def encode(self, texts, normalize_embeddings=True, **_kwargs):
            single = isinstance(texts, str)
            rows = np.stack([self._vec(t) for t in ([texts] if single else texts)])

            return rows[0] if single else rows

    module = types.ModuleType("sentence_transformers")
    module.SentenceTransformer = FakeSentenceTransformer
    sys.modules["sentence_transformers"] = module


if not os.getenv("DD_TEST_REAL_EMBEDDINGS"):
    _install_fake_sentence_transformers()

    # Hashed n-gram vectors score lexical overlap lower than real embeddings,
    # so the Sentry threshold is lowered for the offline stand-in only.
    os.environ.setdefault("SENTRY_THRESHOLD", "0.35")
