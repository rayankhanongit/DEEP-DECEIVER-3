import base64
import codecs
import re
import unicodedata

LEETSPEAK_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
})

ZERO_WIDTH = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")

# A "mixed" token contains both letters and digits (1gn0r3, pr3v10u5).
# Plain numbers ("3 apples", "2026") are not leetspeak.
MIXED_TOKEN = re.compile(r"\b(?=\w*[a-z])(?=\w*\d)\w+\b", re.IGNORECASE)

# i g n o r e  /  i.g.n.o.r.e  (single characters separated by spaces/dots)
SPACED_LETTERS = re.compile(r"(?:\b\w[\s.\-_]){5,}\w\b")

SUSPICIOUS_WORDS = [
    "ignore", "previous", "instructions", "system", "prompt", "reveal",
    "hidden", "override", "bypass", "confidential",
]


def decode_base64(text: str) -> str | None:
    """Decode a Base64 message, or return None if it is not one."""

    cleaned = text.strip()

    if len(cleaned) < 16:
        return None

    if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", cleaned):
        return None

    try:
        decoded = base64.b64decode(cleaned, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error):
        return None

    # Random alphanumeric strings occasionally decode; keep only text.
    if not decoded.strip() or not all(c.isprintable() or c in "\n\r\t" for c in decoded):
        return None

    return decoded


def decode_rot13(text: str) -> str | None:
    if not text.strip():
        return None

    try:
        decoded = codecs.decode(text, "rot_13")
    except Exception:
        return None

    decoded_lower = decoded.lower()
    matches = sum(word in decoded_lower for word in SUSPICIOUS_WORDS)

    # Ordinary English must not be classified as ROT13.
    if decoded != text and matches >= 2:
        return decoded

    return None


def decode_leetspeak(text: str) -> str | None:
    """Normalise leetspeak, but only when the text really looks leet-encoded."""

    if len(MIXED_TOKEN.findall(text)) < 2:
        return None

    decoded = text.translate(LEETSPEAK_MAP)

    return None if decoded == text else decoded


def decode_spaced_letters(text: str) -> str | None:
    """"i g n o r e   p r e v i o u s": words separated by wider gaps, letters
    by single spaces / dots / dashes."""

    if not SPACED_LETTERS.search(text):
        return None

    words = re.split(r"\s{2,}|\s\|\s", text.strip())
    decoded_words = []

    for word in words:
        tokens = [t for t in re.split(r"[\s.\-_]+", word) if t]

        if len(tokens) >= 2 and all(len(t) == 1 for t in tokens):
            decoded_words.append("".join(tokens))
        else:
            decoded_words.append(word)

    decoded = " ".join(decoded_words)

    return None if decoded == text else decoded


def normalize_unicode(text: str) -> str | None:
    """Strip zero-width characters and fold look-alike (full-width,
    mathematical ...) characters to plain text."""

    cleaned = unicodedata.normalize("NFKC", ZERO_WIDTH.sub("", text))

    return None if cleaned == text else cleaned


def detect_obfuscation(text: str) -> dict:
    """Detect and decode obfuscated input."""

    for name, decoder in (
        ("base64", decode_base64),
        ("unicode", normalize_unicode),
        ("spaced_letters", decode_spaced_letters),
        ("leetspeak", decode_leetspeak),
        ("rot13", decode_rot13),
    ):
        decoded = decoder(text)

        if decoded is not None:
            return {
                "detected": True,
                "encoding": name,
                "decoded_text": decoded,
            }

    return {
        "detected": False,
        "encoding": None,
        "decoded_text": None,
    }
