"""Injection and jailbreak classifiers, run sentence by sentence on the CPU.

Scoring whole emails only answers "is something wrong in here". Scoring
sentences says *which* sentence, which is what muffling needs: the injected line
is removed and the rest of the mail still reaches the model, so the agent can
finish the real task.

The models are ONNX, so this needs onnxruntime and tokenizers but not torch. If
neither is installed the guard still runs: the policy engine does not depend on
any of this, and the red-team suite measures exactly that case.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from ..normalize import strip_invisible, tags_to_ascii

# Repository ids, resolved through the local Hugging Face cache.
ENGLISH_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
AGENT_MODEL = "Horizon-Labs/prompt-injection-guard-small"

_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n+")


@dataclass(frozen=True)
class Span:
    """One sentence the classifier judged to be an instruction."""

    text: str
    start: int
    end: int
    score: float
    model: str


def _cache_root() -> Path:
    return Path(
        os.environ.get("HF_HOME", Path.home() / ".cache" / "huggingface")
    ).expanduser() / "hub"


def _snapshot(repo_id: str) -> Path | None:
    """The newest local snapshot of a model, or None when it is not cached."""
    folder = _cache_root() / ("models--" + repo_id.replace("/", "--")) / "snapshots"
    if not folder.is_dir():
        return None
    snaps = sorted(folder.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    return snaps[0] if snaps else None


def _tokenizer_file_is_safe(path: Path) -> bool:
    """Reject malformed BPE merge pairs before the native parser sees them."""
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    model = config.get("model") if isinstance(config, dict) else None
    if not isinstance(model, dict):
        return False
    if model.get("type") != "BPE":
        return True

    vocab, merges = model.get("vocab"), model.get("merges")
    prefix = model.get("continuing_subword_prefix")
    if prefix is None:
        prefix = ""
    if not isinstance(vocab, dict) or not isinstance(merges, list) or not isinstance(prefix, str):
        return False
    if not all(isinstance(token, str) for token in vocab):
        return False

    byte_vocab = {token: len(token.encode("utf-8")) for token in vocab}
    max_token_len = max(byte_vocab.values(), default=0)
    prefix_len = len(prefix.encode("utf-8"))
    for merge in merges:
        if isinstance(merge, str):
            parts = merge.split(" ", 1)
            if len(parts) != 2:
                return False
            left, right = parts
        elif isinstance(merge, list) and len(merge) == 2:
            left, right = merge
        else:
            return False
        if not isinstance(left, str) or not isinstance(right, str):
            return False
        if left not in byte_vocab or right not in byte_vocab:
            return False

        right_bytes = right.encode("utf-8")
        if prefix_len > len(right_bytes):
            return False
        try:
            suffix = right_bytes[prefix_len:].decode("utf-8")
        except UnicodeDecodeError:
            return False
        if byte_vocab[left] + len(suffix.encode("utf-8")) > max_token_len:
            return False
    return True


def sentences(text: str) -> list[tuple[str, int, int]]:
    """Split into sentences, keeping each one's offsets in the original text."""
    out, pos = [], 0
    for piece in _SENTENCE_RE.split(text):
        if piece is None:
            continue
        start = text.find(piece, pos) if piece else pos
        if piece.strip():
            out.append((piece, start, start + len(piece)))
        pos = start + len(piece)
    return out or ([(text, 0, len(text))] if text.strip() else [])


class OnnxClassifier:
    """A sequence classifier loaded from the local cache, run on the CPU."""

    def __init__(self, repo_id: str, positive_labels: tuple[str, ...] = ("INJECTION", "LABEL_1")):
        self.repo_id = repo_id
        self.positive_labels = positive_labels
        self._session = None
        self._tokenizer = None
        self._positive_index = 1

    def load(self) -> bool:
        if self._session is not None:
            return True
        snapshot = _snapshot(self.repo_id)
        if snapshot is None:
            return False
        tokenizer_path = snapshot / "tokenizer.json"
        # Quantised weights first: roughly three times faster on a CPU, which is
        # the difference between a demo that waits and one that does not.
        candidates = [
            snapshot / "onnx" / "model_quantized.onnx",
            snapshot / "onnx" / "model.onnx",
            snapshot / "model.onnx",
        ]
        onnx_path = next((p for p in candidates if p.exists()), None)
        if onnx_path is None or not tokenizer_path.exists():
            return False
        if not _tokenizer_file_is_safe(tokenizer_path):
            return False
        try:
            import onnxruntime
            from tokenizers import Tokenizer
        except ImportError:
            return False

        options = onnxruntime.SessionOptions()
        options.intra_op_num_threads = os.cpu_count() or 4
        options.graph_optimization_level = onnxruntime.GraphOptimizationLevel.ORT_ENABLE_ALL
        self._session = onnxruntime.InferenceSession(
            str(onnx_path), options, providers=["CPUExecutionProvider"]
        )
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        self._tokenizer.enable_truncation(max_length=256)
        self._tokenizer.enable_padding()
        self._positive_index = self._resolve_positive_index(snapshot)
        return True

    def _resolve_positive_index(self, snapshot: Path) -> int:
        """Which output column means 'this is an injection'.

        Read from the model's own config so a model that orders its labels the
        other way round is not silently inverted.
        """
        config = snapshot / "config.json"
        if not config.exists():
            return 1
        try:
            id2label = json.loads(config.read_text(encoding="utf-8")).get("id2label", {})
        except (json.JSONDecodeError, OSError):
            return 1
        for index, label in id2label.items():
            if str(label).upper() in self.positive_labels:
                return int(index)
        return 1 if len(id2label) > 1 else 0

    def score(self, text: str) -> float:
        """Probability that the text is an instruction aimed at the model."""
        return self.score_batch([text])[0]

    def score_batch(self, texts: list[str]) -> list[float]:
        """Score every text in one pass.

        One padded batch rather than a call per sentence: the fixed cost of a
        session run dominates at this size, so this is most of the speed-up.
        """
        if not texts:
            return []
        if not self.load():
            return [0.0] * len(texts)
        import numpy as np

        encodings = self._tokenizer.encode_batch(texts)
        feed = {}
        for inp in self._session.get_inputs():
            if inp.name == "input_ids":
                feed[inp.name] = np.array([e.ids for e in encodings], dtype=np.int64)
            elif inp.name == "attention_mask":
                feed[inp.name] = np.array([e.attention_mask for e in encodings], dtype=np.int64)
            elif inp.name == "token_type_ids":
                feed[inp.name] = np.array([e.type_ids for e in encodings], dtype=np.int64)
        logits = self._session.run(None, feed)[0]
        shifted = logits - logits.max(axis=1, keepdims=True)
        probs = np.exp(shifted) / np.exp(shifted).sum(axis=1, keepdims=True)
        index = min(self._positive_index, probs.shape[1] - 1)
        return [float(p) for p in probs[:, index]]


@lru_cache(maxsize=4)
def _classifier(repo_id: str) -> OnnxClassifier:
    return OnnxClassifier(repo_id)


class InjectionDetector:
    """Flags the sentences in a tool result that try to instruct the model.

    The agent-content model runs first: it is quantised, so about twice as fast,
    and it was trained on injections sitting inside tool results, which is the
    case here. Measured on this laptop it scores 1.0 on an injection aimed at an
    assistant that the English model scores 0.0, so running it second would
    spend the slower model's time to reach a worse answer.

    The English model is then a second opinion on sentences the first was unsure
    about. Sentences at 0.0 or 1.0 need no second opinion, which is most of them,
    so the slower model rarely runs at all.
    """

    def __init__(
        self,
        threshold: float = 0.5,
        models: tuple[str, ...] = (AGENT_MODEL, ENGLISH_MODEL),
        second_opinion_band: tuple[float, float] = (0.08, 0.5),
        max_sentences: int = 40,
    ):
        self.threshold = threshold
        self.models = models
        self.second_opinion_band = second_opinion_band
        self.max_sentences = max_sentences

    def available(self) -> bool:
        """Whether every configured classifier has local weights and runtime support."""
        return bool(self.models) and all(_classifier(m).load() for m in self.models)

    def scan(self, text: str) -> list[Span]:
        """Every sentence either classifier judges to be an injection.

        Hidden carriers are decoded first, so a sentence written in invisible
        Unicode is scored as the text the model would actually read.
        """
        revealed, _ = strip_invisible(text)
        decoded_tags = tags_to_ascii(text)
        probe = revealed if not decoded_tags else f"{revealed}\n{decoded_tags}"

        candidates = [(s, a, b) for s, a, b in sentences(probe) if len(s.strip()) >= 8]
        candidates = candidates[: self.max_sentences]  # bound the worst case
        if not candidates:
            return []

        best = [(0.0, "")] * len(candidates)
        pending = list(range(len(candidates)))
        low, high = self.second_opinion_band
        for position, repo_id in enumerate(self.models):
            if not pending:
                break
            clf = _classifier(repo_id)
            if not clf.load():
                continue
            scores = clf.score_batch([candidates[i][0] for i in pending])
            still: list[int] = []
            for i, score in zip(pending, scores):
                if score > best[i][0]:
                    best[i] = (score, repo_id)
                # After the first model, only the undecided go on to the next.
                if position == 0 and low <= best[i][0] < high:
                    still.append(i)
                elif position > 0 and best[i][0] < self.threshold:
                    still.append(i)
            pending = still

        spans = []
        for i, (sentence, start, end) in enumerate(candidates):
            score, model = best[i]
            if score >= self.threshold:
                spans.append(Span(sentence.strip(), start, end, score, model))
        return spans
