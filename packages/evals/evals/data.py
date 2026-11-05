"""Build the labelled dataset.

Rows are ``{id, text, label, source, split}`` with ``label`` 1 for an attack
and 0 for a benign message.

Splits
------
* ``train`` / ``val`` / ``test``: stratified row-level split of the
  *in-distribution* sources.
* ``test_ood``: whole sources that are never trained on. This is the number
  that matters for a detector that will meet traffic it has not seen.
* ``test_evident``: the hand-labelled corpus that pins the regex library,
  parsed from ``packages/detectors/src/__tests__/injection.corpus.test.ts``.
* ``test_perturbed``: produced by :mod:`evals.perturb` from the attacks in
  ``test`` and ``test_ood``.

Run ``python -m evals.data`` to (re)build ``data/``.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from . import CORPUS_TS, DATA_DIR

SEED = 20261105

# Sources never used for training. Cross-dataset generalisation is measured on these.
OOD_SOURCES = ("jackhhao/jailbreak-classification", "lakera/gandalf_ignore_instructions")

# Caps keep the CPU pipeline tractable. (source, label) -> max rows after dedupe.
CAPS = {
    ("xTRam1/safe-guard-prompt-injection", 1): 3000,
    ("xTRam1/safe-guard-prompt-injection", 0): 1500,
    ("deepset/prompt-injections", 1): 10_000,
    ("deepset/prompt-injections", 0): 10_000,
    ("databricks/databricks-dolly-15k", 0): 1600,
    ("tatsu-lab/alpaca", 0): 1600,
    ("jackhhao/jailbreak-classification", 1): 10_000,
    ("jackhhao/jailbreak-classification", 0): 10_000,
    ("lakera/gandalf_ignore_instructions", 1): 1000,
}

MIN_CHARS = 4
MAX_CHARS = 4000


@dataclass
class Row:
    id: str
    text: str
    label: int
    source: str
    split: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


def normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def make_id(source: str, text: str) -> str:
    digest = hashlib.sha1(f"{source}\x00{normalise(text)}".encode("utf-8")).hexdigest()
    return digest[:16]


def dedupe(rows: Iterable[Row]) -> list[Row]:
    """Drop duplicate texts across all sources (first occurrence wins) and junk rows."""
    seen: set[str] = set()
    out: list[Row] = []
    for row in rows:
        text = row.text.strip()
        if not (MIN_CHARS <= len(text) <= MAX_CHARS):
            continue
        key = normalise(text)
        if key in seen:
            continue
        seen.add(key)
        out.append(Row(row.id, text, int(row.label), row.source, row.split))
    return out


def apply_caps(rows: list[Row], caps: dict[tuple[str, int], int], seed: int = SEED) -> list[Row]:
    rng = random.Random(seed)
    by_key: dict[tuple[str, int], list[Row]] = defaultdict(list)
    for r in rows:
        by_key[(r.source, r.label)].append(r)
    out: list[Row] = []
    for key, group in by_key.items():
        cap = caps.get(key, len(group))
        if len(group) > cap:
            group = rng.sample(group, cap)
        out.extend(group)
    out.sort(key=lambda r: r.id)
    return out


def stratified_split(rows: list[Row], fractions=(0.8, 0.1, 0.1), seed: int = SEED) -> list[Row]:
    """Assign train/val/test per (source, label) stratum."""
    rng = random.Random(seed)
    by_key: dict[tuple[str, int], list[Row]] = defaultdict(list)
    for r in rows:
        by_key[(r.source, r.label)].append(r)
    out: list[Row] = []
    for group in by_key.values():
        group = sorted(group, key=lambda r: r.id)
        rng.shuffle(group)
        n = len(group)
        n_train = int(round(n * fractions[0]))
        n_val = int(round(n * fractions[1]))
        for i, r in enumerate(group):
            split = "train" if i < n_train else "val" if i < n_train + n_val else "test"
            out.append(Row(r.id, r.text, r.label, r.source, split))
    return out


# ---------------------------------------------------------------------------
# Hand-labelled corpus from the TypeScript test file
# ---------------------------------------------------------------------------

_ARRAY_RE = re.compile(r"const\s+(\w+)\s*(?::\s*string\[\])?\s*=\s*\[(.*?)\n\];", re.S)
_STRING_RE = re.compile(r"""(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")""", re.S)

CORPUS_LABELS = {
    "ATTACKS_DEFAULT": 1,
    "ATTACKS_HIGH_SENSITIVITY": 1,
    "BENIGN": 0,
    "BENIGN_AMBIGUOUS": 0,
}


def _unescape(s: str) -> str:
    return (
        s.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\'", "'")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
    )


def parse_corpus(ts_source: str) -> list[Row]:
    rows: list[Row] = []
    for name, body in _ARRAY_RE.findall(ts_source):
        if name not in CORPUS_LABELS:
            continue
        # Strip line comments before pulling string literals.
        body = re.sub(r"^\s*//.*$", "", body, flags=re.M)
        for m in _STRING_RE.finditer(body):
            text = _unescape(m.group(1) if m.group(1) is not None else m.group(2))
            rows.append(Row(make_id("evident", text), text, CORPUS_LABELS[name], f"evident/{name.lower()}", "test_evident"))
    return rows


def load_corpus(path: Path = CORPUS_TS) -> list[Row]:
    return parse_corpus(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Hugging Face sources
# ---------------------------------------------------------------------------

def _hf(name: str, **kwargs):
    from datasets import load_dataset  # imported lazily so tests need no network

    return load_dataset(name, **kwargs)


def _concat_splits(ds) -> list[dict]:
    out: list[dict] = []
    for split in ds.keys():
        out.extend(ds[split])
    return out


def load_hf_sources(skipped: dict[str, str]) -> list[Row]:
    rows: list[Row] = []

    def add(source: str, text: str, label: int) -> None:
        if isinstance(text, str) and text.strip():
            rows.append(Row(make_id(source, text), text.strip(), label, source))

    loaders = {
        "deepset/prompt-injections": lambda: [
            (r["text"], int(r["label"])) for r in _concat_splits(_hf("deepset/prompt-injections"))
        ],
        "xTRam1/safe-guard-prompt-injection": lambda: [
            (r["text"], int(r["label"])) for r in _concat_splits(_hf("xTRam1/safe-guard-prompt-injection"))
        ],
        "jackhhao/jailbreak-classification": lambda: [
            (r["prompt"], 1 if str(r["type"]).lower().startswith("jail") else 0)
            for r in _concat_splits(_hf("jackhhao/jailbreak-classification"))
        ],
        "lakera/gandalf_ignore_instructions": lambda: [
            (r["text"], 1) for r in _concat_splits(_hf("lakera/gandalf_ignore_instructions"))
        ],
        "databricks/databricks-dolly-15k": lambda: [
            (r["instruction"], 0) for r in _concat_splits(_hf("databricks/databricks-dolly-15k"))
        ],
        "tatsu-lab/alpaca": lambda: [
            ((r["instruction"] + ("\n\n" + r["input"] if r.get("input") else "")), 0)
            for r in _concat_splits(_hf("tatsu-lab/alpaca"))
        ],
    }

    for source, loader in loaders.items():
        try:
            pairs = loader()
        except Exception as exc:  # gated, renamed or offline: record and move on
            skipped[source] = f"{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"
            print(f"[data] skipped {source}: {skipped[source]}", file=sys.stderr)
            continue
        for text, label in pairs:
            add(source, text, label)
        print(f"[data] loaded {source}: {len(pairs)} rows", file=sys.stderr)
    return rows


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def build(out_dir: Path = DATA_DIR) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    skipped: dict[str, str] = {}

    raw = load_hf_sources(skipped)
    deduped = dedupe(raw)
    capped = apply_caps(deduped, CAPS)

    in_dist = [r for r in capped if r.source not in OOD_SOURCES]
    ood = [Row(r.id, r.text, r.label, r.source, "test_ood") for r in capped if r.source in OOD_SOURCES]
    split_rows = stratified_split(in_dist)

    # The hand-labelled corpus must not overlap anything else.
    seen = {normalise(r.text) for r in split_rows + ood}
    evident = [r for r in load_corpus() if normalise(r.text) not in seen]

    all_rows = split_rows + ood + evident
    by_split: dict[str, list[Row]] = defaultdict(list)
    for r in all_rows:
        by_split[r.split].append(r)

    for split, rows in by_split.items():
        with (out_dir / f"{split}.jsonl").open("w", encoding="utf-8") as fh:
            for r in sorted(rows, key=lambda r: r.id):
                fh.write(r.to_json() + "\n")

    manifest = {
        "seed": SEED,
        "ood_sources": list(OOD_SOURCES),
        "skipped_sources": skipped,
        "raw_rows": len(raw),
        "after_dedupe": len(deduped),
        "after_caps": len(capped),
        "splits": {
            split: {
                "total": len(rows),
                "attack": sum(r.label for r in rows),
                "benign": sum(1 - r.label for r in rows),
                "by_source": dict(sorted(Counter(f"{r.source}|{r.label}" for r in rows).items())),
            }
            for split, rows in sorted(by_split.items())
        },
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def read_split(name: str, data_dir: Path = DATA_DIR) -> list[dict]:
    path = data_dir / f"{name}.jsonl"
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


if __name__ == "__main__":
    manifest = build()
    print(json.dumps({k: v for k, v in manifest.items() if k != "splits"}, indent=2))
    for split, info in manifest["splits"].items():
        print(f"{split:14s} total={info['total']:5d} attack={info['attack']:5d} benign={info['benign']:5d}")
