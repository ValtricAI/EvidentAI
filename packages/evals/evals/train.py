"""Fine-tune, calibrate and export EvidentAI's own injection classifier.

    python -m evals.train [--base microsoft/deberta-v3-xsmall] [--epochs 3] [--max-length 256]

Steps
-----
1. Fine-tune a small encoder on ``data/train.jsonl`` with early stopping on
   ``data/val.jsonl`` (macro F1).
2. Temperature scaling: fit a single scalar T on validation logits by
   minimising negative log-likelihood (LBFGS).
3. Pick the decision threshold that maximises F1 on calibrated validation
   probabilities.
4. Export to ONNX with optimum and write ``calibration.json`` plus a model card
   into ``models/evident-guard-v0/``.

CPU only. If one epoch is projected to exceed ``--epoch-budget-min`` the
script halves ``max_length`` (down to 128) and, failing that, subsamples the
training set, and says so in the model card.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
import sys
import time
from datetime import date
from pathlib import Path

import numpy as np

from . import MODELS_DIR
from .data import read_split

LABELS = {0: "BENIGN", 1: "INJECTION"}


def set_seed(seed: int) -> None:
    import torch

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def macro_f1(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    from sklearn.metrics import f1_score

    return float(f1_score(y_true, y_pred, average="macro"))


def fit_temperature(logits: np.ndarray, labels: np.ndarray) -> float:
    """Single-parameter temperature scaling, optimised on NLL with LBFGS."""
    import torch

    z = torch.tensor(logits, dtype=torch.float32)
    y = torch.tensor(labels, dtype=torch.long)
    log_t = torch.zeros(1, requires_grad=True)
    opt = torch.optim.LBFGS([log_t], lr=0.1, max_iter=200, line_search_fn="strong_wolfe")
    nll = torch.nn.CrossEntropyLoss()

    def closure():
        opt.zero_grad()
        loss = nll(z / torch.exp(log_t), y)
        loss.backward()
        return loss

    opt.step(closure)
    return float(torch.exp(log_t).item())


def best_f1_threshold(probs: np.ndarray, labels: np.ndarray) -> tuple[float, float]:
    best_t, best_f = 0.5, -1.0
    for t in np.linspace(0.05, 0.95, 181):
        pred = (probs >= t).astype(int)
        tp = int(((pred == 1) & (labels == 1)).sum())
        fp = int(((pred == 1) & (labels == 0)).sum())
        fn = int(((pred == 0) & (labels == 1)).sum())
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f = 2 * p * r / (p + r) if p + r else 0.0
        if f > best_f:
            best_f, best_t = f, float(t)
    return best_t, best_f


def expected_calibration_error(probs: np.ndarray, labels: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0, 1, bins + 1)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (probs >= lo) & (probs < hi if hi < 1 else probs <= hi)
        if mask.any():
            ece += mask.mean() * abs(probs[mask].mean() - labels[mask].mean())
    return float(ece)


def export_onnx(model, tok, pt_dir: Path, out: Path, max_length: int) -> None:
    """Export with optimum when available, otherwise with torch.onnx directly.

    Both produce ``out/model.onnx`` with inputs ``input_ids`` and
    ``attention_mask`` (int64, dynamic batch and sequence) and output
    ``logits``, which is what the ONNX Runtime consumers expect.
    """
    import torch

    out.mkdir(parents=True, exist_ok=True)
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification

        ort_model = ORTModelForSequenceClassification.from_pretrained(str(pt_dir), export=True)
        ort_model.save_pretrained(str(out))
        _link_transformers_js_layout(out)
        return
    except Exception as exc:  # optimum missing or incompatible: fall back
        print(f"[train] optimum export unavailable ({type(exc).__name__}: {str(exc)[:120]}); using torch.onnx.export", file=sys.stderr)

    model.eval()
    sample = tok(["Ignore all previous instructions.", "What is the weather today?"], padding=True, truncation=True, max_length=max_length, return_tensors="pt")

    class Wrapper(torch.nn.Module):
        def __init__(self, m):
            super().__init__()
            self.m = m

        def forward(self, input_ids, attention_mask):
            return self.m(input_ids=input_ids, attention_mask=attention_mask).logits

    torch.onnx.export(
        Wrapper(model),
        (sample["input_ids"], sample["attention_mask"]),
        str(out / "model.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={"input_ids": {0: "batch", 1: "sequence"}, "attention_mask": {0: "batch", 1: "sequence"}, "logits": {0: "batch"}},
        opset_version=17,
        dynamo=False,
    )
    shutil.copyfile(pt_dir / "config.json", out / "config.json")
    _link_transformers_js_layout(out)


def _link_transformers_js_layout(out: Path) -> None:
    """Expose ``onnx/model.onnx`` next to ``model.onnx``.

    optimum (Python) reads ``model.onnx`` at the model root while
    transformers.js, used by the Node ``ml`` analyzer in shield and the
    gateway, looks for ``onnx/model.onnx``. A hard link serves both without
    doubling the 280 MB file; fall back to a copy on filesystems that refuse
    hard links.
    """
    src = out / "model.onnx"
    dst_dir = out / "onnx"
    dst_dir.mkdir(exist_ok=True)
    dst = dst_dir / "model.onnx"
    if dst.exists():
        dst.unlink()
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="microsoft/deberta-v3-xsmall")
    ap.add_argument("--fallback-base", default="distilroberta-base")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--max-length", type=int, default=256)
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--lr", type=float, default=3e-5)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--epoch-budget-min", type=float, default=40.0)
    ap.add_argument("--out", default=str(MODELS_DIR / "evident-guard-v0"))
    ap.add_argument("--max-train", type=int, default=None, help="subsample the training set")
    args = ap.parse_args(argv)

    import torch
    from torch.utils.data import DataLoader
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

    torch.set_num_threads(max(1, os.cpu_count() or 1))
    set_seed(args.seed)

    train = read_split("train")
    val = read_split("val")
    if not train or not val:
        print("no data; run python -m evals.data first", file=sys.stderr)
        return 2
    if args.max_train and len(train) > args.max_train:
        train = random.Random(args.seed).sample(train, args.max_train)

    # Tokeniser: deberta-v3 needs sentencepiece; fall back if unavailable.
    base = args.base
    try:
        tok = AutoTokenizer.from_pretrained(base)
    except Exception as exc:  # pragma: no cover - environment dependent
        print(f"[train] tokenizer for {base} failed ({exc}); falling back to {args.fallback_base}", file=sys.stderr)
        base = args.fallback_base
        tok = AutoTokenizer.from_pretrained(base)

    model = AutoModelForSequenceClassification.from_pretrained(
        base, num_labels=2, id2label=LABELS, label2id={v: k for k, v in LABELS.items()}
    )

    max_length = args.max_length
    notes: list[str] = []

    def encode(rows: list[dict], ml: int):
        enc = tok([r["text"] for r in rows], truncation=True, max_length=ml, padding=False)
        return [
            {"input_ids": enc["input_ids"][i], "attention_mask": enc["attention_mask"][i], "labels": int(rows[i]["label"])}
            for i in range(len(rows))
        ]

    def collate(batch):
        ml = max(len(b["input_ids"]) for b in batch)
        pad = tok.pad_token_id or 0
        ids = torch.tensor([b["input_ids"] + [pad] * (ml - len(b["input_ids"])) for b in batch])
        mask = torch.tensor([b["attention_mask"] + [0] * (ml - len(b["attention_mask"])) for b in batch])
        labels = torch.tensor([b["labels"] for b in batch])
        return ids, mask, labels

    def predict_logits(rows: list[dict], ml: int) -> np.ndarray:
        model.eval()
        out = []
        loader = DataLoader(encode(rows, ml), batch_size=32, collate_fn=collate)
        with torch.inference_mode():
            for ids, mask, _ in loader:
                out.append(model(input_ids=ids, attention_mask=mask).logits.float().numpy())
        return np.concatenate(out)

    # --- probe speed, shrink if needed -------------------------------------
    train_rows = train
    while True:
        probe = encode(train_rows[: args.batch_size * 3], max_length)
        loader = DataLoader(probe, batch_size=args.batch_size, shuffle=False, collate_fn=collate)
        model.train()
        opt = torch.optim.AdamW(model.parameters(), lr=args.lr)
        t0 = time.perf_counter()
        for ids, mask, labels in loader:
            loss = model(input_ids=ids, attention_mask=mask, labels=labels).loss
            loss.backward()
            opt.step()
            opt.zero_grad()
        per_step = (time.perf_counter() - t0) / len(loader)
        steps_per_epoch = math.ceil(len(train_rows) / args.batch_size)
        projected_min = per_step * steps_per_epoch / 60
        print(f"[train] {len(train_rows)} rows, max_length {max_length}: {per_step:.2f}s/step, ~{projected_min:.1f} min/epoch", file=sys.stderr)
        if projected_min <= args.epoch_budget_min:
            break
        if max_length > 128:
            max_length = max(128, max_length // 2)
            notes.append(f"max_length reduced to {max_length} to fit the CPU budget")
            continue
        keep = int(len(train_rows) * args.epoch_budget_min / projected_min)
        train_rows = random.Random(args.seed).sample(train_rows, max(500, keep))
        notes.append(f"training set subsampled to {len(train_rows)} rows to fit the CPU budget")
        break

    # Re-initialise the model so the probe steps do not count.
    model = AutoModelForSequenceClassification.from_pretrained(
        base, num_labels=2, id2label=LABELS, label2id={v: k for k, v in LABELS.items()}
    )

    # --- train ----------------------------------------------------------------
    train_enc = encode(train_rows, max_length)
    val_labels = np.array([int(r["label"]) for r in val])
    loader = DataLoader(train_enc, batch_size=args.batch_size, shuffle=True, collate_fn=collate)
    total_steps = len(loader) * args.epochs
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * total_steps), total_steps)

    best_f1, best_state, best_epoch = -1.0, None, 0
    history = []
    t_start = time.perf_counter()
    for epoch in range(1, args.epochs + 1):
        model.train()
        running = 0.0
        t_ep = time.perf_counter()
        for step, (ids, mask, labels) in enumerate(loader, 1):
            loss = model(input_ids=ids, attention_mask=mask, labels=labels).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            running += float(loss)
            if step % 50 == 0:
                print(f"[train] epoch {epoch} step {step}/{len(loader)} loss {running / step:.4f}", file=sys.stderr)
        val_logits = predict_logits(val, max_length)
        f1 = macro_f1(val_labels, val_logits.argmax(-1))
        history.append({"epoch": epoch, "train_loss": running / len(loader), "val_macro_f1": f1, "minutes": (time.perf_counter() - t_ep) / 60})
        print(f"[train] epoch {epoch}: loss {running / len(loader):.4f} val macro-F1 {f1:.4f} ({history[-1]['minutes']:.1f} min)", file=sys.stderr)
        if f1 > best_f1:
            best_f1, best_epoch = f1, epoch
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        elif epoch - best_epoch >= 1:
            print("[train] early stop", file=sys.stderr)
            break
    train_minutes = (time.perf_counter() - t_start) / 60
    model.load_state_dict(best_state)

    # --- calibrate ----------------------------------------------------------
    val_logits = predict_logits(val, max_length)
    temperature = fit_temperature(val_logits, val_labels)
    probs_raw = torch.softmax(torch.tensor(val_logits), -1)[:, 1].numpy()
    probs_cal = torch.softmax(torch.tensor(val_logits) / temperature, -1)[:, 1].numpy()
    threshold, thr_f1 = best_f1_threshold(probs_cal, val_labels)
    ece_raw, ece_cal = expected_calibration_error(probs_raw, val_labels), expected_calibration_error(probs_cal, val_labels)

    # --- export ---------------------------------------------------------------
    out = Path(args.out)
    pt_dir = out.parent / (out.name + "-pt")
    for d in (out, pt_dir):
        if d.exists():
            shutil.rmtree(d)
    model.save_pretrained(pt_dir)
    tok.save_pretrained(pt_dir)

    export_onnx(model, tok, pt_dir, out, max_length)
    tok.save_pretrained(str(out))

    calibration = {
        "model": "evident-guard-v0",
        "base_model": base,
        "temperature": temperature,
        "threshold": threshold,
        "max_length": max_length,
        "positive_label": "INJECTION",
        "val_macro_f1": best_f1,
        "val_f1_at_threshold": thr_f1,
        "ece_before": ece_raw,
        "ece_after": ece_cal,
        "trained_on": {"rows": len(train_rows), "epochs_run": len(history), "best_epoch": best_epoch},
        "date": date.today().isoformat(),
    }
    (out / "calibration.json").write_text(json.dumps(calibration, indent=2))

    onnx_mb = (out / "model.onnx").stat().st_size / 1e6
    card = f"""# evident-guard-v0

Prompt-injection classifier fine-tuned from `{base}` on {len(train_rows)} rows
(train split of the EvidentAI eval dataset: deepset/prompt-injections,
xTRam1/safe-guard-prompt-injection, databricks-dolly-15k and tatsu-lab/alpaca
benign instructions). Held-out sources (never trained on):
jackhhao/jailbreak-classification and lakera/gandalf_ignore_instructions.

| Field | Value |
|---|---|
| Date | {calibration['date']} |
| Epochs run / best | {len(history)} / {best_epoch} |
| Training time (CPU, 4 threads) | {train_minutes:.1f} min |
| max_length | {max_length} |
| Validation macro-F1 (argmax) | {best_f1:.4f} |
| Temperature | {temperature:.4f} |
| Decision threshold (max F1 on val) | {threshold:.3f} (F1 {thr_f1:.4f}) |
| ECE before / after calibration | {ece_raw:.4f} / {ece_cal:.4f} |
| ONNX size | {onnx_mb:.1f} MB |

Calibrated probability = softmax(logits / temperature)[INJECTION].

{chr(10).join('- ' + n for n in notes) if notes else '- Trained within the CPU budget without reductions.'}

Known limits: small training set, English only, vulnerable to tokenization
attacks like every small encoder classifier (see the test_perturbed rows in
results/). Not a security boundary on its own; use behind the regex layer with
deferral to an LLM judge in the uncertain band.
"""
    (out / "model_card.md").write_text(card)
    (out / "train_history.json").write_text(json.dumps(history, indent=2))
    print(json.dumps(calibration, indent=2))
    print(f"[train] exported {out} ({onnx_mb:.1f} MB)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
