"""Run every detector on every test split and write the results tables.

    python -m evals.run [--only regex_medium,ngram_lr] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from collections import defaultdict
from datetime import date
from pathlib import Path

from . import DATA_DIR, RESULTS_DIR
from .data import OOD_SOURCES, read_split
from .detectors import build_detectors
from .length import length_buckets, length_matched_indices
from .metrics import evaluate, fmt

SPLITS = ("test", "test_ood", "test_evident", "test_perturbed")


def stratified_head(rows: list[dict], limit: int) -> list[dict]:
    """A smoke-test subset that keeps both classes (and perturbation types) represented."""
    if len(rows) <= limit:
        return rows
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        groups[(int(r["label"]), r.get("perturbation", ""))].append(r)
    per_group = max(1, limit // len(groups))
    out: list[dict] = []
    for key in sorted(groups):
        out.extend(groups[key][:per_group])
    return out[:limit] if len(out) > limit else out


def run(only: set[str] | None = None, limit: int | None = None, out_root: Path = RESULTS_DIR) -> dict:
    manifest = json.loads((DATA_DIR / "manifest.json").read_text()) if (DATA_DIR / "manifest.json").exists() else {}
    splits = {name: read_split(name) for name in SPLITS}
    if limit:
        splits = {k: stratified_head(v, limit) for k, v in splits.items()}
    train_rows = read_split("train")

    detectors = build_detectors(train_rows)
    results: dict = {
        "date": date.today().isoformat(),
        "ood_sources": list(OOD_SOURCES),
        "manifest": manifest,
        "detectors": {},
    }

    for det in detectors:
        if only and det.name not in only:
            continue
        entry = det.describe()
        entry["splits"] = {}
        if not det.available:
            print(f"[run] {det.name}: not measured ({det.unavailable_reason})", file=sys.stderr)
            results["detectors"][det.name] = entry
            continue
        for split_name, rows in splits.items():
            if not rows:
                continue
            texts = [r["text"] for r in rows]
            labels = [int(r["label"]) for r in rows]
            t0 = time.perf_counter()
            try:
                res = det.score(texts)
            except Exception as exc:  # keep the report going; record the failure
                entry["splits"][split_name] = {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}
                print(f"[run] {det.name} on {split_name} failed: {exc}", file=sys.stderr)
                continue
            wall = time.perf_counter() - t0
            metrics = evaluate(labels, res.scores, det.threshold, res.latencies_ms)
            metrics["wall_seconds"] = wall

            # Length confound: metrics per character-length quartile and on a
            # subset where attacks and benign rows share the length distribution.
            buckets, edges = length_buckets(texts)
            metrics["length_bucket_edges_chars"] = edges
            by_bucket = {}
            for b in sorted(set(buckets)):
                idx = [i for i, bb in enumerate(buckets) if bb == b]
                by_bucket[b] = evaluate([labels[i] for i in idx], [res.scores[i] for i in idx], det.threshold)
            metrics["by_length_bucket"] = by_bucket
            matched = length_matched_indices(labels, buckets)
            metrics["length_matched"] = (
                evaluate([labels[i] for i in matched], [res.scores[i] for i in matched], det.threshold)
                if matched else None
            )
            if split_name == "test_perturbed":
                by_type: dict[str, list[int]] = defaultdict(list)
                for i, r in enumerate(rows):
                    by_type[r.get("perturbation", "none")].append(i)
                benign_idx = by_type.get("none", [])
                breakdown = {}
                for ptype, idx in sorted(by_type.items()):
                    if ptype == "none":
                        continue
                    # Each perturbation type is scored together with the unperturbed benign rows.
                    sel = idx + benign_idx
                    breakdown[ptype] = evaluate([labels[i] for i in sel], [res.scores[i] for i in sel], det.threshold)
                metrics["by_perturbation"] = breakdown
            entry["splits"][split_name] = metrics
            print(f"[run] {det.name:24s} {split_name:15s} P={fmt(metrics['precision'])} R={fmt(metrics['recall'])} F1={fmt(metrics['f1'])} AUROC={fmt(metrics['auroc'])} ({wall:.1f}s)", file=sys.stderr)
        results["detectors"][det.name] = entry

    out_dir = out_root / results["date"]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(json.dumps(results, indent=2))
    md = render_markdown(results)
    (out_dir / "README.md").write_text(md)
    shutil.copyfile(out_dir / "README.md", out_root / "latest.md")
    return results


def render_markdown(results: dict) -> str:
    manifest = results.get("manifest", {})
    counts = manifest.get("splits", {})
    lines = [f"# Detector evaluation ({results['date']})", ""]
    lines.append(
        "Held-out (never trained on) sources for `test_ood`: " + ", ".join(f"`{s}`" for s in results["ood_sources"]) + "."
    )
    lines.append(
        "`test` is the in-distribution split of the training sources; `test_evident` is the hand-labelled "
        "regex corpus; `test_perturbed` applies TokenBreak-style and obfuscation perturbations to attacks from "
        "`test` and `test_ood` with the benign rows of those splits unchanged."
    )
    lines.append(
        "Regex scores are an **ordinal severity proxy**, not probabilities: their AUROC only ranks severities. "
        "Latency is per text; for batched classifiers it is the batch wall time divided by batch size."
    )
    lines.append("")
    if counts:
        lines.append("| Split | Rows | Attacks | Benign |")
        lines.append("|---|---:|---:|---:|")
        for split, info in counts.items():
            lines.append(f"| {split} | {info['total']} | {info['attack']} | {info['benign']} |")
        lines.append("")

    for split in SPLITS:
        lines.append(f"## {split}")
        lines.append("")
        lines.append("| Detector | Kind | Thr | Precision | Recall | F1 | FPR | AUROC | AP | FPR@95%R | Latency mean / p95 (ms) |")
        lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|")
        for name, entry in results["detectors"].items():
            if not entry["available"]:
                lines.append(f"| {name} | {entry['kind']} | - | not measured | | | | | | | {entry['unavailable_reason']} |")
                continue
            m = entry["splits"].get(split)
            if not m:
                continue
            if "error" in m:
                lines.append(f"| {name} | {entry['kind']} | - | error | | | | | | | {m['error']} |")
                continue
            lat = m.get("latency", {})
            lines.append(
                f"| {name} | {entry['kind']} | {fmt(m['threshold'], 2)} | {fmt(m['precision'])} | {fmt(m['recall'])} | "
                f"{fmt(m['f1'])} | {fmt(m['fpr'])} | {fmt(m['auroc'])} | {fmt(m['average_precision'])} | "
                f"{fmt(m['fpr_at_95_recall'])} | {fmt(lat.get('mean_ms'), 2)} / {fmt(lat.get('p95_ms'), 2)} |"
            )
        lines.append("")

    # Perturbation breakdown: recall per type (attacks only), one column per detector.
    names = [n for n, e in results["detectors"].items() if e["available"] and "test_perturbed" in e["splits"] and "by_perturbation" in e["splits"]["test_perturbed"]]
    if names:
        types = sorted({t for n in names for t in results["detectors"][n]["splits"]["test_perturbed"]["by_perturbation"]})
        lines.append("## Recall on perturbed attacks, by perturbation type")
        lines.append("")
        lines.append("Each cell is recall at the detector's native threshold on attacks of that type (precision against the unperturbed benign rows is in metrics.json).")
        lines.append("")
        lines.append("| Perturbation | " + " | ".join(names) + " |")
        lines.append("|---|" + "---:|" * len(names))
        for t in types:
            row = [fmt(results["detectors"][n]["splits"]["test_perturbed"]["by_perturbation"][t]["recall"]) for n in names]
            lines.append(f"| {t} | " + " | ".join(row) + " |")
        lines.append("")

    # Length confound check.
    avail = [n for n, e in results["detectors"].items() if e["available"]]
    if avail:
        lines.append("## Length confound check")
        lines.append("")
        lines.append(
            "Attack and benign rows in public datasets differ in length, so a detector can score well by reading "
            "length alone. `length_only` is a logistic regression on log character and word counts; the "
            "`length_matched` columns re-score each split on a subset where attacks and benign rows are sampled to the "
            "same character-length quartile distribution. A detector whose AUROC collapses toward `length_only` on the "
            "matched subset is leaning on length, not content."
        )
        lines.append("")
        for split in ("test", "test_ood", "test_evident"):
            rows_out = []
            for n in avail:
                m = results["detectors"][n]["splits"].get(split)
                if not m or "error" in m:
                    continue
                lm = m.get("length_matched")
                bucket_auroc = " / ".join(
                    fmt(m["by_length_bucket"][b]["auroc"], 2) for b in sorted(m.get("by_length_bucket", {}))
                )
                rows_out.append(
                    f"| {n} | {fmt(m['auroc'])} | {fmt(m['f1'])} | "
                    f"{fmt(lm['auroc']) if lm else '-'} | {fmt(lm['f1']) if lm else '-'} | {lm['n'] if lm else '-'} | {bucket_auroc} |"
                )
            if rows_out:
                lines.append(f"### {split}")
                lines.append("")
                lines.append("| Detector | AUROC (all) | F1 (all) | AUROC (length-matched) | F1 (length-matched) | n matched | AUROC by length quartile (short to long) |")
                lines.append("|---|---:|---:|---:|---:|---:|---|")
                lines.extend(rows_out)
                lines.append("")

    notes = [f"- **{n}**: {e['notes']}" for n, e in results["detectors"].items() if e.get("notes")]
    if notes:
        lines.append("## Detector notes")
        lines.append("")
        lines.extend(notes)
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None, help="comma-separated detector names")
    ap.add_argument("--limit", type=int, default=None, help="rows per split (smoke test)")
    args = ap.parse_args(argv)
    only = set(args.only.split(",")) if args.only else None
    results = run(only=only, limit=args.limit)
    print((RESULTS_DIR / "latest.md").read_text())
    return 0 if results["detectors"] else 1


if __name__ == "__main__":
    sys.exit(main())
