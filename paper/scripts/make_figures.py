#!/usr/bin/env python
"""Generate the paper's result figures and LaTeX tables from the harness output.

Two modes:

    python scripts/make_figures.py            # newest packages/evals/results/*/metrics.json
    python scripts/make_figures.py --fixture  # scripts/fixture_metrics.json (synthetic)

Fixture mode writes ``tables/mode.tex`` with ``\\resultsmodefixture`` so that
``main.tex`` renders a DRAFT banner and a "RESULTS PENDING: synthetic fixture"
watermark. Real mode writes ``\\resultsmodefinal``. Synthetic numbers can
therefore never appear in an un-watermarked PDF.

Every number quoted in the prose of main.tex is a macro emitted here, so the
text cannot drift from the tables.

Figures follow the data-visualisation method: colour assigned by job
(categorical identity in a fixed slot order, one-hue sequential ramp for
magnitude), thin marks, direct labels where they fit, legends whenever more
than one series is drawn, and a texture (hatching) rather than colour alone
for the "not measured" state. The four-colour categorical palette passes the
validator (worst adjacent CVD distance 9.1, normal-vision 22.9).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

HERE = Path(__file__).resolve().parent
PAPER = HERE.parent
REPO = PAPER.parent
RESULTS_ROOT = REPO / "packages" / "evals" / "results"
FIG_DIR = PAPER / "figures"
TAB_DIR = PAPER / "tables"

# Reference palette (categorical slots in fixed order, sequential blue ramp, ink).
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
SEQ_RAMP = ["#cde2fb", "#b7d3f6", "#9ec5f4", "#86b6ef", "#6da7ec", "#5598e7", "#3987e5", "#2a78d6", "#256abf", "#1c5cab", "#184f95", "#104281", "#0d366b"]
INK = "#0b0b0b"
INK_2 = "#52514e"
MUTED = "#898781"
GRID = "#e1e0d9"
AXIS = "#c3c2b7"
SURFACE = "#fcfcfb"

SPLITS = ["test", "test_ood", "test_evident", "test_perturbed"]
SPLIT_LABEL = {
    "test": "in-distribution",
    "test_ood": "out-of-distribution",
    "test_evident": "hand-labelled corpus",
    "test_perturbed": "perturbed",
}
DETECTOR_LABEL = {
    "regex_low": "regex (low)",
    "regex_medium": "regex (medium)",
    "regex_high": "regex (high)",
    "length_only": "length-only (confound)",
    "ngram_lr": "char n-gram LR",
    "protectai_deberta_v2": "ProtectAI DeBERTa v2",
    "evident_guard_v0": "Evident Guard v0",
    "promptguard2_22m": "Prompt Guard 2 (22M)",
    "promptguard2_86m": "Prompt Guard 2 (86M)",
    "jev": "Jev (TypeSafe)",
    "llm_judge_gpt4o_mini": "LLM judge (gpt-4o-mini)",
}
# Short labels for wide tables.
DETECTOR_SHORT = {
    "regex_low": "regex L",
    "regex_medium": "regex M",
    "regex_high": "regex H",
    "length_only": "length",
    "ngram_lr": "n-gram LR",
    "protectai_deberta_v2": "DeBERTa v2",
    "evident_guard_v0": "EG v0",
}
# Fixed display order (identity never follows rank).
DETECTOR_ORDER = list(DETECTOR_LABEL)
PERTURBATION_ORDER = [
    "token_break_space",
    "token_break_hyphen",
    "zero_width",
    "homoglyph",
    "leetspeak",
    "case_flip",
    "benign_prefix",
    "base64_wrap",
]

plt.rcParams.update(
    {
        "font.family": "sans-serif",
        "font.size": 8,
        "axes.edgecolor": AXIS,
        "axes.labelcolor": INK_2,
        "axes.titlecolor": INK,
        "xtick.color": INK_2,
        "ytick.color": INK_2,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": False,
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "pdf.fonttype": 42,
    }
)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def newest_results() -> Path:
    if not RESULTS_ROOT.exists():
        sys.exit(f"[make_figures] no results directory at {RESULTS_ROOT}; run `python -m evals.run` or use --fixture")
    candidates = sorted(p for p in RESULTS_ROOT.glob("*/metrics.json"))
    if not candidates:
        sys.exit(f"[make_figures] no metrics.json under {RESULTS_ROOT}; run `python -m evals.run` or use --fixture")
    return candidates[-1]


def load(fixture: bool) -> tuple[dict, str, Path]:
    if fixture:
        path = HERE / "fixture_metrics.json"
        mode = "fixture"
    else:
        path = newest_results()
        mode = "final"
    data = json.loads(path.read_text())
    return data, mode, path


def measured(data: dict) -> list[str]:
    return [n for n in DETECTOR_ORDER if n in data["detectors"] and data["detectors"][n].get("available")]


def unmeasured(data: dict) -> list[tuple[str, str]]:
    return [
        (n, data["detectors"][n].get("unavailable_reason", ""))
        for n in DETECTOR_ORDER
        if n in data["detectors"] and not data["detectors"][n].get("available")
    ]


def split_metrics(data: dict, det: str, split: str) -> dict | None:
    m = data["detectors"].get(det, {}).get("splits", {}).get(split)
    if not m or "error" in m:
        return None
    return m


def metric(data: dict, det: str, split: str, key: str):
    m = split_metrics(data, det, split)
    if not m:
        return None
    if key.startswith("latency."):
        return (m.get("latency") or {}).get(key.split(".", 1)[1])
    if key.startswith("length_matched."):
        lm = m.get("length_matched")
        return (lm or {}).get(key.split(".", 1)[1]) if isinstance(lm, dict) else None
    return m.get(key)


def fmt(v, digits: int = 3, pct: bool = False) -> str:
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "--"
    if pct:
        return f"{100 * v:.1f}"
    return f"{v:.{digits}f}"


def tex_escape(s: str) -> str:
    return (
        s.replace("\\", r"\textbackslash{}")
        .replace("_", r"\_")
        .replace("%", r"\%")
        .replace("&", r"\&")
        .replace("#", r"\#")
    )


_DIGIT_WORDS = {"0": "zero", "1": "one", "2": "two", "3": "three", "4": "four", "5": "five", "6": "six", "7": "seven", "8": "eight", "9": "nine"}


def macro_key(name: str) -> str:
    """LaTeX control sequences are letters only: drop underscores, spell digits."""
    return "".join(_DIGIT_WORDS.get(c, c) for c in name.replace("_", "") if c.isalnum())


# ---------------------------------------------------------------------------
# Figures
# ---------------------------------------------------------------------------

def style_axes(ax, ygrid: bool = True):
    if ygrid:
        ax.yaxis.grid(True, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)
    ax.tick_params(length=0)
    for spine in ("left", "bottom"):
        ax.spines[spine].set_color(AXIS)


def fig_auroc(data: dict, out: Path) -> None:
    dets = [d for d in measured(data) if d != "length_only"]
    missing = unmeasured(data)
    names = dets + [n for n, _ in missing]
    x = np.arange(len(names))
    width = 0.19
    fig, ax = plt.subplots(figsize=(6.6, 2.9))
    for i, split in enumerate(SPLITS):
        vals = [metric(data, d, split, "auroc") for d in dets] + [None] * len(missing)
        offs = x + (i - 1.5) * width
        heights = [v if v is not None else 0 for v in vals]
        ax.bar(offs, heights, width - 0.02, color=SERIES[i], label=SPLIT_LABEL[split], linewidth=0)
    # Not-measured detectors: hatched empty bars across the full group.
    for j, (_name, _reason) in enumerate(missing):
        xi = x[len(dets) + j]
        ax.bar(xi, 1.0, width * 4 - 0.04, facecolor="none", edgecolor=MUTED, hatch="////", linewidth=0.6)
        ax.text(xi, 0.5, "not\nmeasured", ha="center", va="center", fontsize=7, color=INK_2)
    # Reference lines: chance, and the length-only confound on the OOD split.
    handles, labels = ax.get_legend_handles_labels()
    chance = ax.axhline(0.5, color=INK_2, linewidth=0.7, linestyle=(0, (3, 3)), label="chance (0.5)")
    handles.append(chance)
    labels.append("chance (0.5)")
    lo = metric(data, "length_only", "test_ood", "auroc")
    if lo is not None:
        line = ax.axhline(lo, color=INK_2, linewidth=0.9, linestyle=(0, (1, 2)), label=f"length-only confound, OOD ({lo:.2f})")
        handles.append(line)
        labels.append(f"length-only confound, OOD ({lo:.2f})")
    ax.set_xticks(x)
    ax.set_xticklabels([DETECTOR_LABEL.get(n, n) for n in names], rotation=20, ha="right")
    ax.set_ylim(0, 1.0)
    ax.set_ylabel("AUROC")
    style_axes(ax)
    ax.legend(handles, labels, frameon=False, ncol=3, loc="lower center", bbox_to_anchor=(0.5, 1.0), fontsize=7)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def perturbation_types(data: dict, dets: list[str]) -> list[str]:
    present = {t for d in dets for t in (split_metrics(data, d, "test_perturbed") or {}).get("by_perturbation", {})}
    return [t for t in PERTURBATION_ORDER if t in present] + sorted(present - set(PERTURBATION_ORDER))


def fig_perturbation_heatmap(data: dict, out: Path) -> None:
    dets = [d for d in measured(data) if "by_perturbation" in (split_metrics(data, d, "test_perturbed") or {})]
    if not dets:
        return
    types = perturbation_types(data, dets)
    rows = ["unperturbed, in-dist.", "unperturbed, OOD"] + types
    mat = np.full((len(rows), len(dets)), np.nan)
    for j, d in enumerate(dets):
        mat[0, j] = metric(data, d, "test", "recall") if metric(data, d, "test", "recall") is not None else np.nan
        mat[1, j] = metric(data, d, "test_ood", "recall") if metric(data, d, "test_ood", "recall") is not None else np.nan
        bp = split_metrics(data, d, "test_perturbed")["by_perturbation"]
        for i, t in enumerate(types, start=2):
            mat[i, j] = bp.get(t, {}).get("recall", np.nan)
    cmap = matplotlib.colors.LinearSegmentedColormap.from_list("seq", SEQ_RAMP)
    fig, ax = plt.subplots(figsize=(6.6, 0.3 * len(rows) + 1.3))
    im = ax.imshow(mat, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(dets)))
    ax.set_xticklabels([DETECTOR_LABEL.get(d, d) for d in dets], rotation=20, ha="right")
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([r.replace("_", " ") for r in rows])
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_xticks(np.arange(-0.5, len(dets), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rows), 1), minor=True)
    ax.grid(which="minor", color=SURFACE, linewidth=2)
    ax.tick_params(which="minor", length=0)
    ax.axhline(1.5, color=INK_2, linewidth=0.8)
    for i in range(len(rows)):
        for j in range(len(dets)):
            v = mat[i, j]
            if np.isnan(v):
                continue
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=6.5, color="#ffffff" if v > 0.55 else INK)
    cb = fig.colorbar(im, ax=ax, fraction=0.03, pad=0.02)
    cb.set_label("recall at native threshold", color=INK_2)
    cb.outline.set_visible(False)
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def fig_latency_vs_auroc(data: dict, out: Path) -> None:
    dets = [d for d in measured(data) if d != "length_only"]
    fig, ax = plt.subplots(figsize=(4.8, 3.1))
    markers = {"rule": "s", "classifier": "o", "external": "D", "confound": "^"}
    for d in dets:
        lat = metric(data, d, "test_ood", "latency.mean_ms")
        au = metric(data, d, "test_ood", "auroc")
        if lat is None or au is None or lat <= 0:
            continue
        kind = data["detectors"][d].get("kind", "classifier")
        ax.scatter(lat, au, s=40, color=SERIES[0], marker=markers.get(kind, "o"), edgecolor=SURFACE, linewidth=1.2, zorder=3)
        dx, dy, ha = 6, 4, "left"
        if d == "regex_low":
            dy = -12
        elif d == "regex_high":
            dy = 11
        elif d == "protectai_deberta_v2":
            dx, dy, ha = -6, -12, "right"
        ax.annotate(DETECTOR_LABEL.get(d, d), (lat, au), textcoords="offset points", xytext=(dx, dy), fontsize=7, color=INK, ha=ha)
    ax.set_xscale("log")
    ax.set_xlabel("mean latency per text, ms (log scale, 4 CPU cores)")
    ax.set_ylabel("AUROC, out-of-distribution split")
    ax.set_ylim(0.5, 1.02)
    style_axes(ax)
    ax.xaxis.grid(True, color=GRID, linewidth=0.6)
    legend = [
        plt.Line2D([], [], marker="s", linestyle="", color=SERIES[0], label="rule-based (ordinal score)"),
        plt.Line2D([], [], marker="o", linestyle="", color=SERIES[0], label="classifier (probability)"),
    ]
    ax.legend(handles=legend, frameon=False, fontsize=7, loc="lower right")
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)


def fig_deferral(data: dict, out: Path) -> str:
    """Analytic expected-latency curves of the cascade as a function of the deferral rate.

    The harness stores aggregate metrics, not per-row scores, so the curve is
    the cost model E[L] = L_regex + L_clf + p_defer * L_judge evaluated with the
    measured regex and classifier latencies and three assumed judge latencies.
    Returns a caption fragment.
    """
    l_regex = metric(data, "regex_medium", "test_ood", "latency.mean_ms") or 0.1
    clfs = [c for c in ("evident_guard_v0", "protectai_deberta_v2") if c in measured(data)]
    fig, axes = plt.subplots(1, max(1, len(clfs)), figsize=(6.6, 2.7), sharey=True)
    if len(clfs) <= 1:
        axes = [axes]
    p = np.linspace(0, 0.5, 51)
    judge_latencies = (500, 1500, 4000)
    for ax, clf in zip(axes, clfs):
        l_clf = metric(data, clf, "test_ood", "latency.mean_ms") or 25.0
        for i, l_judge in enumerate(judge_latencies):
            ax.plot(p, l_regex + l_clf + p * l_judge, color=SERIES[i], linewidth=2, label=f"judge {l_judge} ms")
        ax.axhline(l_regex + l_clf, color=MUTED, linewidth=0.8, linestyle=(0, (4, 3)))
        ax.text(0.49, (l_regex + l_clf) * 1.15, f"no deferral: {l_regex + l_clf:.0f} ms", fontsize=6.5, color=MUTED, ha="right")
        ax.set_title(f"stage 2 = {DETECTOR_LABEL[clf]} ({l_clf:.0f} ms)", fontsize=8, color=INK)
        ax.set_xlabel("deferral rate $p_\\mathrm{defer}$")
        ax.set_yscale("log")
        ax.set_ylim(5, 5000)
        style_axes(ax)
    axes[0].set_ylabel("expected latency per request (ms)")
    axes[0].legend(frameon=False, fontsize=7, loc="upper left")
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    variant = f"analytic cost model with the measured regex ({l_regex:.2f} ms) and classifier latencies"
    return variant


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def table_results(data: dict, split: str, include_unmeasured: bool = True) -> str:
    dets = measured(data)
    lines = [
        r"\begin{tabular}{@{}llrrrrrrrrr@{}}",
        r"\toprule",
        r"Detector & Kind & Thr. & P & R & F$_1$ & FPR & AUROC & AP & FPR@95\%R & ms/text \\",
        r"\midrule",
    ]
    for d in dets:
        m = split_metrics(data, d, split)
        kind = data["detectors"][d].get("kind", "")
        if not m:
            lines.append(f"{tex_escape(DETECTOR_LABEL.get(d, d))} & {kind} & \\multicolumn{{9}}{{l}}{{error}} \\\\")
            continue
        lat = (m.get("latency") or {}).get("mean_ms")
        lines.append(
            " & ".join(
                [
                    tex_escape(DETECTOR_LABEL.get(d, d)),
                    kind,
                    fmt(m.get("threshold"), 2),
                    fmt(m.get("precision")),
                    fmt(m.get("recall")),
                    fmt(m.get("f1")),
                    fmt(m.get("fpr")),
                    fmt(m.get("auroc")),
                    fmt(m.get("average_precision")),
                    fmt(m.get("fpr_at_95_recall")),
                    fmt(lat, 2) if lat else "--",
                ]
            )
            + r" \\"
        )
    miss = unmeasured(data)
    if miss and include_unmeasured:
        lines.append(r"\midrule")
        for d, reason in miss:
            kind = data["detectors"][d].get("kind", "")
            lines.append(f"{tex_escape(DETECTOR_LABEL.get(d, d))} & {kind} & \\multicolumn{{9}}{{l}}{{\\emph{{not measured}}: {tex_escape(reason[:60])}}} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines)


def table_manifest(data: dict) -> str:
    man = data.get("manifest", {})
    splits = man.get("splits", {})
    lines = [r"\begin{tabular}{@{}lrrr@{}}", r"\toprule", r"Split & Rows & Attacks & Benign \\", r"\midrule"]
    for s in ["train", "val", "test", "test_ood", "test_evident", "test_perturbed"]:
        info = splits.get(s)
        if not info:
            continue
        lines.append(f"\\texttt{{{tex_escape(s)}}} & {info['total']} & {info['attack']} & {info['benign']} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines)


def table_perturbation(data: dict) -> str:
    dets = [d for d in measured(data) if "by_perturbation" in (split_metrics(data, d, "test_perturbed") or {})]
    if not dets:
        return r"\emph{No perturbation breakdown in the results.}"
    types = perturbation_types(data, dets)
    cols = "l" + "r" * len(dets)
    lines = [f"\\begin{{tabular}}{{@{{}}{cols}@{{}}}}", r"\toprule",
             "Perturbation & " + " & ".join(tex_escape(DETECTOR_SHORT.get(d, DETECTOR_LABEL.get(d, d))) for d in dets) + r" \\", r"\midrule"]
    lines.append(" & ".join(["unperturbed, in-distribution"] + [fmt(metric(data, d, "test", "recall")) for d in dets]) + r" \\")
    lines.append(" & ".join(["unperturbed, OOD"] + [fmt(metric(data, d, "test_ood", "recall")) for d in dets]) + r" \\")
    lines.append(r"\midrule")
    for t in types:
        row = [tex_escape(t.replace("_", " "))] + [fmt(split_metrics(data, d, "test_perturbed")["by_perturbation"].get(t, {}).get("recall")) for d in dets]
        lines.append(" & ".join(row) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines)


def table_length(data: dict, split: str) -> str:
    dets = measured(data)
    lines = [
        r"\begin{tabular}{@{}lrrrrrl@{}}",
        r"\toprule",
        r"Detector & AUROC & F$_1$ & AUROC$_\mathrm{m}$ & F$_{1,\mathrm{m}}$ & $n_\mathrm{m}$ & AUROC by length quartile \\",
        r"\midrule",
    ]
    any_row = False
    for d in dets:
        m = split_metrics(data, d, split)
        if not m or not isinstance(m.get("length_matched"), dict):
            continue
        any_row = True
        lm = m["length_matched"]
        buckets = m.get("by_length_bucket", {})
        quart = " / ".join(fmt((buckets.get(b) or {}).get("auroc"), 2) for b in ("q1_short", "q2", "q3", "q4_long"))
        lines.append(
            " & ".join(
                [
                    tex_escape(DETECTOR_LABEL.get(d, d)),
                    fmt(m.get("auroc")),
                    fmt(m.get("f1")),
                    fmt(lm.get("auroc")),
                    fmt(lm.get("f1")),
                    str(lm.get("n", "--")),
                    quart,
                ]
            )
            + r" \\"
        )
    if not any_row:
        return r"\emph{No length-confound breakdown in the results.}"
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines)


def macros(data: dict, mode: str, deferral_variant: str, results_path: Path) -> str:
    """Numbers quoted in prose, as macros, so text never drifts from the tables."""
    man = data.get("manifest", {})
    splits = man.get("splits", {})

    def n(split, key):
        return str(splits.get(split, {}).get(key, "--"))

    ood = ", ".join(tex_escape(s) for s in data.get("ood_sources", []))
    best = None
    for d in measured(data):
        if d == "length_only":
            continue
        v = metric(data, d, "test_ood", "auroc")
        if v is not None and (best is None or v > best[1]):
            best = (d, v)
    lines = [
        f"\\newcommand{{\\resultsmode}}{{{mode}}}",
        f"\\newcommand{{\\resultsdate}}{{{tex_escape(str(data.get('date', 'unknown')))}}}",
        f"\\newcommand{{\\resultspath}}{{{tex_escape(str(results_path.relative_to(REPO)) if results_path.is_relative_to(REPO) else results_path.name)}}}",
        f"\\newcommand{{\\oodsources}}{{{ood}}}",
        f"\\newcommand{{\\nraw}}{{{man.get('raw_rows', '--')}}}",
        f"\\newcommand{{\\ndedupe}}{{{man.get('after_dedupe', '--')}}}",
        f"\\newcommand{{\\ncaps}}{{{man.get('after_caps', '--')}}}",
        f"\\newcommand{{\\ntrain}}{{{n('train', 'total')}}}",
        f"\\newcommand{{\\ntrainattack}}{{{n('train', 'attack')}}}",
        f"\\newcommand{{\\ntrainbenign}}{{{n('train', 'benign')}}}",
        f"\\newcommand{{\\nval}}{{{n('val', 'total')}}}",
        f"\\newcommand{{\\ntest}}{{{n('test', 'total')}}}",
        f"\\newcommand{{\\ntestood}}{{{n('test_ood', 'total')}}}",
        f"\\newcommand{{\\ntestoodattack}}{{{n('test_ood', 'attack')}}}",
        f"\\newcommand{{\\ntestoodbenign}}{{{n('test_ood', 'benign')}}}",
        f"\\newcommand{{\\ntestevident}}{{{n('test_evident', 'total')}}}",
        f"\\newcommand{{\\ntestperturbed}}{{{n('test_perturbed', 'total')}}}",
        f"\\newcommand{{\\ntestperturbedattack}}{{{n('test_perturbed', 'attack')}}}",
        f"\\newcommand{{\\nperturbtype}}{{{(man.get('perturbation') or {}).get('max_attacks_per_type', '--')}}}",
        f"\\newcommand{{\\bestooddetector}}{{{tex_escape(DETECTOR_LABEL.get(best[0], best[0])) if best else '--'}}}",
        f"\\newcommand{{\\bestoodauroc}}{{{fmt(best[1]) if best else '--'}}}",
        f"\\newcommand{{\\deferralvariant}}{{{tex_escape(deferral_variant)}}}",
    ]
    metrics_wanted = (
        ("auroc", "auroc"),
        ("recall", "recall"),
        ("precision", "precision"),
        ("f1", "fone"),
        ("fpr", "fpr"),
        ("average_precision", "ap"),
        ("fpr_at_95_recall", "fpratrecall"),
        ("latency.mean_ms", "latency"),
        ("latency.p95_ms", "latencypninefive"),
        ("length_matched.auroc", "lmauroc"),
        ("length_matched.f1", "lmfone"),
    )
    for d in DETECTOR_ORDER:
        key = macro_key(d)
        for split in SPLITS:
            s = macro_key(split)
            for m, short in metrics_wanted:
                v = metric(data, d, split, m)
                digits = 2 if m.startswith("latency") else 3
                if m.startswith("latency") and v is not None and v >= 100:
                    digits = 0
                lines.append(f"\\newcommand{{\\m{key}{s}{short}}}{{{fmt(v, digits)}}}")
        # FPR as a percentage for prose.
        v = metric(data, d, "test_ood", "fpr")
        lines.append(f"\\newcommand{{\\m{key}testoodfprpct}}{{{fmt(v, pct=True)}}}")
        # Per-perturbation recall.
        bp = (split_metrics(data, d, "test_perturbed") or {}).get("by_perturbation", {})
        for t in PERTURBATION_ORDER:
            lines.append(f"\\newcommand{{\\mp{key}{macro_key(t)}}}{{{fmt((bp.get(t) or {}).get('recall'))}}}")
    if mode == "fixture":
        lines.append(r"\newcommand{\resultsmodefixture}{}")
    else:
        lines.append(r"\newcommand{\resultsmodefinal}{}")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fixture", action="store_true", help="use scripts/fixture_metrics.json (synthetic; watermarked)")
    args = ap.parse_args()
    data, mode, path = load(args.fixture)
    FIG_DIR.mkdir(exist_ok=True)
    TAB_DIR.mkdir(exist_ok=True)

    fig_auroc(data, FIG_DIR / "auroc.pdf")
    fig_perturbation_heatmap(data, FIG_DIR / "perturbation.pdf")
    fig_latency_vs_auroc(data, FIG_DIR / "latency_auroc.pdf")
    variant = fig_deferral(data, FIG_DIR / "deferral.pdf")

    for split in SPLITS:
        (TAB_DIR / f"results_{split}.tex").write_text(table_results(data, split, include_unmeasured=(split == "test_ood")) + "\n")
    for split in ("test", "test_ood", "test_evident"):
        (TAB_DIR / f"length_{split}.tex").write_text(table_length(data, split) + "\n")
    (TAB_DIR / "manifest.tex").write_text(table_manifest(data) + "\n")
    (TAB_DIR / "perturbation.tex").write_text(table_perturbation(data) + "\n")
    (TAB_DIR / "mode.tex").write_text(macros(data, mode, variant, path))
    print(f"[make_figures] mode={mode} source={path}")
    print(f"[make_figures] measured: {', '.join(measured(data))}")
    print(f"[make_figures] not measured: {', '.join(n for n, _ in unmeasured(data)) or 'none'}")
    print(f"[make_figures] deferral figure: {variant}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
