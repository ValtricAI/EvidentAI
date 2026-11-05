# Detector evaluation (2026-11-05)

Held-out (never trained on) sources for `test_ood`: `jackhhao/jailbreak-classification`, `lakera/gandalf_ignore_instructions`.
`test` is the in-distribution split of the training sources; `test_evident` is the hand-labelled regex corpus; `test_perturbed` applies TokenBreak-style and obfuscation perturbations to attacks from `test` and `test_ood` with the benign rows of those splits unchanged.
Regex scores are an **ordinal severity proxy**, not probabilities: their AUROC only ranks severities. Latency is per text; for batched classifiers it is the batch wall time divided by batch size.

| Split | Rows | Attacks | Benign |
|---|---:|---:|---:|
| test | 836 | 326 | 510 |
| test_evident | 278 | 147 | 131 |
| test_ood | 1740 | 1110 | 630 |
| train | 6689 | 2610 | 4079 |
| val | 836 | 326 | 510 |
| test_perturbed | 4340 | 3200 | 1140 |

## test

| Detector | Kind | Thr | Precision | Recall | F1 | FPR | AUROC | AP | FPR@95%R | Latency mean / p95 (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| regex_low | rule | 0.01 | 0.990 | 0.291 | 0.450 | 0.002 | 0.644 | 0.561 | 1.000 | 0.08 / 0.20 |
| regex_medium | rule | 0.01 | 0.990 | 0.301 | 0.461 | 0.002 | 0.649 | 0.566 | 1.000 | 0.10 / 0.21 |
| regex_high | rule | 0.01 | 0.990 | 0.310 | 0.472 | 0.002 | 0.654 | 0.572 | 1.000 | 0.11 / 0.24 |
| length_only | confound | 0.50 | 0.576 | 0.724 | 0.641 | 0.341 | 0.745 | 0.596 | 0.633 | 0.00 / 0.00 |
| ngram_lr | classifier | 0.50 | 0.984 | 0.948 | 0.966 | 0.010 | 0.996 | 0.994 | 0.012 | 0.33 / 0.53 |
| protectai_deberta_v2 | classifier | 0.50 | 0.996 | 0.813 | 0.895 | 0.002 | 0.986 | 0.985 | 0.027 | 294.21 / 664.13 |
| promptguard2_22m | classifier | - | not measured | | | | | | | gated model; set HF_TOKEN after accepting the licence |
| promptguard2_86m | classifier | - | not measured | | | | | | | gated model; set HF_TOKEN after accepting the licence |
| evident_guard_v0 | classifier | 0.14 | 0.976 | 0.985 | 0.980 | 0.016 | 0.999 | 0.999 | 0.002 | 19.59 / 27.00 |
| jev | external | - | not measured | | | | | | | no TYPESAFE_API_KEY configured (user declined to add a key) |
| llm_judge_gpt4o_mini | external | - | not measured | | | | | | | no OPENAI_API_KEY configured |

## test_ood

| Detector | Kind | Thr | Precision | Recall | F1 | FPR | AUROC | AP | FPR@95%R | Latency mean / p95 (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| regex_low | rule | 0.01 | 0.991 | 0.584 | 0.735 | 0.010 | 0.790 | 0.849 | 1.000 | 0.08 / 0.29 |
| regex_medium | rule | 0.01 | 0.990 | 0.604 | 0.750 | 0.011 | 0.799 | 0.856 | 1.000 | 0.09 / 0.31 |
| regex_high | rule | 0.01 | 0.990 | 0.608 | 0.753 | 0.011 | 0.801 | 0.857 | 1.000 | 0.11 / 0.41 |
| length_only | confound | 0.50 | 0.553 | 0.508 | 0.530 | 0.722 | 0.336 | 0.538 | 0.987 | 0.00 / 0.00 |
| ngram_lr | classifier | 0.50 | 0.952 | 0.932 | 0.942 | 0.083 | 0.978 | 0.989 | 0.106 | 0.62 / 0.86 |
| protectai_deberta_v2 | classifier | 0.50 | 0.996 | 0.983 | 0.990 | 0.006 | 0.998 | 0.998 | 0.002 | 372.54 / 617.29 |
| promptguard2_22m | classifier | - | not measured | | | | | | | gated model; set HF_TOKEN after accepting the licence |
| promptguard2_86m | classifier | - | not measured | | | | | | | gated model; set HF_TOKEN after accepting the licence |
| evident_guard_v0 | classifier | 0.14 | 0.772 | 0.887 | 0.826 | 0.462 | 0.863 | 0.928 | 0.690 | 22.24 / 25.99 |
| jev | external | - | not measured | | | | | | | no TYPESAFE_API_KEY configured (user declined to add a key) |
| llm_judge_gpt4o_mini | external | - | not measured | | | | | | | no OPENAI_API_KEY configured |

## test_evident

| Detector | Kind | Thr | Precision | Recall | F1 | FPR | AUROC | AP | FPR@95%R | Latency mean / p95 (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| regex_low | rule | 0.01 | 1.000 | 0.871 | 0.931 | 0.000 | 0.935 | 0.939 | 1.000 | 0.02 / 0.03 |
| regex_medium | rule | 0.01 | 0.973 | 0.986 | 0.980 | 0.031 | 0.992 | 0.991 | 0.031 | 0.02 / 0.03 |
| regex_high | rule | 0.01 | 0.919 | 1.000 | 0.958 | 0.099 | 0.998 | 0.997 | 0.031 | 0.03 / 0.06 |
| length_only | confound | 0.50 | 0.848 | 0.265 | 0.404 | 0.053 | 0.728 | 0.771 | 0.878 | 0.00 / 0.00 |
| ngram_lr | classifier | 0.50 | 0.902 | 0.755 | 0.822 | 0.092 | 0.911 | 0.928 | 0.466 | 0.10 / 0.17 |
| protectai_deberta_v2 | classifier | 0.50 | 0.948 | 0.871 | 0.908 | 0.053 | 0.965 | 0.960 | 0.168 | 15.37 / 28.79 |
| promptguard2_22m | classifier | - | not measured | | | | | | | gated model; set HF_TOKEN after accepting the licence |
| promptguard2_86m | classifier | - | not measured | | | | | | | gated model; set HF_TOKEN after accepting the licence |
| evident_guard_v0 | classifier | 0.14 | 0.859 | 0.789 | 0.823 | 0.145 | 0.915 | 0.933 | 0.435 | 5.82 / 8.88 |
| jev | external | - | not measured | | | | | | | no TYPESAFE_API_KEY configured (user declined to add a key) |
| llm_judge_gpt4o_mini | external | - | not measured | | | | | | | no OPENAI_API_KEY configured |

## test_perturbed

| Detector | Kind | Thr | Precision | Recall | F1 | FPR | AUROC | AP | FPR@95%R | Latency mean / p95 (ms) |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| regex_low | rule | 0.01 | 0.989 | 0.188 | 0.316 | 0.006 | 0.591 | 0.785 | 1.000 | 0.06 / 0.27 |
| regex_medium | rule | 0.01 | 0.988 | 0.200 | 0.332 | 0.007 | 0.597 | 0.788 | 1.000 | 0.08 / 0.35 |
| regex_high | rule | 0.01 | 0.994 | 0.385 | 0.555 | 0.007 | 0.689 | 0.836 | 1.000 | 0.10 / 0.45 |
| length_only | confound | 0.50 | 0.759 | 0.618 | 0.681 | 0.552 | 0.561 | 0.800 | 0.904 | 0.00 / 0.00 |
| ngram_lr | classifier | 0.50 | 0.976 | 0.727 | 0.833 | 0.050 | 0.930 | 0.974 | 0.393 | 0.47 / 0.66 |
| protectai_deberta_v2 | classifier | 0.50 | 0.998 | 0.932 | 0.964 | 0.004 | 0.996 | 0.998 | 0.007 | 389.36 / 608.61 |
| promptguard2_22m | classifier | - | not measured | | | | | | | gated model; set HF_TOKEN after accepting the licence |
| promptguard2_86m | classifier | - | not measured | | | | | | | gated model; set HF_TOKEN after accepting the licence |
| evident_guard_v0 | classifier | 0.14 | 0.906 | 0.901 | 0.903 | 0.262 | 0.894 | 0.949 | 0.299 | 22.76 / 26.61 |
| jev | external | - | not measured | | | | | | | no TYPESAFE_API_KEY configured (user declined to add a key) |
| llm_judge_gpt4o_mini | external | - | not measured | | | | | | | no OPENAI_API_KEY configured |

## Recall on perturbed attacks, by perturbation type

Each cell is recall at the detector's native threshold on attacks of that type (precision against the unperturbed benign rows is in metrics.json).

| Perturbation | regex_low | regex_medium | regex_high | length_only | ngram_lr | protectai_deberta_v2 | evident_guard_v0 |
|---|---:|---:|---:|---:|---:|---:|---:|
| base64_wrap | 0.000 | 0.000 | 0.665 | 1.000 | 0.018 | 1.000 | 0.762 |
| benign_prefix | 0.512 | 0.535 | 0.542 | 0.682 | 0.830 | 0.927 | 0.940 |
| case_flip | 0.510 | 0.532 | 0.542 | 0.552 | 0.938 | 0.983 | 1.000 |
| homoglyph | 0.087 | 0.095 | 0.868 | 0.552 | 0.828 | 0.927 | 0.905 |
| leetspeak | 0.090 | 0.098 | 0.105 | 0.552 | 0.613 | 0.835 | 0.887 |
| token_break_hyphen | 0.110 | 0.120 | 0.128 | 0.655 | 0.833 | 0.932 | 0.902 |
| token_break_space | 0.107 | 0.120 | 0.128 | 0.295 | 0.873 | 0.917 | 0.895 |
| zero_width | 0.087 | 0.098 | 0.105 | 0.655 | 0.882 | 0.932 | 0.915 |

## Length confound check

Attack and benign rows in public datasets differ in length, so a detector can score well by reading length alone. `length_only` is a logistic regression on log character and word counts; the `length_matched` columns re-score each split on a subset where attacks and benign rows are sampled to the same character-length quartile distribution. A detector whose AUROC collapses toward `length_only` on the matched subset is leaning on length, not content.

### test

| Detector | AUROC (all) | F1 (all) | AUROC (length-matched) | F1 (length-matched) | n matched | AUROC by length quartile (short to long) |
|---|---:|---:|---:|---:|---:|---|
| regex_low | 0.644 | 0.450 | 0.649 | 0.463 | 556 | 0.64 / 0.67 / 0.59 / 0.70 |
| regex_medium | 0.649 | 0.461 | 0.654 | 0.475 | 556 | 0.64 / 0.68 / 0.59 / 0.70 |
| regex_high | 0.654 | 0.472 | 0.658 | 0.484 | 556 | 0.64 / 0.68 / 0.60 / 0.71 |
| length_only | 0.745 | 0.641 | 0.676 | 0.668 | 556 | 0.54 / 0.75 / 0.66 / 0.71 |
| ngram_lr | 0.996 | 0.966 | 0.995 | 0.965 | 556 | 0.99 / 1.00 / 1.00 / 0.98 |
| protectai_deberta_v2 | 0.986 | 0.895 | 0.984 | 0.888 | 556 | 0.93 / 1.00 / 0.99 / 0.97 |
| evident_guard_v0 | 0.999 | 0.980 | 0.999 | 0.982 | 556 | 1.00 / 1.00 / 1.00 / 1.00 |

### test_ood

| Detector | AUROC (all) | F1 (all) | AUROC (length-matched) | F1 (length-matched) | n matched | AUROC by length quartile (short to long) |
|---|---:|---:|---:|---:|---:|---|
| regex_low | 0.790 | 0.735 | 0.860 | 0.836 | 886 | 0.70 / 0.83 / 0.89 / 0.83 |
| regex_medium | 0.799 | 0.750 | 0.865 | 0.844 | 886 | 0.71 / 0.84 / 0.89 / 0.84 |
| regex_high | 0.801 | 0.753 | 0.869 | 0.848 | 886 | 0.71 / 0.84 / 0.90 / 0.85 |
| length_only | 0.336 | 0.530 | 0.577 | 0.623 | 886 | 0.68 / 0.68 / 0.53 / 0.61 |
| ngram_lr | 0.978 | 0.942 | 0.993 | 0.954 | 886 | 0.98 / 0.99 / 0.99 / 0.99 |
| protectai_deberta_v2 | 0.998 | 0.990 | 0.997 | 0.976 | 886 | 1.00 / 1.00 / 1.00 / 0.98 |
| evident_guard_v0 | 0.863 | 0.826 | 0.928 | 0.791 | 886 | 0.84 / 0.90 / 0.93 / 0.98 |

### test_evident

| Detector | AUROC (all) | F1 (all) | AUROC (length-matched) | F1 (length-matched) | n matched | AUROC by length quartile (short to long) |
|---|---:|---:|---:|---:|---:|---|
| regex_low | 0.935 | 0.931 | 0.944 | 0.941 | 252 | 0.85 / 0.97 / 0.97 / 0.97 |
| regex_medium | 0.992 | 0.980 | 0.995 | 0.980 | 252 | 0.98 / 1.00 / 1.00 / 1.00 |
| regex_high | 0.998 | 0.958 | 0.998 | 0.951 | 252 | 1.00 / 1.00 / 1.00 / 1.00 |
| length_only | 0.728 | 0.404 | 0.746 | 0.435 | 252 | 0.72 / 0.72 / 0.73 / 0.79 |
| ngram_lr | 0.911 | 0.822 | 0.917 | 0.840 | 252 | 0.89 / 0.96 / 0.93 / 0.92 |
| protectai_deberta_v2 | 0.965 | 0.908 | 0.964 | 0.901 | 252 | 0.98 / 0.95 / 0.99 / 0.95 |
| evident_guard_v0 | 0.915 | 0.823 | 0.927 | 0.837 | 252 | 0.89 / 0.98 / 0.94 / 0.96 |

## Detector notes

- **regex_low**: score is an ordinal severity proxy, not a probability
- **regex_medium**: score is an ordinal severity proxy, not a probability
- **regex_high**: score is an ordinal severity proxy, not a probability
- **length_only**: logistic regression on log character and word counts only; a detector near this line is reading length, not content
- **ngram_lr**: char_wb 2-5 grams, C=4, class_weight balanced; trained on the train split
- **protectai_deberta_v2**: protectai/deberta-v3-base-prompt-injection-v2; P(positive label), max_length 512
- **promptguard2_22m**: meta-llama/Llama-Prompt-Guard-2-22M; P(positive label), max_length 512
- **promptguard2_86m**: meta-llama/Llama-Prompt-Guard-2-86M; P(positive label), max_length 512
- **evident_guard_v0**: deberta-v3-xsmall fine-tune, ONNX, temperature 1.634, threshold 0.140
- **jev**: TypeSafe systemone API, one score question per text; untested against the live API
- **llm_judge_gpt4o_mini**: gpt-4o-mini, temperature 0, one call per text
