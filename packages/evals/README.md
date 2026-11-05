# evidentai-evals

Evaluation harness for prompt-injection detectors. It builds a labelled
dataset from public sources, applies TokenBreak-style perturbations, scores
every detector we ship or compare against, trains and calibrates our own
classifier, and writes the results tables that the top-level README cites.

Everything runs on CPU. Data and model artifacts are generated locally and are
not committed; the summary tables under `results/` are.

## Setup

```bash
cd packages/evals
python3 -m venv .venv && . .venv/bin/activate
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
```

## Workflow

```bash
python -m evals.data      # download, dedupe, split  -> data/*.jsonl, data/manifest.json
python -m evals.perturb   # perturb test attacks     -> data/test_perturbed.jsonl
python -m evals.train     # fine-tune + calibrate + ONNX export -> models/evident-guard-v0/
python -m evals.run       # score every detector     -> results/<date>/, results/latest.md
pytest                    # unit tests, no network
```

`python -m evals.run --only regex_medium,ngram_lr --limit 200` is a quick smoke test.

## Splits

| Split | What it is |
|---|---|
| `train` / `val` / `test` | Stratified row split of the in-distribution sources: deepset/prompt-injections, xTRam1/safe-guard-prompt-injection, databricks-dolly-15k and tatsu-lab/alpaca instructions (benign). |
| `test_ood` | Whole sources never trained on: jackhhao/jailbreak-classification and lakera/gandalf_ignore_instructions. Cross-dataset generalisation is the number to trust. |
| `test_evident` | The hand-labelled regex corpus parsed from `packages/detectors/src/__tests__/injection.corpus.test.ts`; ambiguous requests count as benign. |
| `test_perturbed` | Attacks from `test` and `test_ood` under eight perturbations (token-break space/hyphen, zero-width characters, homoglyphs, leetspeak, case flips, benign prefix, base64 wrapping) plus the unperturbed benign rows. |

## Detectors

| Name | Kind | Needs |
|---|---|---|
| `regex_low` / `regex_medium` / `regex_high` | rule | Node; scores the shared `@evidentai/detectors` library through `packages/detectors/bin/score.mjs`. Scores are an ordinal severity proxy, not probabilities. |
| `ngram_lr` | classifier | nothing; char n-gram TF-IDF + logistic regression trained on `train`. The boring baseline. |
| `protectai_deberta_v2` | classifier | Hugging Face download of `protectai/deberta-v3-base-prompt-injection-v2`. |
| `promptguard2_22m` / `promptguard2_86m` | classifier | `HF_TOKEN` after accepting Meta's licence (gated). Otherwise "not measured". |
| `evident_guard_v0` | classifier | `models/evident-guard-v0/` from `python -m evals.train`. |
| `jev` | external | `TYPESAFE_API_KEY`. Untested against the live API. |
| `llm_judge_gpt4o_mini` | external | `OPENAI_API_KEY`. |

Add a detector by subclassing `evals.detectors.base.Detector` and registering
it in `evals/detectors/__init__.py`.

## Model artifact layout

`python -m evals.train` writes `models/evident-guard-v0/`:

```
model.onnx                # optimum export of the fine-tuned encoder (read by Python/optimum)
onnx/model.onnx           # hard link to the same file, the layout transformers.js expects
config.json               # id2label {"0": "BENIGN", "1": "INJECTION"}
tokenizer.json, tokenizer_config.json, special_tokens_map.json, spm.model
calibration.json          # see below
model_card.md
train_history.json
```

`calibration.json`:

```json
{
  "model": "evident-guard-v0",
  "base_model": "microsoft/deberta-v3-xsmall",
  "temperature": 1.23,
  "threshold": 0.47,
  "max_length": 256,
  "positive_label": "INJECTION",
  "val_macro_f1": 0.98,
  "ece_before": 0.03,
  "ece_after": 0.01,
  "date": "2026-11-05"
}
```

Consumers compute `softmax(logits / temperature)[INJECTION]` and compare with
`threshold`. The TypeScript `transformers` backend in `@evidentai/detectors`
reads this file when present next to the model.
