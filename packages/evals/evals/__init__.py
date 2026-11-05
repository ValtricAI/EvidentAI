"""EvidentAI detector evaluation harness."""

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = PACKAGE_DIR.parent.parent
DATA_DIR = PACKAGE_DIR / "data"
MODELS_DIR = PACKAGE_DIR / "models"
RESULTS_DIR = PACKAGE_DIR / "results"
CORPUS_TS = REPO_ROOT / "packages" / "detectors" / "src" / "__tests__" / "injection.corpus.test.ts"
REGEX_BRIDGE = REPO_ROOT / "packages" / "detectors" / "bin" / "score.mjs"
