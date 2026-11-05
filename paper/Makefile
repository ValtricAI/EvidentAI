PY      ?= .venv/bin/python
NAME     = evidentai-release-gates
BUILD    = build
LATEXMK  = latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=$(BUILD) -jobname=$(NAME)

.PHONY: all draft final figures figures-fixture clean check

all: draft

figures:
	$(PY) scripts/make_figures.py

figures-fixture:
	$(PY) scripts/make_figures.py --fixture

# Draft: synthetic fixture numbers, DRAFT banner and RESULTS PENDING watermark.
draft: figures-fixture
	$(LATEXMK) main.tex

# Final: newest packages/evals/results/*/metrics.json, no watermark.
final: figures
	$(LATEXMK) main.tex

check:
	@pdftotext $(BUILD)/$(NAME).pdf - | grep -c "??" | xargs -I{} sh -c 'test {} -eq 0 && echo "no unresolved references" || (echo "unresolved references: {}" && exit 1)'
	@pdfinfo $(BUILD)/$(NAME).pdf | grep Pages

clean:
	rm -rf $(BUILD) figures/*.pdf tables/*.tex
