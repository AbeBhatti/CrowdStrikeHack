.PHONY: setup train library test decoys-test e2e e2e-live demo check-env download bench models

export PYTHONPATH := .
export LDFLAGS := -L/opt/homebrew/opt/libomp/lib
export CPPFLAGS := -I/opt/homebrew/opt/libomp/include

UV ?= uv
PY := $(UV) run python

check-env:
	bash scripts/check_env.sh

setup: check-env
	$(UV) sync --all-extras
	@if ! curl -sf http://127.0.0.1:11434/api/tags >/dev/null; then \
		echo "Starting ollama serve..."; \
		ollama serve >/tmp/ollama.log 2>&1 & sleep 2; \
	fi
	$(PY) scripts/bench_models.py
	bash scripts/download_data.sh
	$(PY) -m ingest.convert_parquet
	@echo "Setup complete."

download:
	bash scripts/download_data.sh
	$(PY) -m ingest.convert_parquet

bench:
	$(PY) scripts/bench_models.py

train:
	$(PY) -m classifier.train
	$(PY) -m classifier.compare_methods
	$(PY) -m forecast.train
	@echo "Training complete."

library:
	$(PY) -m library.learn
	@echo "Defense library learning pass complete."

test:
	$(UV) run ruff check .
	$(UV) run pytest -q

decoys-test:
	$(PY) -m decoys.run_tests

e2e:
	$(UV) run pytest -q -m e2e tests/test_e2e.py

e2e-live:
	$(UV) run pytest -q -m live tests/test_e2e_live.py || true

demo:
	bash scripts/run_demo.sh
