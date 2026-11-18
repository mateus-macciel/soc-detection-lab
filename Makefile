PY ?= python

.PHONY: demo data detect test clean docs

demo: data detect

data:
	$(PY) src/generate_logs.py --users 300 --seed 42 --start 2026-10-01

detect:
	$(PY) src/run_lab.py

test:
	$(PY) -m unittest discover -s tests -v

clean:
	rm -rf output

docs:
	$(PY) src/make_docs.py
