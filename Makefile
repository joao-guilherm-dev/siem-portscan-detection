.PHONY: install test demo demo-raw export clean

install:
	pip install -r requirements.txt

test:
	python -m pytest

demo:
	mkdir -p out
	python -m portscan_detection generate --output out/synthetic.csv
	python -m portscan_detection detect --input out/synthetic.csv

demo-raw:  ## mesmo log SEM allowlist: mostra o ruído que as camadas anti-FP evitam
	python -m portscan_detection detect --input out/synthetic.csv --no-allowlist

export:
	python -m portscan_detection export-allowlist --format splunk --output-dir exports/splunk
	python -m portscan_detection export-allowlist --format sentinel --output-dir exports/sentinel
	python -m portscan_detection export-allowlist --format elastic --output-dir exports/elastic

clean:
	rm -rf out exports .pytest_cache
