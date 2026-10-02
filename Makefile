VENV ?= .venv
PY   := $(VENV)/bin/python
BIN  := $(VENV)/bin

.PHONY: help venv install test selftest demo report dashboard devnet probe example-config clean

help:
	@echo "make venv            create .venv and install otscope with dev extras"
	@echo "make test            run the test suite (pytest)"
	@echo "make selftest        analyse a generated capture and verify the outcome"
	@echo "make demo            generate a synthetic plant capture and analyse it"
	@echo "make report          write reports/report.{html,md,json} for the demo capture"
	@echo "make dashboard       serve the web dashboard on 0.0.0.0:8055"
	@echo "make devnet          run the emulated OT/ERP plant on loopback"
	@echo "make probe           probe the emulated plant (read only)"
	@echo "make example-config  write examples/site-config.json"

venv:
	python3 -m venv $(VENV)
	$(BIN)/pip install --upgrade pip -q
	$(BIN)/pip install -e ".[dev]" -q
	@echo "installed: $$($(BIN)/otscope --version)"

install: venv

test:
	$(PY) -m pytest

selftest:
	$(BIN)/otscope selftest

demo:
	$(BIN)/otscope demo --pcap reports/demo.pcap --format console

report:
	mkdir -p reports
	$(BIN)/otscope demo --pcap reports/demo.pcap --format html     --out reports/report.html
	$(BIN)/otscope demo --pcap reports/demo.pcap --format markdown --out reports/report.md
	$(BIN)/otscope demo --pcap reports/demo.pcap --format json     --out reports/report.json
	@echo "reports written to reports/"

dashboard:
	$(BIN)/otscope dashboard --host 0.0.0.0 --port 8055

devnet:
	$(BIN)/otscope devnet --forever

probe:
	@echo "note: 'make devnet' prints the exact probe command for the ports it bound"
	$(BIN)/otscope probe 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5 \
	  --service-port s7=10102 --service-port modbus=10502 \
	  --service-port enip=14481 --service-port enip_udp=12222 \
	  --service-port http=10080 --service-port snmp=10161 --snmp --rate 20

example-config:
	mkdir -p examples
	$(BIN)/otscope config --out examples/site-config.json

clean:
	rm -rf reports .state .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
