# Merkle Tree Lab — TesseraCT + Python workshop
#
# Run `make` or `make help` to list targets.

# Prefer the repo virtualenv: the MTC lab needs ML-DSA, which needs
# cryptography >= 46. Fall back to whatever python3 is on PATH.
PYTHON      ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)
GO          ?= go
GOTOOLCHAIN ?= go1.27.0

BIN_DIR     := bin
TESSERACT   := $(BIN_DIR)/tesseract-posix
STORAGE_DIR ?= log
ORIGIN      ?= example.com/workshop
HTTP_ADDR   ?= 127.0.0.1:6962
ROOTS_PEM   ?= out/pki/mldsa65/root.crt
LOG_KEY     ?= out/log-key.pem
MTC_DIR     ?= out/mtc
VERBOSE     ?=

.DEFAULT_GOAL := help
.PHONY: help submodules build-tesseract lab-up lab-down pki pki-all tls-demo measure demo walk mtc-lab mtc-shapes mtc-verify workshop test lint clean


help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

submodules: ## Fetch the pinned TesseraCT submodule
	git submodule update --init --recursive

build-tesseract: submodules ## Build the TesseraCT POSIX log server (requires Go 1.27)
	mkdir -p $(BIN_DIR)
	cd impl/tesseract && GOTOOLCHAIN=$(GOTOOLCHAIN) $(GO) build -o ../../$(TESSERACT) ./cmd/tesseract/posix

lab-up: build-tesseract ## Build and start the local TesseraCT POSIX log
	STORAGE_DIR=$(STORAGE_DIR) ORIGIN=$(ORIGIN) HTTP_ADDR=$(HTTP_ADDR) \
	ROOTS_PEM=$(ROOTS_PEM) LOG_KEY=$(LOG_KEY) ./scripts/run_tesseract.sh start

lab-down: ## Stop the local TesseraCT log
	./scripts/run_tesseract.sh stop

pki: ## Generate one PKI (override with ALG=mldsa65 etc.)
	$(PYTHON) -m lab.cli pki --algorithm $(or $(ALG),mldsa65)

pki-all: ## Generate the full measurement set of PKIs
	./scripts/gen_pki.sh

tls-demo: ## Run the private-PQC-PKI TLS demo (ALG=mldsa65)
	ALG=$(or $(ALG),mldsa65) ./scripts/tls_demo.sh

measure: ## Measure certificate/key/signature sizes (generates missing PKIs)
	$(PYTHON) -m lab.cli measure --generate

demo: ## Submit a certificate and verify its inclusion proof (needs lab-up; VERBOSE=1 traces HTTP)
	$(PYTHON) -m lab.cli demo $(if $(VERBOSE),--verbose,) --storage-dir $(STORAGE_DIR) \
		--log-key $(LOG_KEY) --log http://$(HTTP_ADDR) --origin $(ORIGIN)

walk: ## Print an inclusion proof hash-by-hash (needs lab-up; VERBOSE=1 shows entry bytes)
	$(PYTHON) -m lab.cli walk $(if $(VERBOSE),--verbose,) --storage-dir $(STORAGE_DIR) --index $(or $(INDEX),0)

fill: ## Submit N distinct certificates so the tree grows (needs lab-up; VERBOSE=1 traces)
	$(PYTHON) -m lab.cli fill $(if $(VERBOSE),--verbose,) --storage-dir $(STORAGE_DIR) \
		--count $(or $(N),8) --algorithm $(or $(ALG),mldsa65) \
		--log $(or $(LOG),http://$(HTTP_ADDR)) --origin $(ORIGIN)

mtc-lab: ## Build the MTC CA lab: issuance log + 2 checkpoints + 1 landmark (ENTRIES=20 LOGNO=8)
	$(PYTHON) -m lab.cli mtc lab --outdir $(MTC_DIR) --entries $(or $(ENTRIES),20) --log $(or $(LOGNO),8)

mtc-shapes: ## Emit the four certificate shapes for one entry and size them (INDEX=3)
	$(PYTHON) -m lab.cli mtc shapes --outdir $(MTC_DIR) --index $(or $(INDEX),3)

mtc-verify: ## Run the relying-party verification walk (INDEX=3 KNOWS=landmark TAMPER=0)
	$(PYTHON) -m lab.cli mtc verify --outdir $(MTC_DIR) --index $(or $(INDEX),3) \
		--knows $(or $(KNOWS),landmark) $(if $(TAMPER),--tamper,)

workshop: ## Run the full end-to-end happy path
	./scripts/workshop.sh


test: ## Run the unit test suite
	$(PYTHON) -m unittest discover -s tests -v

lint: ## Lint the Python sources
	ruff check lab tests

clean: ## Remove build and lab artifacts
	rm -rf $(BIN_DIR) log certs out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
