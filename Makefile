# Merkle Tree Lab — TesseraCT + Python workshop
#
# Run `make` or `make help` to list targets.

PYTHON      ?= python3
GO          ?= go
GOTOOLCHAIN ?= go1.27.0

BIN_DIR     := bin
TESSERACT   := $(BIN_DIR)/tesseract-posix
STORAGE_DIR ?= log
ORIGIN      ?= example.com/workshop
HTTP_ADDR   ?= 127.0.0.1:6962
ROOTS_PEM   ?= out/pki/mldsa65/root.crt
LOG_KEY     ?= out/log-key.pem

.DEFAULT_GOAL := help
.PHONY: help submodules build-tesseract build-witness lab-up lab-down pki pki-all tls-demo measure demo walk bundle witness-setup witness-demo workshop test lint clean

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

demo: ## Submit a certificate and verify its inclusion proof (needs lab-up)
	$(PYTHON) -m lab.cli demo --storage-dir $(STORAGE_DIR) --log-key $(LOG_KEY)

walk: ## Print an inclusion proof hash-by-hash (needs lab-up)
	$(PYTHON) -m lab.cli walk --storage-dir $(STORAGE_DIR) --index $(or $(INDEX),0)

bundle: ## Build and size an MTC-shaped bundle (needs lab-up)
	$(PYTHON) -m lab.cli bundle --storage-dir $(STORAGE_DIR) --index $(or $(INDEX),0) \
		--output out/mtc_bundle.json

build-witness: ## Build the local tlog witness (requires Go 1.27)
	mkdir -p $(BIN_DIR)
	cd tools/witness && GOTOOLCHAIN=$(GOTOOLCHAIN) $(GO) build -o ../../$(BIN_DIR)/witness .

witness-setup: build-witness ## Generate witness keys and policy
	./scripts/setup_witness.sh

witness-demo: ## Run the native-witness demo (start witness + log, verify cosignature)
	./scripts/witness_demo.sh

workshop: ## Run the full end-to-end happy path
	./scripts/workshop.sh

test: ## Run the unit test suite
	$(PYTHON) -m unittest discover -s tests -v

lint: ## Lint the Python sources
	ruff check lab tests

clean: ## Remove build and lab artifacts
	rm -rf $(BIN_DIR) log certs out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
