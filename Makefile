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
.PHONY: help submodules build-tesseract lab-up lab-down pki measure demo workshop test lint clean

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

pki: ## Generate the workshop PKI (override with ALG=mldsa65 etc.)
	$(PYTHON) -m lab.cli pki --algorithm $(or $(ALG),mldsa65)

measure: ## Measure certificate/key/signature sizes across algorithms
	$(PYTHON) -m lab.cli measure

demo: ## Submit a certificate and verify its inclusion proof (needs lab-up)
	$(PYTHON) -m lab.cli demo --origin $(ORIGIN) --storage-dir $(STORAGE_DIR)

workshop: ## Run the full end-to-end happy path
	./scripts/workshop.sh

test: ## Run the unit test suite
	$(PYTHON) -m unittest discover -s tests -v

lint: ## Lint the Python sources
	ruff check lab tests

clean: ## Remove build and lab artifacts
	rm -rf $(BIN_DIR) log certs out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
