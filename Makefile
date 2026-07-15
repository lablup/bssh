SHELL := /bin/sh

CARGO ?= cargo
BINARY ?= bssh
BUILD_DIR ?= target/release
BIN := $(BUILD_DIR)/$(BINARY)
PLAYBOOK ?= examples/playbook.yaml
INVENTORY ?= examples/playbook-inventory.yaml
ARGS ?=
RUST_VERSION ?= 1.93
DOCKER_IMAGE ?= rust:$(RUST_VERSION)

.PHONY: help setup bootstrap-rustup toolchain dependencies deps build install check test \
	test-playbook fmt fmt-check lint clean playbook playbook-combined dry-run \
	dry-run-combined demo playbook-help docker-check docker-test

help: ## Show available commands
	@printf '%s\n' \
		'Common commands:' \
		'  make setup             Bootstrap rustup, install Rust, and fetch dependencies' \
		'  make bootstrap-rustup  Install rustup when it is missing' \
		'  make dependencies      Download locked Cargo dependencies' \
		'  make build             Build the release binary' \
		'  make install           Install bssh with cargo' \
		'  make check             Check all Rust targets' \
		'  make test              Run the workspace tests' \
		'  make test-playbook     Run only playbook tests' \
		'  make demo              Dry-run the included example' \
		'  make playbook          Run the configured playbook' \
		'  make dry-run           Dry-run the configured playbook' \
		'' \
		'Playbook overrides:' \
		'  make playbook PLAYBOOK=deploy.yaml INVENTORY=inventory.yaml' \
		'  make playbook-combined PLAYBOOK=combined.yaml' \
		'  make dry-run-combined PLAYBOOK=combined.yaml' \
		'  make playbook ARGS="--full-output"' \
		'' \
		'Toolchain-free validation (requires Docker):' \
		'  make docker-check' \
		'  make docker-test'

setup: toolchain dependencies ## Bootstrap Rust and fetch dependencies

bootstrap-rustup: ## Install rustup from rustup.rs when it is missing
	command -v rustup >/dev/null 2>&1 || [ -x "$(HOME)/.cargo/bin/rustup" ] || { command -v curl >/dev/null 2>&1 || { echo "curl is required to install rustup" >&2; exit 1; }; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path; }

toolchain: bootstrap-rustup ## Install the supported Rust toolchain, formatter, and linter
	PATH="$(HOME)/.cargo/bin:$$PATH" rustup toolchain install $(RUST_VERSION) --profile minimal --component rustfmt,clippy
	PATH="$(HOME)/.cargo/bin:$$PATH" rustup default $(RUST_VERSION)

dependencies: ## Download all locked Cargo dependencies
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) fetch --locked

deps: dependencies ## Alias for dependencies

build: ## Build the optimized bssh binary
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) build --release --locked --bin $(BINARY)

install: ## Install bssh from this checkout
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) install --path . --locked

check: ## Type-check all targets
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) check --all-targets --locked

test: ## Run all workspace tests
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) test --workspace --locked

test-playbook: ## Run only playbook tests
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) test --lib playbook --locked

fmt: ## Format Rust sources
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) fmt --all

fmt-check: ## Verify Rust formatting
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) fmt --all -- --check

lint: ## Run Clippy with warnings treated as errors
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) clippy --all-targets --all-features --locked -- -D warnings

clean: ## Remove build artifacts
	PATH="$(HOME)/.cargo/bin:$$PATH" $(CARGO) clean

playbook: build ## Run separate playbook and inventory files
	"$(BIN)" playbook "$(PLAYBOOK)" --inventory "$(INVENTORY)" $(ARGS)

playbook-combined: build ## Run a legacy combined inventory/playbook file
	"$(BIN)" playbook "$(PLAYBOOK)" $(ARGS)

dry-run: build ## Preview separate playbook and inventory files
	"$(BIN)" playbook "$(PLAYBOOK)" --inventory "$(INVENTORY)" --dry-run $(ARGS)

dry-run-combined: build ## Preview a legacy combined inventory/playbook file
	"$(BIN)" playbook "$(PLAYBOOK)" --dry-run $(ARGS)

demo: dry-run ## Dry-run the included example inventory and playbook

playbook-help: build ## Show playbook CLI help
	"$(BIN)" playbook --help

docker-check: ## Run cargo check with Rust $(RUST_VERSION) in Docker
	docker run --rm --user "$$(id -u):$$(id -g)" \
		-e HOME=/tmp/home -e CARGO_HOME=/tmp/cargo-home \
		-v "$(CURDIR):/work" -w /work $(DOCKER_IMAGE) \
		cargo check --all-targets --locked

docker-test: ## Run playbook tests with Rust $(RUST_VERSION) in Docker
	docker run --rm --user "$$(id -u):$$(id -g)" \
		-e HOME=/tmp/home -e CARGO_HOME=/tmp/cargo-home \
		-v "$(CURDIR):/work" -w /work $(DOCKER_IMAGE) \
		cargo test --lib playbook --locked
