.PHONY: all clean lint fmt release doc build run test test-panic test-st macros

# non-versioned include
VARS ?= vars.mk
-include $(VARS)

override CARGO_BUILD_ARGS += --features "$(FEATURES)" --color=always

all: build

build: fmt
	cargo build $(CARGO_BUILD_ARGS)

fmt:
	cargo fmt

release: override CARGO_BUILD_ARGS += --release
release: build

doc:
	cargo doc $(CARGO_BUILD_ARGS)

test: fmt
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test-release: override CARGO_BUILD_ARGS += --release
test-release: test

test-panic: override FEATURES += panic-on-error
test-panic: fmt
	RUST_BACKTRACE=1 \
		cargo test \
			$(TEST) \
			$(CARGO_BUILD_ARGS) -- \
			--nocapture

test-st: fmt
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture --test-threads 1

lint:
	cargo clippy $(CARGO_BUILD_ARGS) -- \
		-A clippy::comparison_chain \
		-A clippy::module_inception \
		-A clippy::redundant_closure \
		-A clippy::redundant_pattern_matching \
		-A clippy::search_is_some

clean:
	rm -rf target/
	cargo clean

