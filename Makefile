.PHONY: all clean lint release doc build run test test-panic test-st macros

# non-versioned include
VARS ?= vars.mk
-include $(VARS)

override CARGO_BUILD_ARGS += --features "$(FEATURES)" --color=always

all: build

build:
	cargo build $(CARGO_BUILD_ARGS)

release: override CARGO_BUILD_ARGS += --release
release: build

doc:
	cargo doc $(CARGO_BUILD_ARGS)

test-release: override CARGO_BUILD_ARGS += --release
test-release:
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test:
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test-panic: override FEATURES += panic-on-error
test-panic:
	RUST_BACKTRACE=1 \
		cargo test \
			$(TEST) \
			$(CARGO_BUILD_ARGS) -- \
			--nocapture

test-st:
	cargo test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture --test-threads 1

lint:
	cargo clippy $(CARGO_BUILD_ARGS) -- \
		-A clippy::redundant_closure \
		-A clippy::module_inception \
		-A clippy::comparison_chain

clean:
	rm -rf target/
	cargo clean

