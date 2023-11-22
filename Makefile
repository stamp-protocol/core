.PHONY: all clean lint release doc build run test test-panic test-st macros

# non-versioned include
VARS ?= vars.mk
-include $(VARS)

CARGO ?= $(shell which cargo)
override CARGO_BUILD_ARGS += --features "$(FEATURES)" --color=always

all: build

build:
	$(CARGO) build $(CARGO_BUILD_ARGS)

release: override CARGO_BUILD_ARGS += --release
release: build

doc:
	$(CARGO) doc $(CARGO_BUILD_ARGS)

test-release: override CARGO_BUILD_ARGS += --release
test-release:
	$(CARGO) test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test:
	$(CARGO) test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture

test-panic: override FEATURES += panic-on-error
test-panic:
	RUST_BACKTRACE=1 \
		$(CARGO) test \
			$(TEST) \
			$(CARGO_BUILD_ARGS) -- \
			--nocapture

test-st:
	$(CARGO) test $(TEST) $(CARGO_BUILD_ARGS) -- --nocapture --test-threads 1

lint:
	$(CARGO) clippy $(CARGO_BUILD_ARGS) -- \
		-A clippy::redundant_closure \
		-A clippy::module_inception \
		-A clippy::comparison_chain

clean:
	rm -rf target/
	$(CARGO) clean

