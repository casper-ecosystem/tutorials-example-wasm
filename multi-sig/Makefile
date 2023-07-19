ALL_CONTRACTS = add_account remove_account update_associated_keys update_thresholds
CONTRACT_TARGET_DIR = target/wasm32-unknown-unknown/release
PINNED_TOOLCHAIN := $(shell cat rust-toolchain)

prepare:
	rustup target add wasm32-unknown-unknown
	rustup component add clippy --toolchain ${PINNED_TOOLCHAIN}
	rustup component add rustfmt --toolchain ${PINNED_TOOLCHAIN}

.PHONY:	build-contracts
build-contracts:
	cargo build --release --target wasm32-unknown-unknown $(patsubst %, -p %, $(ALL_CONTRACTS))
	$(foreach WASM, $(ALL_CONTRACTS), wasm-strip $(CONTRACT_TARGET_DIR)/$(subst -,_,$(WASM)).wasm ;)

test: build-contracts
	mkdir -p tests/wasm
	cp ./target/wasm32-unknown-unknown/release/add_account.wasm tests/wasm
	cp ./target/wasm32-unknown-unknown/release/remove_account.wasm tests/wasm
	cp ./target/wasm32-unknown-unknown/release/update_associated_keys.wasm tests/wasm
	cp ./target/wasm32-unknown-unknown/release/update_thresholds.wasm tests/wasm
	cd tests && cargo test

clippy:
	cd contracts/add_account && cargo clippy --target wasm32-unknown-unknown --bins -- -D warnings
	cd contracts/remove_account && cargo clippy --target wasm32-unknown-unknown --bins -- -D warnings
	cd contracts/update_associated_keys && cargo clippy --target wasm32-unknown-unknown --bins -- -D warnings
	cd contracts/update_thresholds && cargo clippy --target wasm32-unknown-unknown --bins -- -D warnings
	cd tests && cargo clippy --all-targets -- -D warnings

check-lint: clippy
	cd contracts/add_account && cargo fmt -- --check
	cd contracts/remove_account && cargo fmt -- --check
	cd contracts/update_associated_keys && cargo fmt -- --check
	cd contracts/update_thresholds && cargo fmt -- --check
	cd tests && cargo fmt -- --check

lint: clippy
	cd contracts/add_account && cargo fmt
	cd contracts/remove_account && cargo fmt
	cd contracts/update_associated_keys && cargo fmt
	cd contracts/update_thresholds && cargo fmt
	cd tests && cargo fmt

clean:
	cd contracts/add_account/ && cargo clean
	cd contracts/remove_account/ && cargo clean
	cd contracts/update_associated_keys/ && cargo clean
	cd contracts/update_thresholds/ && cargo clean
	cd tests && cargo clean
	rm -rf tests/wasm
