prepare:
	rustup target add wasm32-unknown-unknown

build-contract:
	cd contract && cargo build --release --target wasm32-unknown-unknown
	wasm-strip target/wasm32-unknown-unknown/release/contract.wasm
	cd client/named_key_session/src/ && cargo build --release --target wasm32-unknown-unknown
	wasm-strip target/wasm32-unknown-unknown/release/named_key_session.wasm

test: build-contract
	mkdir -p tests/wasm
	cp target/wasm32-unknown-unknown/release/contract.wasm tests/wasm/
	cp target/wasm32-unknown-unknown/release/named_key_session.wasm tests/wasm/
	cd tests && cargo test

clippy:
	cd contract && cargo clippy --release --target wasm32-unknown-unknown -- -D warnings
	cd client/named_key_session && cargo clippy --release --target wasm32-unknown-unknown -- -D warnings
	cd tests && cargo clippy --all-targets -- -D warnings

check-lint: clippy
	cd contract && cargo fmt -- --check
	cd client/named_key_session && cargo fmt -- --check
	cd tests && cargo fmt -- --check

lint: clippy
	cd contract && cargo fmt
	cd client/named_key_session && cargo fmt
	cd tests && cargo fmt

clean:
	cd contract && cargo clean
	cd client/named_key_session && cargo clean
	cd tests && cargo clean
	rm -rf tests/wasm
