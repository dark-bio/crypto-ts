.PHONY: build format version

build:
	npm run build

format:
	npx prettier --write .
	cargo fmt --all --manifest-path crates/wasm/Cargo.toml

version:
ifndef VERSION
	$(error VERSION is not set. Usage: make version VERSION=x.y.z)
endif
	@echo "Setting version to $(VERSION)"
	sed -i '' 's/"version": "[^"]*"/"version": "$(VERSION)"/' package.json
	sed -i '' 's/^version = .*/version = "$(VERSION)"/' crates/wasm/Cargo.toml
	npm install --package-lock-only
	cargo generate-lockfile --manifest-path crates/wasm/Cargo.toml
