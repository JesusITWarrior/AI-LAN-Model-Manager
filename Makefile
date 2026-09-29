.PHONY: check build test go-test vet fmt-check supply-chain release-audit all

all: check

build:
	npm run build

test:
	npx tsx --test packages/core/src/*.test.ts apps/controller/src/*.test.ts apps/controller/src/transport/*.test.ts

go-test:
	cd agents/host-agent && go test ./...

vet:
	cd agents/host-agent && go vet ./...

fmt-check:
	@if [ -n "$$(cd agents/host-agent && gofmt -l .)" ]; then \
		echo "ERROR: Go files are not gofmt'd"; \
		gofmt -d agents/host-agent; \
		exit 1; \
	fi

supply-chain:
	npm run supply-chain

release-audit:
	node scripts/packaging/audit.js . --allow-dirty --run-gates

check: build test go-test vet fmt-check supply-chain release-audit
