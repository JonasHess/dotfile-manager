BINARY := dfm
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet dist clean

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/dfm

test:
	go test ./...

vet:
	go vet ./...

dist: clean
	@mkdir -p dist
	@for t in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/arm; do \
	  os=$${t%/*}; arch=$${t#*/}; \
	  echo "building $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$$os-$$arch ./cmd/dfm || exit 1; \
	done
	@cd dist && sha256sum $(BINARY)-* > SHA256SUMS

clean:
	rm -rf dist $(BINARY)
