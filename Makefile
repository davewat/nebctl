VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
TARGETS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm

.PHONY: build dist release test clean

build:
	go build -ldflags '$(LDFLAGS)' -o nebctl .

# One static binary per platform in dist/.
dist:
	@mkdir -p dist
	@for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "dist/nebctl-$$os-$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags '$(LDFLAGS)' -o dist/nebctl-$$os-$$arch . || exit 1; \
	done

# dist plus SHA256SUMS, ready to attach to a GitHub release.
release: clean dist
	cd dist && shasum -a 256 nebctl-* > SHA256SUMS

# Set NEBULA_CERT to a nebula-cert binary to run the key-matching tests too.
test:
	go vet ./...
	go test ./...

clean:
	rm -rf dist nebctl
