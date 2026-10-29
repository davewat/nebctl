VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
TARGETS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 linux/arm

.PHONY: build dist release test web mac mac-test clean

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

# The admin console (React). Its build is committed in internal/web/dist,
# so plain `go build` needs no Node; run this after changing web/.
web:
	cd web && npm ci && npm run build

# The Mac app, with a universal nebctl inside.
mac:
	macos/build.sh $(VERSION) dist

# Needs Go, and nebula and nebula-cert in /usr/local/bin.
mac-test:
	cd macos && swift test

# dist and the Mac app plus SHA256SUMS, ready to attach to a GitHub release.
release: clean dist mac
	cd dist && shasum -a 256 nebctl-* NebulaNode-macos.zip > SHA256SUMS

# Set NEBULA_CERT to a nebula-cert binary to run the key-matching tests too.
test:
	go vet ./...
	go test ./...

clean:
	rm -rf dist nebctl
