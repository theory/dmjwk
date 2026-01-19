GO       ?= go
GOOS     ?= $(word 1,$(subst /, ,$(word 4, $(shell $(GO) version))))
GOARCH   ?= $(word 2,$(subst /, ,$(word 4, $(shell $(GO) version))))
PLATFORM := $(GOOS)-$(GOARCH)
VERSION  := v0.2.2-dev

export VERSION GOOS GOARCH
# https://github.com/xaionaro/documentation/blob/master/golang/reduce-binary-size.md
# https://www.gnu.org/software/make/manual/html_node/Splitting-Lines.html
ldflags = -ldflags="$\
	-s -w\
	-X 'main.version=$(VERSION)'\
	-X 'main.build=$(shell git rev-parse --short HEAD)'$\
"

# Prevent intermediate targets from being deleted.
# https://www.gnu.org/software/make/manual/html_node/Special-Targets.html#index-secondary-targets
.SECONDARY:

############################################################################
# App
.PHONY: app # Build dmjwk
app: _build/$(PLATFORM)/dmjwk

 _build/%/dmjwk: $(filter-out %_test.go,$(shell find . -name '*.go'))
	GOOS=$(word 1,$(subst -, ,$*)) GOARCH=$(word 2,$(subst -, ,$*)) CGO_ENABLED=0 $(GO) build $(ldflags) -o $@

############################################################################
# Test, Lint, Clean.
.PHONY: test # Run the unit tests
test:
	GOTOOLCHAIN=local $(GO) test ./... -count=1

.PHONY: cover # Run test coverage
cover: $(shell find . -name \*.go)
	GOTOOLCHAIN=local $(GO) test -v -coverprofile=cover.out -covermode=count ./...
	@$(GO) tool cover -html=cover.out

.PHONY: lint # Lint the project
lint: .golangci.yaml
	@pre-commit run --show-diff-on-failure --color=always --all-files

.PHONY: clean # Remove generated files
clean:
	$(GO) clean
	@rm -rf cover.out _build

############################################################################
# Release artifacts.
.PHONY: release # Build a release zip file or .tar.gz & tar.bz2 files.
ifeq ($(GOOS),windows)
release: _build/artifacts/dmjwk-$(VERSION)-windows-$(GOARCH).zip
else
release: _build/artifacts/dmjwk-$(VERSION)-$(PLATFORM).tar.gz
endif

# Build a release zip file for Windows.
_build/artifacts/dmjwk-$(VERSION)-windows-$(GOARCH).zip: README.md LICENSE.md CHANGELOG.md openapi.json _build/windows-$(GOARCH)/dmjwk
	@mkdir -p "_build/artifacts/dmjwk-$(VERSION)-windows-$(GOARCH)"
	cp $^ "_build/artifacts/dmjwk-$(VERSION)-windows-$(GOARCH)"
	cd _build/artifacts && 7z a "dmjwk-$(VERSION)-windows-$(GOARCH).zip" "dmjwk-$(VERSION)-windows-$(GOARCH)"
	rm -R "_build/artifacts/dmjwk-$(VERSION)-windows-$(GOARCH)"

# Build a .tar.gz file for the specified platform.
_build/artifacts/dmjwk-$(VERSION)-$(PLATFORM).tar.gz: README.md LICENSE.md CHANGELOG.md openapi.json _build/$(PLATFORM)/dmjwk
	@mkdir -p "_build/artifacts/dmjwk-$(VERSION)-$(PLATFORM)"
	cp $^ "_build/artifacts/dmjwk-$(VERSION)-$(PLATFORM)"
	cd _build/artifacts && tar zcvf "dmjwk-$(VERSION)-$(PLATFORM).tar.gz" "dmjwk-$(VERSION)-$(PLATFORM)"
	rm -R "_build/artifacts/dmjwk-$(VERSION)-$(PLATFORM)"

run: _build/$(PLATFORM)/dmjwk
	@./_build/$(PLATFORM)/dmjwk --version

show-build: _build/$(PLATFORM)/dmjwk
	@echo ./_build/$(PLATFORM)/dmjwk

.PHONY: version-env # Echo setting an environment variable with the release version.
version-env:
	@echo VERSION=$${VERSION%-*}

############################################################################
# Utilities.
.PHONY: brew-lint-depends # Install linting tools from Homebrew
brew-lint-depends:
	brew install golangci-lint vacuum

.PHONY: debian-lint-depends # Install linting tools on Debian
debian-lint-depends:
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sudo sh -s -- -b /usr/bin v2.8.0
	curl -fsSL https://quobix.com/scripts/install_vacuum.sh | sudo sh

## .git/hooks/pre-commit: Install the pre-commit hook
.git/hooks/pre-commit:
	@printf "#!/bin/sh\nmake lint\n" > $@
	@chmod +x $@

############################################################################
# OCI images.
.PHONY: image # Build the linux/amd64 OCI image.
image: _build/linux-$(GOARCH)/dmjwk
	version=$(VERSION) revision=$(REVISION) docker buildx bake --set *.platform=linux/$(GOARCH) --load
	docker run --rm ghcr.io/theory/dmjwk --version

.PHONY: release-image # Build the linux/amd64 OCI image.
release-image: _build/linux-amd64/dmjwk _build/linux-arm64/dmjwk _build/linux-ppc64le/dmjwk _build/linux-arm/dmjwk _build/linux-s390x/dmjwk
	version=$(VERSION) revision=$(REVISION) docker buildx bake $(if $(filter true,$(PUSH)),--push,)
