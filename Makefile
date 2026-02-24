.DEFAULT_GOAL := all

TARGET     := ghqr
OS         := $(if $(GOOS),$(GOOS),$(shell go env GOOS))
ARCH       := $(if $(GOARCH),$(GOARCH),$(shell go env GOARCH))
BIN         = bin/$(OS)_$(ARCH)/$(TARGET)
ifeq ($(OS),windows)
  BIN = bin/$(OS)_$(ARCH)/$(TARGET).exe
endif
GOLANGCI_LINT := ./bin/golangci-lint
PRODUCT_VERSION	:= $(if $(PRODUCT_VERSION),$(PRODUCT_VERSION),'0.0.0-dev')
LDFLAGS	:= -s -w -X github.com/microsoft/ghqr/cmd/ghqr/commands.version=$(PRODUCT_VERSION)
TRIM_PATH := -trimpath

all: $(TARGET)

build: $(TARGET)

help:
	@echo "Available targets:"
	@echo "  all          - Build the ghqr binary (default)"
	@echo "  build        - Build the ghqr binary (same as all)"
	@echo "  vet          - Run go vet checks"
	@echo "  tidy         - Tidy up go modules"
	@echo "  test         - Run tests"
	@echo "  clean        - Remove built binaries"

lint: lint-install
	$(GOLANGCI_LINT) run

lint-all: lint-install
	$(GOLANGCI_LINT) run --enable=errcheck,govet,ineffassign,staticcheck,gocyclo,unused,gocognit,gosec,gocritic

lint-install:
	@if [ ! -f $(GOLANGCI_LINT) ]; then \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh | sh -s v2.9.0; \
	fi

vet:
	go vet ./...

tidy:
	go mod tidy
	git diff --exit-code ./go.mod
	git diff --exit-code ./go.sum

test: lint vet tidy
	go test -race ./... -coverprofile=coverage.txt -covermode=atomic

$(TARGET): clean
	CGO_ENABLED=0 go build $(TRIM_PATH) -o $(BIN) -ldflags "$(LDFLAGS)" ./cmd/ghqr/main.go

clean:
	-rm -f $(BIN)

# Docker image build target
IMAGE_NAME    := ghcr.io/microsoft/ghqr
IMAGE_TAG     := $(if $(PRODUCT_VERSION),$(PRODUCT_VERSION),latest)

build-image: $(TARGET)
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@if [ "$(PRODUCT_VERSION)" != "" ]; then \
		docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):latest; \
	fi
