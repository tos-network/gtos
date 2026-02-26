# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: gtos gtos-ed25519c gtos-ed25519native all test clean tps ttl-prune-bench ttl-prune-bench-ci dpos-soak lint devtools

GOBIN = ./build/bin
GO ?= latest
NCPU = $(shell expr $$(nproc) / 2)
GORUN = env GO111MODULE=on GOMAXPROCS=$(NCPU) go run
SOAK_ARGS ?= -duration 24h

gtos:
	$(GORUN) build/ci.go install ./cmd/gtos
	@echo "Done building."
	@echo "Run \"$(GOBIN)/gtos\" to launch gtos."

gtos-ed25519c:
	CGO_ENABLED=1 $(GORUN) build/ci.go install -tags "ed25519c" ./cmd/gtos
	@echo "Done building (ed25519 C backend)."
	@echo "Run \"$(GOBIN)/gtos\" to launch gtos."

gtos-ed25519native:
	CGO_ENABLED=1 $(GORUN) build/ci.go install -tags "ed25519c ed25519native" ./cmd/gtos
	@echo "Done building (ed25519 native accel backend)."
	@echo "Run \"$(GOBIN)/gtos\" to launch gtos."

all:
	$(GORUN) build/ci.go install

test: all
	$(GORUN) build/ci.go test

lint: ## Run linters.
	$(GORUN) build/ci.go lint

clean:
	env GO111MODULE=on go clean -cache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

tps: gtos
	bash ./scripts/tps_bench.sh

ttl-prune-bench:
	bash ./scripts/ttl_prune_bench_smoke.sh

ttl-prune-bench-ci:
	$(GORUN) build/ci.go bench-ttlprune

dpos-soak:
	bash ./scripts/dpos_stability_soak.sh


# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go install golang.org/x/tools/cmd/stringer@latest
	env GOBIN= go install github.com/fjl/gencodec@latest
	env GOBIN= go install github.com/golang/protobuf/protoc-gen-go@latest
	@type "protoc" 2> /dev/null || echo 'Please install protoc'
