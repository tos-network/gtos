# This Makefile is meant to be used by people that do not usually work
# with Go source code. If you know what GOPATH is then you probably
# don't need to bother with make.

.PHONY: gtos android ios gtos-cross evm all test clean
.PHONY: gtos-linux gtos-linux-386 gtos-linux-amd64 gtos-linux-mips64 gtos-linux-mips64le
.PHONY: gtos-linux-arm gtos-linux-arm-5 gtos-linux-arm-6 gtos-linux-arm-7 gtos-linux-arm64
.PHONY: gtos-darwin gtos-darwin-386 gtos-darwin-amd64
.PHONY: gtos-windows gtos-windows-386 gtos-windows-amd64

GOBIN = ./build/bin
GO ?= latest
GORUN = env GO111MODULE=on go run

gtos:
	$(GORUN) build/ci.go install ./cmd/gtos
	@echo "Done building."
	@echo "Run \"$(GOBIN)/gtos\" to launch gtos."

all:
	$(GORUN) build/ci.go install

android:
	$(GORUN) build/ci.go aar --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/gtos.aar\" to use the library."
	@echo "Import \"$(GOBIN)/gtos-sources.jar\" to add javadocs"
	@echo "For more info see https://stackoverflow.com/questions/20994336/android-studio-how-to-attach-javadoc"
	
ios:
	$(GORUN) build/ci.go xcode --local
	@echo "Done building."
	@echo "Import \"$(GOBIN)/Gtos.framework\" to use the library."

test: all
	$(GORUN) build/ci.go test

testp: all
	$(GORUN) build/ci.go test $(PA)

lint: ## Run linters.
	$(GORUN) build/ci.go lint

clean:
	env GO111MODULE=on go clean -cache
	rm -fr build/_workspace/pkg/ $(GOBIN)/*

# The devtools target installs tools required for 'go generate'.
# You need to put $GOBIN (or $GOPATH/bin) in your PATH to use 'go generate'.

devtools:
	env GOBIN= go get -u golang.org/x/tools/cmd/stringer
	env GOBIN= go get -u github.com/kevinburke/go-bindata/go-bindata
	env GOBIN= go get -u github.com/fjl/gencodec
	env GOBIN= go get -u github.com/golang/protobuf/protoc-gen-go
	env GOBIN= go install ./cmd/abigen
	@type "npm" 2> /dev/null || echo 'Please install node.js and npm'
	@type "solc" 2> /dev/null || echo 'Please install solc'
	@type "protoc" 2> /dev/null || echo 'Please install protoc'

# Cross Compilation Targets (xgo)

gtos-cross: gtos-linux gtos-darwin gtos-windows gtos-android gtos-ios
	@echo "Full cross compilation done:"
	@ls -ld $(GOBIN)/gtos-*

gtos-linux: gtos-linux-386 gtos-linux-amd64 gtos-linux-arm gtos-linux-mips64 gtos-linux-mips64le
	@echo "Linux cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-*

gtos-linux-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/386 -v ./cmd/gtos
	@echo "Linux 386 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep 386

gtos-linux-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/amd64 -v ./cmd/gtos
	@echo "Linux amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep amd64

gtos-linux-arm: gtos-linux-arm-5 gtos-linux-arm-6 gtos-linux-arm-7 gtos-linux-arm64
	@echo "Linux ARM cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep arm

gtos-linux-arm-5:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-5 -v ./cmd/gtos
	@echo "Linux ARMv5 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep arm-5

gtos-linux-arm-6:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-6 -v ./cmd/gtos
	@echo "Linux ARMv6 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep arm-6

gtos-linux-arm-7:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm-7 -v ./cmd/gtos
	@echo "Linux ARMv7 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep arm-7

gtos-linux-arm64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/arm64 -v ./cmd/gtos
	@echo "Linux ARM64 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep arm64

gtos-linux-mips:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips --ldflags '-extldflags "-static"' -v ./cmd/gtos
	@echo "Linux MIPS cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep mips

gtos-linux-mipsle:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mipsle --ldflags '-extldflags "-static"' -v ./cmd/gtos
	@echo "Linux MIPSle cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep mipsle

gtos-linux-mips64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips64 --ldflags '-extldflags "-static"' -v ./cmd/gtos
	@echo "Linux MIPS64 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep mips64

gtos-linux-mips64le:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=linux/mips64le --ldflags '-extldflags "-static"' -v ./cmd/gtos
	@echo "Linux MIPS64le cross compilation done:"
	@ls -ld $(GOBIN)/gtos-linux-* | grep mips64le

gtos-darwin: gtos-darwin-386 gtos-darwin-amd64
	@echo "Darwin cross compilation done:"
	@ls -ld $(GOBIN)/gtos-darwin-*

gtos-darwin-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=darwin/386 -v ./cmd/gtos
	@echo "Darwin 386 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-darwin-* | grep 386

gtos-darwin-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=darwin/amd64 -v ./cmd/gtos
	@echo "Darwin amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-darwin-* | grep amd64

gtos-windows: gtos-windows-386 gtos-windows-amd64
	@echo "Windows cross compilation done:"
	@ls -ld $(GOBIN)/gtos-windows-*

gtos-windows-386:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=windows/386 -v ./cmd/gtos
	@echo "Windows 386 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-windows-* | grep 386

gtos-windows-amd64:
	$(GORUN) build/ci.go xgo -- --go=$(GO) --targets=windows/amd64 -v ./cmd/gtos
	@echo "Windows amd64 cross compilation done:"
	@ls -ld $(GOBIN)/gtos-windows-* | grep amd64
