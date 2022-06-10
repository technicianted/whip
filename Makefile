##################################################
# Variables                                      #
##################################################

VERSION		   ?= latest
IMAGE_REGISTRY ?= skyman.azurecr.io
IMAGE_REPO     ?= scratch
IMAGE_FULL = $(IMAGE_REGISTRY)/$(IMAGE_REPO)/southspot:$(VERSION)

ARCH       ?=amd64
CGO        ?=0
TARGET_OS  ?=linux

GIT_VERSION = $(shell git describe --always --abbrev=7)
GIT_COMMIT  = $(shell git rev-list -1 HEAD)
DATE        = $(shell date -u +"%Y.%m.%d.%H.%M.%S")
GOPATH      = $(shell go env GOPATH)
GOROOT      = $(shell go env GOROOT)
PROTOCPATH  = "${GOPATH}/bin"

GIT_VERSION := $(shell git rev-parse HEAD)
CURRENT_TIME := $(shell date "+%F-%T")
ifndef BUILD_VERSION
	BUILD_VERSION := $(GIT_VERSION)-$(CURRENT_TIME)
endif

.PHONY=binaries
.DEFAULT_GOAL := binaries

##################################################
# Build                                          #
##################################################
GO_BUILD_VARS= GO111MODULE=on CGO_ENABLED=$(CGO) GOOS=$(TARGET_OS) GOARCH=$(ARCH) GOROOT=$(GOROOT) GOPATH=$(GOPATH) GOPRIVATE=$(GOPRIVATE)

protos: pkg/proto/whip.pb.go

pkg/proto/whip.pb.go: pkg/proto/v1/whip.proto
	@protoc \
		--plugin=$(PROTOCPATH)/protoc-gen-go \
		--plugin=$(PROTOCPATH)/protoc-gen-go-grpc \
		-I pkg/proto/ pkg/proto/v1/whip.proto \
		--go_out=pkg/proto/v1 \
		--go-grpc_out=pkg/proto/v1

mocks: protos
	(cd pkg/proto/v1/mocks && mockgen -package mocks -destination whip_grpc.go "github.com/technicianted/whip/pkg/proto/v1" WhipClient,WhipServer,Whip_RegisterServer)
	(cd pkg/client/mocks && mockgen -package mocks -destination resolver.go "github.com/technicianted/whip/pkg/client/types" WhipEndpointResolver)

.PHONY: binaries
binaries: protos
	rm -rf bin/ > /dev/null 2>&1
	mkdir bin/
	$(GO_BUILD_VARS) go build -ldflags "-X github.com/technicianted/whip/version.Build=$(BUILD_VERSION)" -o bin/whip ./cmd/whip/
	$(GO_BUILD_VARS) go build -ldflags "-X github.com/technicianted/whip/version.Build=$(BUILD_VERSION)" -o bin/whiphack ./cmd/whiphack/

dockerbuild: binaries
	docker build -t whip .