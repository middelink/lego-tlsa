.PHONY: clean build test

MAIN_DIRECTORY := .
BIN_OUTPUT := $(if $(filter $(shell go env GOOS), windows), lego-tlsa.exe, lego-tlsa)

TAG_NAME := $(shell git tag -l --contains HEAD)
SHA := $(shell git rev-parse HEAD)
VERSION := $(if $(TAG_NAME),$(TAG_NAME),$(SHA))

default: clean test build

clean:
	rm -rf ${BIN_OUTPUT} cover.out

build: clean
	CGO_ENABLED=0 go build -v -trimpath -ldflags '-s -w -X "main.version=${VERSION}"' -o ${BIN_OUTPUT} ${MAIN_DIRECTORY}

test: clean
	go test -v -cover ./...
