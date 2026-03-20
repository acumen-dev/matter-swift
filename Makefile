# Makefile — SwiftMatter build and test targets
# Copyright 2026 Monagle Pty Ltd

SWIFT_IMAGE  ?= swift:6.2-noble
PROJECT_NAME  = swiftmatter
PROJECT_DIR   = $(shell pwd)

.PHONY: build test release clean \
        generate-model \
        ref-setup ref-setup-cert ref-setup-tool ref-test ref-all ref-clean \
        linux-build linux-test linux-shell \
        help

## ── Local (macOS) ─────────────────────────────────────────────────────────────

## build          Build all targets (debug)
build:
	swift build

## test           Run full test suite locally
test:
	swift test --parallel

## release        Build in release configuration
release:
	swift build -c release

## clean          Remove build artefacts
clean:
	rm -rf .build

## ── Code Generation ─────────────────────────────────────────────────────────

CHIP_VERSION := $(shell cat Tools/RefImpl/CONNECTEDHOMEIP_VERSION)
CHIP_DIR     := /tmp/swift-matter-refimpl/connectedhomeip-$(CHIP_VERSION)

## generate-model  Regenerate MatterModel from CHIP spec XML
generate-model:
	@test -d $(CHIP_DIR)/data_model || (echo "Run 'make ref-setup' first" && exit 1)
	cd Tools/MatterModelGenerator && swift run MatterModelGenerator \
		--input $(CHIP_DIR)/data_model/1.4 \
		--output ../../Sources/MatterModel/Generated

## ── Reference Tests ──────────────────────────────────────────────────────────

CHIPCERT     = Tools/RefImpl/bin/chip-cert
CHIPTOOL     = Tools/RefImpl/bin/chip-tool

## ref-setup      Clone connectedhomeip and build chip-cert + chip-tool
ref-setup:
	./Tools/RefImpl/setup.sh

## ref-setup-cert Build chip-cert only (faster)
ref-setup-cert:
	./Tools/RefImpl/setup.sh chip-cert

## ref-setup-tool Build chip-tool only
ref-setup-tool:
	./Tools/RefImpl/setup.sh chip-tool

## ref-test       Run reference tests (crypto vectors + chip-cert conformance)
ref-test:
	swift test --filter ReferenceTests

## ref-all        Build chip-cert then run reference tests
ref-all: ref-setup-cert ref-test

## ref-clean      Remove built binaries (forces rebuild on next ref-setup)
ref-clean:
	rm -rf Tools/RefImpl/bin

## ── Linux (Docker) ────────────────────────────────────────────────────────────

## linux-build    Build inside the Swift Linux container
linux-build:
	docker run --rm \
		-v "$(PROJECT_DIR):/workspace:cached" \
		-w /workspace \
		$(SWIFT_IMAGE) \
		swift build

## linux-test     Run tests inside the Swift Linux container
linux-test:
	docker run --rm \
		-v "$(PROJECT_DIR):/workspace:cached" \
		-w /workspace \
		$(SWIFT_IMAGE) \
		swift test --parallel

## linux-shell    Open an interactive shell in the Linux Swift container
linux-shell:
	docker run --rm -it \
		-v "$(PROJECT_DIR):/workspace:cached" \
		-w /workspace \
		$(SWIFT_IMAGE) \
		/bin/bash

## ── Help ──────────────────────────────────────────────────────────────────────

## help           Show this help
help:
	@grep -E '^## ' Makefile | sed 's/^## //'
