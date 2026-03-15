# Makefile — SwiftMatter build and test targets
# Copyright 2026 Monagle Pty Ltd

SWIFT_IMAGE  ?= swift:6.1-noble
PROJECT_NAME  = swiftmatter
PROJECT_DIR   = $(shell pwd)

.PHONY: build test release clean \
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
