# Dockerfile
# Copyright 2026 Monagle Pty Ltd
#
# Multi-stage build for Linux CI testing.
# Stage 1 (deps): resolves Swift package dependencies — cached unless Package.swift changes.
# Stage 2 (builder): compiles all targets.
# Stage 3 (tester): default CMD runs the test suite.

ARG SWIFT_VERSION=6.2
ARG UBUNTU_VERSION=noble

FROM swift:${SWIFT_VERSION}-${UBUNTU_VERSION} AS deps
WORKDIR /build
# Copy manifests only — changes to sources don't invalidate this layer
COPY Package.swift Package.resolved ./
RUN swift package resolve

FROM deps AS builder
# Copy everything needed to compile
COPY Sources ./Sources
COPY Tests ./Tests
RUN swift build 2>&1
RUN swift build --target MatterLinux 2>&1

FROM builder AS tester
CMD ["swift", "test", "--parallel"]
