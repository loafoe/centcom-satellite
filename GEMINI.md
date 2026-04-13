# Pico Agent - Progress Tracking

This file tracks the progress and technical decisions for the `pico-agent` project.

## Completed Tasks

### 2026-04-13: Multi-arch Build & Signing Pipeline
- [x] **Multi-arch OCI Support**: Configured `ko` to build and push images for both `linux/amd64` and `linux/arm64`.
- [x] **Cosign Signing**: Integrated `cosign` for keyless OIDC signing of OCI images in GitHub Actions.
- [x] **Manual Release Support**: Added `workflow_dispatch` to `release.yaml` to allow triggering releases with custom tags.
- [x] **Makefile Updates**: Updated `ko-push` target to support multi-arch builds locally.
- [x] **SBOM Generation**: Automated SBOM generation and attachment using `ko` and `cosign` in the release pipeline.
- [x] **License Documentation**: Added license details and badge to README.md.

## Project Context
- **Base Image**: `gcr.io/distroless/static-debian12:nonroot`
- **Registry**: `ghcr.io`
- **Go Version**: 1.23
