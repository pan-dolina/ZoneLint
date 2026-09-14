# Release Verification

This document lists the checks to run before publishing a release.

## Pre-release checklist

1. **Full test suite passes**

   ```sh
   go test -race -count=1 ./...
   ```

2. **Fuzzing runs clean**

   ```sh
   go test -run xxx -fuzz FuzzParseDNSKEY ./internal/dnssec/ -fuzztime 30s
   ```

3. **Linting passes**

   ```sh
   make lint
   ```

4. **Module integrity**

   ```sh
   go mod verify
   ```

5. **Build all platforms**

   ```sh
   GOOS=linux GOARCH=amd64 go build -trimpath -o dist/zonelint-linux-amd64 ./cmd/zonelint
   GOOS=linux GOARCH=arm64 go build -trimpath -o dist/zonelint-linux-arm64 ./cmd/zonelint
   GOOS=darwin GOARCH=amd64 go build -trimpath -o dist/zonelint-darwin-amd64 ./cmd/zonelint
   GOOS=darwin GOARCH=arm64 go build -trimpath -o dist/zonelint-darwin-arm64 ./cmd/zonelint
   GOOS=windows GOARCH=amd64 go build -trimpath -o dist/zonelint-windows-amd64.exe ./cmd/zonelint
   GOOS=windows GOARCH=arm64 go build -trimpath -o dist/zonelint-windows-arm64.exe ./cmd/zonelint
   ```

6. **Checksums**

   ```sh
   sha256sum dist/zonelint-* > checksums.sha256
   ```

7. **SBOM generation**

   ```sh
   go list -m all | cyclonedx-gomod > bom.json
   ```

8. **OSV-Scanner**

   ```sh
   osv-scanner --lockfile go.mod
   ```

9. **Version flag**

   ```sh
   ./dist/zonelint version
   ```

## Signing (optional)

- Sign checksums with GPG.
- Generate Sigstore/Cosign signatures for binaries.
- Attach provenance (SLSA) to releases.

## Publishing

- Tag `vX.Y.Z`, push.
- Attach binaries, checksums, SBOM, and signatures.
- Update CHANGELOG.
