module agent-signer

go 1.26.4

// Pinned to match backend/ and agent/. Without it this module built
// against the go1.26.4 stdlib, which is the only reason govulncheck reported a
// PACKAGE-level GO-2026-4970 here and nowhere else in the repository.
toolchain go1.26.11

require (
	github.com/go-piv/piv-go/v2 v2.6.0
	golang.org/x/term v0.48.0
)

require (
	golang.org/x/crypto v0.59.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
)
