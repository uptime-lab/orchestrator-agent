package ports

import (
	"agent/pkg/domain/node"
)

// FingerprintReader defines the interface for reading hardware fingerprint
type FingerprintReader interface {
	// Harvest collects hardware fingerprint information
	Harvest() (node.HardwareFingerprint, error)
}
