package node

import (
	"github.com/google/uuid"
)

// HardwareFingerprint represents the hardware identification of a node
type HardwareFingerprint struct {
	MacAddress     string `json:"mac_address"`
	HardwareSerial string `json:"hardware_serial"`
}

// AdoptionConfig represents the parsed adoption file data
// Supports two modes:
// 1. Node-specific: NodeID + UniqueToken (pre-registered node)
// 2. Master token: MasterToken only (agent connects and awaits approval)
type AdoptionConfig struct {
	// Node-specific fields (required for node-specific mode, empty for master token mode)
	NodeID      uuid.UUID `json:"node_id,omitempty"`
	UniqueToken string    `json:"unique_token,omitempty"`

	// Master token field (required for master token mode, empty for node-specific mode)
	MasterToken string `json:"master_token,omitempty"`

	// Common fields (always required)
	AccountID    uuid.UUID `json:"account_id"`
	PlatformURL  string    `json:"platform_url"`
	GRPCEndpoint string    `json:"grpc_endpoint"`
	CreatedAt    int64     `json:"created_at"`
}

// IsMasterTokenMode returns true if this config uses master token authentication
func (c *AdoptionConfig) IsMasterTokenMode() bool {
	return c.MasterToken != "" && c.NodeID == uuid.Nil
}

// IsNodeTokenMode returns true if this config uses node-specific token authentication
func (c *AdoptionConfig) IsNodeTokenMode() bool {
	return c.NodeID != uuid.Nil && c.UniqueToken != ""
}

// GetEffectiveToken returns the token to use for authentication
// In master token mode, returns MasterToken; otherwise returns UniqueToken
func (c *AdoptionConfig) GetEffectiveToken() string {
	if c.IsMasterTokenMode() {
		return c.MasterToken
	}
	return c.UniqueToken
}

// ConnectionRequest represents the connection payload sent to the platform
type ConnectionRequest struct {
	NodeID      uuid.UUID           `json:"node_id"`
	AccountID   uuid.UUID           `json:"account_id"`
	UniqueToken string              `json:"unique_token"`
	Fingerprint HardwareFingerprint `json:"fingerprint"`
	// AgentKind declares what this binary IS: "full" for the managing agent,
	// "watcher" for the telemetry-only variant that carries no
	// command-execution code. The platform records it and refuses to dispatch
	// commands to a watcher.
	AgentKind string `json:"agent_kind"`
	// LEDSources advertises the ambient-indication metric sources this binary
	// can render (LED v2). Empty for the watcher, which renders nothing.
	LEDSources []string `json:"led_sources,omitempty"`
}
