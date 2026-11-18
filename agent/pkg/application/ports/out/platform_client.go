package ports

import (
	"context"

	"agent/pkg/domain/node"
	proto "agent/pkg/infrastructure/grpc/proto"
)

// PlatformClient defines the interface for communicating with the platform
type PlatformClient interface {
	// Connect sends a connection request to the platform
	Connect(ctx context.Context, platformURL string, req node.ConnectionRequest) error

	// SendStatusUpdate sends a status update to the platform
	SendStatusUpdate(nodeID, accountID, uniqueToken, status, message string) error

	// SendCommandStatus sends a command status update to the platform
	SendCommandStatus(nodeID, accountID, uniqueToken, commandID, status string, progress int32, details string) error
	// SendCommandStatusWithResult is SendCommandStatus plus structured outputs
	// (workflow blocks: read_file/run_script/...). Delivered only while
	// connected — results are not queued.
	SendCommandStatusWithResult(nodeID, accountID, uniqueToken, commandID, status string, progress int32, details string, result map[string]string) error

	// SendSystemInfo sends system information (storage, network, hardware, OS) to the platform
	SendSystemInfo(nodeID, accountID, uniqueToken string, systemInfoUpdate *proto.SystemInfoUpdate) error

	// SendMetrics sends a live resource-utilization sample. It is dropped (not
	// queued) when disconnected, since a stale sample is worthless.
	SendMetrics(nodeID, accountID, uniqueToken string, metrics *proto.MetricsUpdate) error

	// SendNodeEvent sends a spontaneous device event (physical button press).
	// Dropped (not queued) when disconnected — a replayed press is a lie.
	SendNodeEvent(nodeID, accountID, uniqueToken, eventType, pressKind string) error

	// SendFileChangedEvent sends a file changed event to the platform
	SendFileChangedEvent(nodeID, accountID, uniqueToken, path, content, hash string, version int32, status, errorMessage string) error

	// StartHeartbeat starts sending heartbeats at regular intervals
	StartHeartbeat(ctx context.Context, nodeID, accountID, uniqueToken string)

	// ListenForCommands listens for commands from the platform
	ListenForCommands(ctx context.Context, commandHandler func(*proto.Command) error)

	// Close closes the platform connection
	Close() error
}
