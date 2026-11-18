package grpc

import (
	"log/slog"
	"sync"
	"time"

	proto "agent/pkg/infrastructure/grpc/proto"
)

// MessageType represents the type of queued message
type MessageType int

const (
	MessageTypeStatusUpdate MessageType = iota
	MessageTypeCommandStatus
	MessageTypeSystemInfo
	MessageTypeFileChanged
)

func (t MessageType) String() string {
	switch t {
	case MessageTypeStatusUpdate:
		return "StatusUpdate"
	case MessageTypeCommandStatus:
		return "CommandStatus"
	case MessageTypeSystemInfo:
		return "SystemInfo"
	case MessageTypeFileChanged:
		return "FileChanged"
	default:
		return "Unknown"
	}
}

// DefaultQueueSize is the default maximum number of messages in the queue
const DefaultQueueSize = 100

// QueuedMessage represents a message waiting to be sent
type QueuedMessage struct {
	Type      MessageType
	Timestamp time.Time
	// Payload fields based on type
	StatusUpdate  *StatusUpdatePayload
	CommandStatus *CommandStatusPayload
	SystemInfo    *SystemInfoPayload
	FileChanged   *FileChangedPayload
}

// StatusUpdatePayload contains status update data
type StatusUpdatePayload struct {
	NodeID      string
	AccountID   string
	UniqueToken string
	Status      string
	Message     string
}

// CommandStatusPayload contains command status data
type CommandStatusPayload struct {
	NodeID      string
	AccountID   string
	UniqueToken string
	CommandID   string
	Status      string
	Progress    int32
	Details     string
	// Result carries the structured outputs of read_file / wait_for_file /
	// run_script. It used to be absent from this struct, and that absence was
	// silent data loss: a terminal status queued during a stream
	// blip was replayed WITHOUT its outputs, so the platform recorded `success`
	// with an empty result. A playbook doing read_file -> write_file then wrote
	// an empty value and stayed green — worse than a failure, because a failure
	// is visible.
	Result map[string]string
}

// SystemInfoPayload contains system info data
type SystemInfoPayload struct {
	NodeID           string
	AccountID        string
	UniqueToken      string
	SystemInfoUpdate *proto.SystemInfoUpdate
}

// FileChangedPayload contains file changed event data
type FileChangedPayload struct {
	NodeID       string
	AccountID    string
	UniqueToken  string
	Path         string
	Content      string
	Hash         string
	Version      int32
	Status       string
	ErrorMessage string
}

// MessageQueue is a bounded queue for messages during disconnection
type MessageQueue struct {
	messages []QueuedMessage
	maxSize  int
	mu       sync.Mutex
	logger   *slog.Logger
}

// NewMessageQueue creates a new message queue with the specified maximum size
func NewMessageQueue(maxSize int, logger *slog.Logger) *MessageQueue {
	if maxSize <= 0 {
		maxSize = DefaultQueueSize
	}
	return &MessageQueue{
		messages: make([]QueuedMessage, 0, maxSize),
		maxSize:  maxSize,
		logger:   logger,
	}
}

// Enqueue adds a message to the queue, dropping the oldest if full
func (q *MessageQueue) Enqueue(msg QueuedMessage) {
	q.mu.Lock()
	defer q.mu.Unlock()

	msg.Timestamp = time.Now()

	if len(q.messages) >= q.maxSize {
		// Drop oldest message
		dropped := q.messages[0]
		q.messages = q.messages[1:]
		q.logger.Warn("Message queue full, dropping oldest message",
			"dropped_type", dropped.Type.String(),
			"dropped_timestamp", dropped.Timestamp)
	}

	q.messages = append(q.messages, msg)
	q.logger.Debug("Message queued",
		"type", msg.Type.String(),
		"queue_size", len(q.messages))
}

// EnqueueStatusUpdate queues a status update message
func (q *MessageQueue) EnqueueStatusUpdate(nodeID, accountID, uniqueToken, status, message string) {
	q.Enqueue(QueuedMessage{
		Type: MessageTypeStatusUpdate,
		StatusUpdate: &StatusUpdatePayload{
			NodeID:      nodeID,
			AccountID:   accountID,
			UniqueToken: uniqueToken,
			Status:      status,
			Message:     message,
		},
	})
}

// EnqueueCommandStatus queues a command status message with no structured
// outputs.
func (q *MessageQueue) EnqueueCommandStatus(nodeID, accountID, uniqueToken, commandID, status string, progress int32, details string) {
	q.EnqueueCommandStatusWithResult(nodeID, accountID, uniqueToken, commandID, status, progress, details, nil)
}

// EnqueueCommandStatusWithResult queues a command status message, preserving its
// structured outputs so a reconnect delivers the same thing the live stream
// would have.
func (q *MessageQueue) EnqueueCommandStatusWithResult(nodeID, accountID, uniqueToken, commandID, status string, progress int32, details string, result map[string]string) {
	// Copied, not aliased: the caller's map is built per command and there is no
	// contract stopping it being reused or mutated between the enqueue and the
	// flush, which may be minutes apart.
	var copied map[string]string
	if len(result) > 0 {
		copied = make(map[string]string, len(result))
		for k, v := range result {
			copied[k] = v
		}
	}
	q.Enqueue(QueuedMessage{
		Type: MessageTypeCommandStatus,
		CommandStatus: &CommandStatusPayload{
			NodeID:      nodeID,
			AccountID:   accountID,
			UniqueToken: uniqueToken,
			CommandID:   commandID,
			Status:      status,
			Progress:    progress,
			Details:     details,
			Result:      copied,
		},
	})
}

// EnqueueSystemInfo queues a system info message
func (q *MessageQueue) EnqueueSystemInfo(nodeID, accountID, uniqueToken string, systemInfoUpdate *proto.SystemInfoUpdate) {
	q.Enqueue(QueuedMessage{
		Type: MessageTypeSystemInfo,
		SystemInfo: &SystemInfoPayload{
			NodeID:           nodeID,
			AccountID:        accountID,
			UniqueToken:      uniqueToken,
			SystemInfoUpdate: systemInfoUpdate,
		},
	})
}

// EnqueueFileChanged queues a file changed event message
func (q *MessageQueue) EnqueueFileChanged(nodeID, accountID, uniqueToken, path, content, hash string, version int32, status, errorMessage string) {
	q.Enqueue(QueuedMessage{
		Type: MessageTypeFileChanged,
		FileChanged: &FileChangedPayload{
			NodeID:       nodeID,
			AccountID:    accountID,
			UniqueToken:  uniqueToken,
			Path:         path,
			Content:      content,
			Hash:         hash,
			Version:      version,
			Status:       status,
			ErrorMessage: errorMessage,
		},
	})
}

// Drain removes and returns all messages from the queue
func (q *MessageQueue) Drain() []QueuedMessage {
	q.mu.Lock()
	defer q.mu.Unlock()

	messages := q.messages
	q.messages = make([]QueuedMessage, 0, q.maxSize)

	if len(messages) > 0 {
		q.logger.Info("Draining message queue", "count", len(messages))
	}

	return messages
}

// Size returns the current number of messages in the queue
func (q *MessageQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.messages)
}

// Clear removes all messages from the queue
func (q *MessageQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.messages = make([]QueuedMessage, 0, q.maxSize)
}
