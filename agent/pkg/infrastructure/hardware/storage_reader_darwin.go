//go:build darwin

package hardware

import (
	proto "agent/pkg/infrastructure/grpc/proto"
)

// StorageReader detects available storage devices on Darwin/macOS systems (noop)
type StorageReader struct{}

// NewStorageReader creates a new storage reader
func NewStorageReader() *StorageReader {
	return &StorageReader{}
}

// DetectDevices detects available storage devices and returns a map of device paths to StorageDevice metadata
// This is a stub implementation for Darwin - returns a single stub device for testing
func (r *StorageReader) DetectDevices() (map[string]*proto.StorageDevice, error) {
	// Return stub device for testing on macOS/Darwin
	devices := make(map[string]*proto.StorageDevice)
	devices["/dev/sda"] = &proto.StorageDevice{
		Path:          "/dev/sda",
		Label:         "Stub Device (macOS) - 500GB",
		Model:         "Stub Device",
		DeviceType:    "ssd",
		TotalCapacity: 500 * 1024 * 1024 * 1024, // 500GB
		IsRemovable:   false,
		IsReadOnly:    false,
		Partitions: []*proto.StoragePartition{
			{
				PartitionId:    "/dev/sda1",
				MountPoint:     "/",
				Filesystem:     "apfs",
				UsedSpace:      100 * 1024 * 1024 * 1024, // 100GB
				AvailableSpace: 400 * 1024 * 1024 * 1024, // 400GB
			},
		},
	}
	return devices, nil
}
