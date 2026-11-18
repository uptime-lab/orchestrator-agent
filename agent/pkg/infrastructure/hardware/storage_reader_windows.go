//go:build windows

package hardware

import (
	proto "agent/pkg/infrastructure/grpc/proto"
)

// StorageReader detects available storage devices on Windows systems (noop)
type StorageReader struct{}

// NewStorageReader creates a new storage reader
func NewStorageReader() *StorageReader {
	return &StorageReader{}
}

// DetectDevices detects available storage devices and returns a map of device paths to StorageDevice metadata
// This is a stub implementation for Windows - returns a single stub device for testing
func (r *StorageReader) DetectDevices() (map[string]*proto.StorageDevice, error) {
	// Return stub device for testing on Windows
	devices := make(map[string]*proto.StorageDevice)
	devices["/dev/sda1"] = &proto.StorageDevice{
		Path:          "/dev/sda1",
		Label:         "Stub Device (Windows) - 500GB",
		Model:         "Stub Device",
		DeviceType:    "ssd",
		TotalCapacity: 500 * 1024 * 1024 * 1024, // 500GB
		UsedSpace:     100 * 1024 * 1024 * 1024, // 100GB
		AvailableSpace: 400 * 1024 * 1024 * 1024, // 400GB
		Filesystem:    "ntfs",
		IsRemovable:   false,
		IsReadOnly:    false,
	}
	return devices, nil
}

