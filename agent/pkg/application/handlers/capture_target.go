package handlers

import (
	"errors"
	"strings"

	"agent/pkg/domain/refusal"
)

// captureTargetDevice returns the disk a capture reads. There is no default:
// a capture runs on the recovery system, whose root is RAM, so nothing on the
// device says which disk the installed system boots from. A guessed disk
// fails on a board without it, or copies a data disk that was taken for the
// boot disk, which is found out only at restore time.
func captureTargetDevice(raw string) (string, error) {
	dev := strings.TrimSpace(raw)
	if dev == "" {
		return "", refusal.Wrap(errors.New("target_device is required: name the disk to back up (the recovery system cannot tell which disk the installed system boots from)"))
	}
	return dev, nil
}
