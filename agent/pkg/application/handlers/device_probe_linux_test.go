//go:build linux

package handlers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestClassifyDeviceProbeError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want deviceProbeVerdict
	}{
		{"nil is ok", nil, deviceProbeOK},
		// The measured failure: a UAS disk behind a browned-out board.
		{"ENXIO is not responding", syscall.ENXIO, deviceProbeNotResponding},
		{"EIO is not responding", syscall.EIO, deviceProbeNotResponding},
		{"ENODEV is not responding", syscall.ENODEV, deviceProbeNotResponding},
		{"ENOMEDIUM is not responding", syscall.ENOMEDIUM, deviceProbeNotResponding},
		{"short read is not responding", io.ErrUnexpectedEOF, deviceProbeNotResponding},
		// Wrapped the way os.OpenFile actually returns it.
		{
			"wrapped ENXIO is not responding",
			&fs.PathError{Op: "open", Path: "/dev/sda", Err: syscall.ENXIO},
			deviceProbeNotResponding,
		},
		{
			"fmt-wrapped EIO is not responding",
			fmt.Errorf("reading /dev/sda: %w", syscall.EIO),
			deviceProbeNotResponding,
		},
		// Everything else must stay inconclusive, or the probe becomes a new way
		// for a healthy device to be refused.
		{"EACCES is inconclusive", syscall.EACCES, deviceProbeInconclusive},
		{"EBUSY is inconclusive", syscall.EBUSY, deviceProbeInconclusive},
		{"EINVAL is inconclusive", syscall.EINVAL, deviceProbeInconclusive},
		{"ENOENT is inconclusive", syscall.ENOENT, deviceProbeInconclusive},
		{"an opaque error is inconclusive", errors.New("boom"), deviceProbeInconclusive},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDeviceProbeError(tc.err); got != tc.want {
				t.Fatalf("classifyDeviceProbeError(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}

func TestProbeDeviceRespondsOnRegularFile(t *testing.T) {
	// A readable file at least as long as one probe read stands in for a healthy
	// device; this asserts the happy path does not report a false failure.
	path := t.TempDir() + "/disk.img"
	if err := os.WriteFile(path, make([]byte, deviceProbeReadBytes*2), 0o600); err != nil {
		t.Fatalf("seeding the fake device: %v", err)
	}
	verdict, err := probeDeviceResponds(path)
	if verdict != deviceProbeOK || err != nil {
		t.Fatalf("probeDeviceResponds = (%d, %v), want (ok, nil)", verdict, err)
	}
}

func TestProbeDeviceRespondsOnMissingPathIsInconclusive(t *testing.T) {
	// ENOENT is not the device failing to answer — the caller has already
	// established the node exists, so anything else here must not refuse.
	verdict, err := probeDeviceResponds(t.TempDir() + "/absent")
	if verdict != deviceProbeInconclusive {
		t.Fatalf("probeDeviceResponds on a missing path = %d (err %v), want inconclusive", verdict, err)
	}
}
