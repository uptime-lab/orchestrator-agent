package hardware

import "testing"

func TestExtractEEPROMPackageSerial(t *testing.T) {
	tests := []struct {
		name     string
		pieeprom []byte
		want     string
	}{
		{
			name:     "per-device package",
			pieeprom: []byte("BOOT_UART=1\nBOOT_ORDER=0xf167\nHTTP_HOST=192.0.2.10\nHTTP_PATH=http-boot/10000000abcd1234\n\x00\x00"),
			want:     "10000000abcd1234",
		},
		{
			name:     "uppercase serial is normalized",
			pieeprom: []byte("HTTP_PATH=http-boot/10000000ABCD1234"),
			want:     "10000000abcd1234",
		},
		{
			name:     "embedded in binary noise",
			pieeprom: append(append([]byte{0xff, 0x00, 0x1b}, []byte("HTTP_PATH=http-boot/10000000feedf00d")...), 0x00, 0xff),
			want:     "10000000feedf00d",
		},
		{
			name:     "shared package without per-device path",
			pieeprom: []byte("BOOT_ORDER=0xf167\nTFTP_PREFIX=0\n"),
			want:     "",
		},
		{
			name:     "legacy templated path is not a serial",
			pieeprom: []byte("HTTP_PATH=http-boot/{pi_serial_number}"),
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractEEPROMPackageSerial(tt.pieeprom); got != tt.want {
				t.Errorf("extractEEPROMPackageSerial() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractEEPROMBootOrder(t *testing.T) {
	tests := []struct {
		name     string
		pieeprom []byte
		want     string
	}{
		{
			name:     "config section order",
			pieeprom: []byte("BOOT_UART=1\nBOOT_ORDER=0xf167\nHTTP_HOST=1.2.3.4\n"),
			want:     "0xf167",
		},
		{
			name:     "uppercase hex normalized",
			pieeprom: []byte("BOOT_ORDER=0xF176"),
			want:     "0xf176",
		},
		{
			name:     "firmware printf without '=' is ignored",
			pieeprom: []byte("BOOT_ORDER override: 0x%08x\nsome noise"),
			want:     "",
		},
		{
			name:     "absent",
			pieeprom: []byte("HTTP_PATH=http-boot/abc"),
			want:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractEEPROMBootOrder(tt.pieeprom); got != tt.want {
				t.Errorf("ExtractEEPROMBootOrder() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyEEPROMPackage(t *testing.T) {
	tests := []struct {
		name        string
		pkgSerial   string
		ownSerial   string
		spent       bool
		inertMedium bool
		wantRemove  bool
	}{
		{
			name:      "foreign serial on reused card is removed",
			pkgSerial: "10000000feedf00d", ownSerial: "10000000abcd1234",
			wantRemove: true,
		},
		{
			name:      "foreign serial removed even when spent flag unset",
			pkgSerial: "10000000feedf00d", ownSerial: "10000000abcd1234",
			spent: false, inertMedium: false,
			wantRemove: true,
		},
		{
			name:      "own staged package on SD is kept",
			pkgSerial: "10000000abcd1234", ownSerial: "10000000abcd1234",
			wantRemove: false,
		},
		{
			name:      "own serial case-insensitive match is kept",
			pkgSerial: "10000000abcd1234", ownSerial: "10000000ABCD1234",
			wantRemove: false,
		},
		{
			name:      "spent package is removed",
			pkgSerial: "10000000abcd1234", ownSerial: "10000000abcd1234",
			spent:      true,
			wantRemove: true,
		},
		{
			name:      "own package staged on NVMe is removed",
			pkgSerial: "10000000abcd1234", ownSerial: "10000000abcd1234",
			inertMedium: true,
			wantRemove:  true,
		},
		{
			name:      "shared package on SD is kept",
			pkgSerial: "", ownSerial: "10000000abcd1234",
			wantRemove: false,
		},
		{
			name:      "shared package on NVMe is removed",
			pkgSerial: "", ownSerial: "10000000abcd1234",
			inertMedium: true,
			wantRemove:  true,
		},
		{
			name:      "unknown own serial never triggers foreign removal",
			pkgSerial: "10000000feedf00d", ownSerial: "",
			wantRemove: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRemove, reason := classifyEEPROMPackage(tt.pkgSerial, tt.ownSerial, tt.spent, tt.inertMedium)
			if gotRemove != tt.wantRemove {
				t.Errorf("classifyEEPROMPackage() remove = %v (reason %q), want %v", gotRemove, reason, tt.wantRemove)
			}
			if gotRemove && reason == "" {
				t.Error("classifyEEPROMPackage() removal must carry a reason")
			}
		})
	}
}
