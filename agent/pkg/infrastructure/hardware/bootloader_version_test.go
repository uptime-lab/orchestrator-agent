//go:build linux

package hardware

import "testing"

func TestParseBootloaderVersion(t *testing.T) {
	t.Run("returns the firmware hash, not the build date", func(t *testing.T) {
		// `vcgencmd bootloader_version` on current RPi firmware.
		out := "2024/06/05 15:30:37\n" +
			"version f2ffbeaa6d59105a273f8fd8213a924f3eb7b207\n" +
			"timestamp 1717601437\n" +
			"update-time 0\n" +
			"capabilities 0x0000007f"
		ver, ts := parseBootloaderVersion(out)
		if ver != "f2ffbeaa6d59105a273f8fd8213a924f3eb7b207" {
			t.Errorf("version = %q, want the hash from the version line (the freshness badge compares hashes)", ver)
		}
		if ts != 1717601437 {
			t.Errorf("timestamp = %d, want 1717601437 (explicit timestamp line)", ts)
		}
	})

	t.Run("drops the channel suffix from the version line", func(t *testing.T) {
		// Observed live: the version line carries a " (release)" channel suffix,
		// which would defeat the freshness comparison against the signer's hash.
		out := "2026/06/29 00:07:01\n" +
			"version f68405bcf704b03511bf1656e86924e8cd6398b4 (release)\n" +
			"timestamp 1751155621"
		ver, _ := parseBootloaderVersion(out)
		if ver != "f68405bcf704b03511bf1656e86924e8cd6398b4" {
			t.Errorf("version = %q, want just the hash token without the (release) suffix", ver)
		}
	})

	t.Run("falls back to parsing the first line as a build date", func(t *testing.T) {
		out := "2024/06/05 15:30:37\nversion abcdef"
		ver, ts := parseBootloaderVersion(out)
		if ver != "abcdef" {
			t.Errorf("version = %q, want the hash", ver)
		}
		if ts == 0 {
			t.Error("expected the first-line date to be parsed when no timestamp line is present")
		}
	})

	t.Run("empty output", func(t *testing.T) {
		if ver, ts := parseBootloaderVersion(""); ver != "" || ts != 0 {
			t.Errorf("empty output must yield empty result, got %q/%d", ver, ts)
		}
	})

	t.Run("no version line yields empty version", func(t *testing.T) {
		ver, _ := parseBootloaderVersion("not-a-date\nfoo bar")
		if ver != "" {
			t.Errorf("version = %q, want empty when there is no version line", ver)
		}
	})
}
