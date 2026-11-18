package handlers

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func testHandler() *CommandHandler {
	return &CommandHandler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// stockUbuntuRoot builds the shape a stock Ubuntu 26.04 preinstalled raspi image
// actually has: the networkd unit ships, /etc/netplan is EMPTY, and there is no
// persistent enablement anywhere. That emptiness is the bug's habitat.
func stockUbuntuRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "usr", "lib", "systemd", "system"))
	mustWrite(t, filepath.Join(root, "usr", "lib", "systemd", "system", networkdUnit), "[Unit]\n")
	mustMkdirAll(t, filepath.Join(root, "etc", "netplan"))
	mustMkdirAll(t, filepath.Join(root, "etc", "systemd", "system", "multi-user.target.wants"))
	return root
}

func mustMkdirAll(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func enablementLink(root string) string {
	return filepath.Join(root, "etc", "systemd", "system", "multi-user.target.wants", networkdUnit)
}

func TestEnsureNetworkdEnabledOnRoot_EnablesOnStockUbuntu(t *testing.T) {
	root := stockUbuntuRoot(t)

	if err := testHandler().ensureNetworkdEnabledOnRoot(root); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	target, err := os.Readlink(enablementLink(root))
	if err != nil {
		t.Fatalf("enablement symlink not created: %v", err)
	}
	// Must be the path as the TARGET's systemd will read it — an absolute path
	// inside the target, never one prefixed with our mount point. Getting this
	// wrong yields a dangling link that fails only on the device.
	if target != networkdUnitPath {
		t.Fatalf("symlink points at %q, want %q", target, networkdUnitPath)
	}
}

func TestEnsureNetworkdEnabledOnRoot_IsIdempotent(t *testing.T) {
	root := stockUbuntuRoot(t)
	h := testHandler()

	for i := range 3 {
		if err := h.ensureNetworkdEnabledOnRoot(root); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if _, err := os.Readlink(enablementLink(root)); err != nil {
		t.Fatalf("enablement symlink missing after repeat calls: %v", err)
	}
}

func TestEnsureNetworkdEnabledOnRoot_LeavesExistingEnablementAlone(t *testing.T) {
	root := stockUbuntuRoot(t)
	// An operator (or the distro) already enabled it, pointing somewhere else.
	const foreign = "/etc/systemd/system/my-networkd.service"
	if err := os.Symlink(foreign, enablementLink(root)); err != nil {
		t.Fatalf("seed symlink: %v", err)
	}

	if err := testHandler().ensureNetworkdEnabledOnRoot(root); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	target, err := os.Readlink(enablementLink(root))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != foreign {
		t.Fatalf("overwrote an enablement we did not create: got %q, want %q", target, foreign)
	}
}

func TestEnsureNetworkdEnabledOnRoot_SkipsWhenUnitAbsent(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, filepath.Join(root, "etc", "netplan"))

	if err := testHandler().ensureNetworkdEnabledOnRoot(root); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Lstat(enablementLink(root)); !os.IsNotExist(err) {
		t.Fatal("enabled systemd-networkd on an image that does not ship it")
	}
}

// The regression that matters most: enabling networkd next to NetworkManager
// puts two DHCP clients on one interface. That is worse than the race being
// fixed and it reproduces on EVERY boot, so each detection route gets a case.
func TestEnsureNetworkdEnabledOnRoot_SkipsForeignManagers(t *testing.T) {
	cases := []struct {
		name string
		seed func(t *testing.T, root string)
	}{
		{
			name: "NetworkManager enabled as a unit",
			seed: func(t *testing.T, root string) {
				mustWrite(t, filepath.Join(root, "etc", "systemd", "system", "multi-user.target.wants", "NetworkManager.service"), "")
			},
		},
		{
			name: "NetworkManager owns saved connections",
			seed: func(t *testing.T, root string) {
				mustWrite(t, filepath.Join(root, "etc", "NetworkManager", "system-connections", "lan.nmconnection"), "[connection]\n")
			},
		},
		{
			name: "netplan present but delegates to NetworkManager",
			seed: func(t *testing.T, root string) {
				mustWrite(t, filepath.Join(root, "etc", "netplan", "01-network-manager-all.yaml"),
					"network:\n  version: 2\n  renderer: NetworkManager\n")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := stockUbuntuRoot(t)
			tc.seed(t, root)

			if err := testHandler().ensureNetworkdEnabledOnRoot(root); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, err := os.Lstat(enablementLink(root)); !os.IsNotExist(err) {
				t.Fatal("enabled systemd-networkd on a foreign-managed image")
			}
		})
	}
}

func TestForeignNetworkManagerOnRoot_IfupdownOnlyWhenNetplanAbsent(t *testing.T) {
	h := testHandler()

	// No /etc/netplan at all + /etc/network/interfaces => ifupdown owns it.
	ifupdown := t.TempDir()
	mustWrite(t, filepath.Join(ifupdown, "etc", "network", "interfaces"), "auto eth0\n")
	if manager, foreign := h.foreignNetworkManagerOnRoot(ifupdown); !foreign || manager != "ifupdown" {
		t.Fatalf("got (%q, %v), want (ifupdown, true)", manager, foreign)
	}

	// Ubuntu ships BOTH a netplan directory and a legacy /etc/network/interfaces
	// stub. Treating that as ifupdown would skip the fix on exactly the image
	// that needs it, so netplan's presence has to win.
	both := stockUbuntuRoot(t)
	mustWrite(t, filepath.Join(both, "etc", "network", "interfaces"), "# ifupdown has been replaced by netplan\n")
	if manager, foreign := h.foreignNetworkManagerOnRoot(both); foreign {
		t.Fatalf("classified a netplan image as %q; the fix would be skipped where it is needed", manager)
	}
}

func TestForeignNetworkManagerOnRoot_UnknownImageIsLeftAlone(t *testing.T) {
	// Positive evidence only: an image we cannot classify must not be declared
	// foreign (that silently disables the fix) nor acted on blindly.
	if manager, foreign := testHandler().foreignNetworkManagerOnRoot(t.TempDir()); foreign {
		t.Fatalf("unclassifiable image reported as %q", manager)
	}
}

func TestEnsureNetworkConfigOnRoot_WritesNetplanAndSkipsForeign(t *testing.T) {
	h := testHandler()

	root := stockUbuntuRoot(t)
	if err := h.ensureNetworkConfigOnRoot(root); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	written := filepath.Join(root, "etc", "netplan", "99-orchestrator.yaml")
	info, err := os.Stat(written)
	if err != nil {
		t.Fatalf("netplan not written: %v", err)
	}
	// netplan warns about and may ignore a world-readable netdef.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("netplan mode is %o, want 600", perm)
	}

	nm := stockUbuntuRoot(t)
	mustWrite(t, filepath.Join(nm, "etc", "NetworkManager", "system-connections", "lan.nmconnection"), "[connection]\n")
	if err := h.ensureNetworkConfigOnRoot(nm); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(nm, "etc", "netplan", "99-orchestrator.yaml")); !os.IsNotExist(err) {
		t.Fatal("wrote a networkd netplan onto a NetworkManager image")
	}
}
