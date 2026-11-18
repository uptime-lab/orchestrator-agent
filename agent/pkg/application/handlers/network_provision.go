package handlers

// Network provisioning of the TARGET rootfs during install/provision. Kept out of
// command_handler_linux.go on purpose: this is plain filesystem work with no Linux
// syscalls, so it compiles — and is therefore unit-tested — on every platform.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ensureNetworkConfigOnRoot writes a default netplan (DHCP on any ethernet
// interface) into the target rootfs so the managed OS gets an IPv4 address and the
// agent can reach the platform. A 99- prefix + wildcard match keeps it additive and
// harmless on images that already configure the network. Netplan requires strict
// (0600) permissions, otherwise it warns and may ignore the file.
//
// Its real value is not the netdef — on an Ubuntu preinstalled image cloud-init's
// 50-cloud-init.yaml matches the same interface and sorts first, so networkd applies
// THAT one and ours is never used. What matters is that /etc/netplan is non-empty
// when the netplan generator runs on the very first boot, which on a stock image it
// otherwise is not.
func (h *CommandHandler) ensureNetworkConfigOnRoot(rootPath string) error {
	if manager, foreign := h.foreignNetworkManagerOnRoot(rootPath); foreign {
		// A networkd netdef is inert on such an image, but writing one is still
		// misleading to the next reader and pointless. Positive evidence only.
		h.logger.Info("target rootfs uses another network manager, skipping netplan write", "manager", manager)
		return nil
	}
	dir := filepath.Join(rootPath, "etc", "netplan")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", dir, err)
	}
	cfg := "network:\n" +
		"  version: 2\n" +
		"  renderer: networkd\n" +
		"  ethernets:\n" +
		"    orchestrator-eth:\n" +
		"      match:\n" +
		"        name: \"e*\"\n" +
		"      dhcp4: true\n"
	p := filepath.Join(dir, "99-orchestrator.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", p, err)
	}
	h.logger.Info("wrote default DHCP netplan to target rootfs", "path", p)
	return nil
}

// networkdUnit is the unit that must survive to boot, and the absolute path its
// enablement symlink has to point at inside the TARGET rootfs (never prefixed
// with rootPath — the link is read by the target's own systemd, not by us).
const (
	networkdUnit     = "systemd-networkd.service"
	networkdUnitPath = "/usr/lib/systemd/system/" + networkdUnit
)

// ensureNetworkdEnabledOnRoot gives systemd-networkd a PERSISTENT enablement
// symlink in the target rootfs.
//
// Why this is needed at all: on Ubuntu 26.04 raspi images systemd-networkd has no
// persistent enablement. `systemctl is-enabled` reports `enabled-runtime` from a
// symlink the netplan generator manufactures into /run on every boot, and the
// daemon is otherwise reached only through systemd-networkd.socket. A boot race
// seen on both CM5 and Pi 4 hardware stops networkd while it is still configuring
// eth0 from the dracut leftover (/run/systemd/network/zzzz-dracut-default.network)
// and — the part that makes it unrecoverable — CLOSES systemd-networkd.socket in
// the same breath. netplan-configure.service finishes a few seconds later and
// nothing ever starts the daemon again: no static Wants, and no socket left to
// activate it. The node boots with a carrier, no DHCP client, no IPv4, and stays
// that way indefinitely.
//
// netplan-configure.service is ordered from sysinit.target, which is reached
// before multi-user.target, so a static multi-user.target.wants symlink starts
// networkd AFTER the stop that loses it. That takes /run and the generator off the
// critical path on every boot, not merely the first.
//
// Deliberately writes the bare symlink rather than calling `systemctl enable`: the
// unit's [Install] carries Also=systemd-networkd-wait-online.service, which is
// WantedBy=network-online.target and can add a 120s boot stall on a host whose
// link is slow. It also needs no chroot, so it cannot fail on an image whose
// systemctl will not run under ours.
func (h *CommandHandler) ensureNetworkdEnabledOnRoot(rootPath string) error {
	if _, err := os.Stat(filepath.Join(rootPath, networkdUnitPath)); err != nil {
		h.logger.Info("target rootfs ships no systemd-networkd unit, skipping enablement")
		return nil
	}
	if manager, foreign := h.foreignNetworkManagerOnRoot(rootPath); foreign {
		// Enabling a second manager alongside NetworkManager puts two DHCP clients
		// on one interface. That is worse than the race being fixed here, and it
		// would reproduce on every boot rather than some of them.
		h.logger.Info("target rootfs uses another network manager, skipping networkd enablement", "manager", manager)
		return nil
	}

	wantsDir := filepath.Join(rootPath, "etc", "systemd", "system", "multi-user.target.wants")
	if err := os.MkdirAll(wantsDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", wantsDir, err)
	}
	link := filepath.Join(wantsDir, networkdUnit)
	if _, err := os.Lstat(link); err == nil {
		h.logger.Info("systemd-networkd already enabled in target rootfs", "link", link)
		return nil // never replace an enablement we did not create
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to inspect %s: %w", link, err)
	}
	if err := os.Symlink(networkdUnitPath, link); err != nil {
		return fmt.Errorf("failed to enable %s: %w", networkdUnit, err)
	}
	h.logger.Info("enabled systemd-networkd persistently in target rootfs", "link", link)
	return nil
}

// foreignNetworkManagerOnRoot names a network manager other than systemd-networkd
// that owns the target rootfs, if one can be positively identified.
//
// Positive evidence only, and it must stay that way: an image we cannot classify
// is left alone rather than guessed at. Guessing wrong in the other direction —
// declaring an unknown image "networkd" and enabling a daemon that fights the one
// already there — breaks a working install, which is a worse outcome than skipping
// a repair on an image that never had the bug.
func (h *CommandHandler) foreignNetworkManagerOnRoot(rootPath string) (string, bool) {
	nmEnabled := filepath.Join(rootPath, "etc", "systemd", "system", "multi-user.target.wants", "NetworkManager.service")
	if _, err := os.Stat(nmEnabled); err == nil {
		return "NetworkManager", true
	}
	if entries, err := os.ReadDir(filepath.Join(rootPath, "etc", "NetworkManager", "system-connections")); err == nil && len(entries) > 0 {
		return "NetworkManager", true
	}

	// netplan can be present and still delegate to NetworkManager (Raspberry Pi OS
	// Bookworm ships exactly that shape), so the directory existing proves nothing.
	netplanDir := filepath.Join(rootPath, "etc", "netplan")
	if entries, err := os.ReadDir(netplanDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			body, err := os.ReadFile(filepath.Join(netplanDir, e.Name()))
			if err != nil {
				continue
			}
			if strings.Contains(string(body), "renderer: NetworkManager") {
				return "NetworkManager", true
			}
		}
	} else if os.IsNotExist(err) {
		// No netplan at all: an ifupdown image configures the network from
		// /etc/network/interfaces and networkd would collide with it.
		if _, err := os.Stat(filepath.Join(rootPath, "etc", "network", "interfaces")); err == nil {
			return "ifupdown", true
		}
	}
	return "", false
}
