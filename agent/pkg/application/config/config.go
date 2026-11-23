package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agent/pkg/domain/node"

	"github.com/google/uuid"
)

// EEPROMAdoptionReader is an interface for reading adoption file content from EEPROM
type EEPROMAdoptionReader interface {
	ReadAdoptionFileFromEEPROM() (string, error)
}

// Parser handles parsing of adoption files
type Parser struct {
	logger *slog.Logger
}

// NewParser creates a new adoption file parser
func NewParser() *Parser {
	return &Parser{
		logger: slog.Default(),
	}
}

// NewParserWithLogger creates a new adoption file parser with a logger
func NewParserWithLogger(logger *slog.Logger) *Parser {
	return &Parser{
		logger: logger,
	}
}

// ReleasedMarkerPath is the file ReleaseAdoption leaves beside the adoption
// file it removed. Its presence is what stops the EEPROM fallback below.
func ReleasedMarkerPath(adoptionFilePath string) string {
	return adoptionFilePath + ".released"
}

// ErrIdentityReleased: the platform released this device's identity and the
// agent must not resurrect one from the EEPROM. The device waits to be adopted
// again; a new adoption file lifts the condition.
var ErrIdentityReleased = errors.New("this device's adoption identity was released by the platform; waiting to be adopted again")

// ParseAdoptionFile parses an adoption file and returns AdoptionConfig
// If the file doesn't exist and eepromReader is provided, it will try reading from EEPROM
//
// UNLESS the identity was released: ReleaseAdoption leaves a marker beside
// the file it removed, and while that marker exists the EEPROM is not
// consulted. Without it, deleting a node from the platform released nothing on
// an EEPROM-adopted Pi: the two disk files went, the
// next start read the same node id and token back out of the EEPROM, and the
// device carried on as the deleted node. A NEW adoption file — an install
// script, an SD card, a re-adoption — takes precedence over the marker, since
// the file is read first; the marker only decides what happens when there is
// no file.
func (p *Parser) ParseAdoptionFile(filePath string, eepromReader EEPROMAdoptionReader) (*node.AdoptionConfig, error) {
	var line string
	var err error

	// Try to read from disk first
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			if released, when := p.identityReleased(filePath); released {
				p.logger.Info("adoption identity was released by the platform; not reading the EEPROM identity, waiting to be adopted again",
					"file", filePath, "released_at", when)
				return nil, ErrIdentityReleased
			}
		}
		// If file doesn't exist and we have an EEPROM reader, try EEPROM
		if os.IsNotExist(err) && eepromReader != nil {
			p.logger.Info("adoption file not found on disk, reading from EEPROM", "file", filePath)
			line, err = eepromReader.ReadAdoptionFileFromEEPROM()
			if err != nil {
				return nil, fmt.Errorf("failed to read adoption file from both disk and EEPROM: %w", err)
			}
			if line == "" {
				return nil, fmt.Errorf("adoption file not found in disk or EEPROM")
			}
			p.logger.Info("adoption file read from EEPROM", "length", len(line))
		} else {
			return nil, fmt.Errorf("failed to read adoption file %s: %w", filePath, err)
		}
	} else {
		// Trim whitespace and get the single line
		line = strings.TrimSpace(string(content))
	}

	if len(line) == 0 {
		return nil, fmt.Errorf("adoption file is empty")
	}

	// Base64 decode the line
	decoded, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode adoption file: %w", err)
	}

	// Unmarshal JSON into AdoptionConfig
	var config node.AdoptionConfig
	if err := json.Unmarshal(decoded, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal adoption config JSON: %w", err)
	}

	// Validate common required fields
	if config.AccountID == uuid.Nil {
		return nil, fmt.Errorf("account_id is required")
	}
	if config.PlatformURL == "" {
		return nil, fmt.Errorf("platform_url is required")
	}
	if config.GRPCEndpoint == "" {
		return nil, fmt.Errorf("grpc_endpoint is required")
	}

	// Validate mode-specific fields
	// Either: NodeID + UniqueToken (node-specific mode)
	// Or: MasterToken (master token mode)
	hasNodeToken := config.NodeID != uuid.Nil && config.UniqueToken != ""
	hasMasterToken := config.MasterToken != ""

	if !hasNodeToken && !hasMasterToken {
		return nil, fmt.Errorf("either node_id+unique_token or master_token is required")
	}

	if hasNodeToken && hasMasterToken {
		return nil, fmt.Errorf("cannot have both node_id+unique_token and master_token")
	}

	// Log which mode is being used
	if hasMasterToken {
		p.logger.Info("adoption config using master token mode")
	} else {
		p.logger.Info("adoption config using node-specific token mode", "node_id", config.NodeID.String())
	}

	return &config, nil
}

// WriteAdoptionFile replaces the adoption file with cfg, atomically.
//
// This exists for exactly one caller: the identity handoff, where the platform
// tells a master-token-adopted node who it actually is. Until that lands, such
// a node keeps authenticating with the SHARED ENROLMENT TOKEN for the rest of
// its life, so the token's expiry becomes the node's — and a node that cannot
// authenticate cannot be commanded, which makes the failure unrecoverable
// without physical access.
//
// Atomic on purpose, with a one-time backup of whatever was there. This file is
// the node's only way to reach the platform: a half-written one is a device
// that needs someone to walk to it, which is the very outcome this whole change
// exists to prevent. The temp file is created with O_EXCL in the same directory
// (same filesystem, so the rename cannot fail with EXDEV) at 0600, because it
// holds the credential that impersonates this node.
// identityReleased reports whether ReleaseAdoption's marker exists beside the
// adoption file, and what it says.
func (p *Parser) identityReleased(filePath string) (bool, string) {
	content, err := os.ReadFile(ReleasedMarkerPath(filePath))
	if err != nil {
		return false, ""
	}
	return true, strings.TrimSpace(string(content))
}

func (p *Parser) WriteAdoptionFile(filePath string, cfg *node.AdoptionConfig) error {
	payload, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to encode adoption config: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(payload)

	dir := filepath.Dir(filePath)
	// Keep the original once, so a bad handoff is recoverable on the device
	// without re-provisioning it. Never overwritten: the first backup is the
	// last known-good one, and a second write would replace it with whatever
	// this change already produced.
	backup := filePath + ".pre-identity.bak"
	if _, statErr := os.Stat(backup); os.IsNotExist(statErr) {
		if original, readErr := os.ReadFile(filePath); readErr == nil {
			// REDACTED, not verbatim. The file this replaces normally holds a
			// MASTER enrolment token — one credential shared by every device a
			// provisioning card ever touched, which may never expire — and the
			// backup is never cleaned up, so it must not carry it. What the
			// recoverability comment above actually needs is node_id, account_id
			// and the endpoints; the credential is what makes the file worth
			// stealing.
			if writeErr := os.WriteFile(backup, redactAdoptionPayload(original), 0o600); writeErr != nil {
				p.logger.Warn("could not back up the adoption file before rewriting it", "error", writeErr)
			}
		}
	}

	tmp, err := os.CreateTemp(dir, ".node-adoption-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp adoption file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.WriteString(encoded); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to write temp adoption file: %w", err)
	}
	// No explicit Chmod. os.CreateTemp already opens at 0600 on any POSIX
	// filesystem, so it would be redundant — and on the one filesystem that
	// matters most here it is fatal: the default adoption path is
	// /mnt/sdcard/node-adoption.txt, the FAT32 boot partition, where chmod to a
	// mode outside the mount's fmask returns EPERM. Failing on it would make
	// this write fail on exactly the SD/USB-provisioned devices the identity
	// handoff exists for, once per connect, forever. vfat carries no
	// permissions at all, so there is nothing to tighten there anyway.
	// Durability before visibility: a power cut between rename and flush would
	// otherwise leave an empty file where the credential used to be.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("failed to sync temp adoption file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp adoption file: %w", err)
	}
	if err := os.Rename(tmpName, filePath); err != nil {
		return fmt.Errorf("failed to install adoption file: %w", err)
	}
	// A new identity lifts a release. The marker only ever decides what happens
	// when there is NO file, so this is tidiness rather than correctness — but
	// a stale "released" note beside a live identity would mislead whoever
	// reads the directory later.
	if err := os.Remove(ReleasedMarkerPath(filePath)); err != nil && !os.IsNotExist(err) {
		p.logger.Warn("could not remove the stale released marker", "error", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// GetRawAdoptionFileString reads the raw adoption file content (base64 string) without parsing
func (p *Parser) GetRawAdoptionFileString(filePath string) (string, error) {
	// Read the single line from the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read adoption file %s: %w", filePath, err)
	}

	// Trim whitespace and return as-is (base64 string)
	return strings.TrimSpace(string(content)), nil
}

// redactAdoptionPayload strips the credentials from an encoded adoption file,
// keeping the identity and endpoints that make it useful for recovery.
//
// Anything it cannot parse is replaced by a marker rather than passed through:
// a payload we failed to decode is exactly the one whose contents we cannot
// vouch for, and copying it verbatim is how the credential would survive.
func redactAdoptionPayload(encoded []byte) []byte {
	const unreadable = "(unreadable adoption payload; not copied)"
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return []byte(unreadable)
	}
	var cfg node.AdoptionConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return []byte(unreadable)
	}
	cfg.UniqueToken = ""
	cfg.MasterToken = ""
	payload, err := json.Marshal(&cfg)
	if err != nil {
		return []byte(unreadable)
	}
	return []byte(base64.StdEncoding.EncodeToString(payload))
}

// RedactExistingAdoptionBackup rewrites a backup written before the redaction
// above existed. Best-effort and idempotent: a backup that is already redacted
// (or absent, or unparseable) is left alone rather than reported as a failure.
//
// It exists because the fix above only helps devices that have not handed over
// their identity yet — every device already in the field is carrying the
// credential on disk right now, and nothing else would ever remove it.
func (p *Parser) RedactExistingAdoptionBackup(filePath string) {
	backup := filePath + ".pre-identity.bak"
	original, err := os.ReadFile(backup)
	if err != nil {
		return
	}
	redacted := redactAdoptionPayload(original)
	if bytes.Equal(redacted, original) {
		return
	}
	if err := os.WriteFile(backup, redacted, 0o600); err != nil {
		p.logger.Warn("could not redact the stored adoption backup", "path", backup, "error", err)
		return
	}
	p.logger.Info("redacted the credential out of a pre-identity adoption backup", "path", backup)
}

// EnsureAdoptionFilePermissions tightens an adoption file that an older
// install_agent wrote world-readable.
//
// Best-effort and quiet when there is nothing to do: this runs on every agent
// start, and a device whose file is already 0600 must not log about it. The
// check is on the low 077 bits, so a 0640 file (group-readable, which is just as
// wrong on a device with a shared login) is caught too.
func (p *Parser) EnsureAdoptionFilePermissions(filePath string) {
	info, err := os.Stat(filePath)
	if err != nil {
		return
	}
	mode := info.Mode().Perm()
	if mode&0o077 == 0 {
		return
	}
	if err := os.Chmod(filePath, 0o600); err != nil {
		p.logger.Warn("could not tighten the adoption file permissions", "path", filePath, "mode", mode.String(), "error", err)
		return
	}
	p.logger.Info("tightened adoption file permissions", "path", filePath, "was", mode.String(), "now", "-rw-------")
}

// ReleaseAdoption deletes the node's adoption file and the redacted backup
// beside it, returning the device to a clean unadopted state.
//
// Called when the platform deletes the node: without it the device keeps
// retrying forever against a platform that no longer has a row for it — its
// adoption file still names a node_id that does not exist, so ConnectionInit is
// refused, and a network-first device cannot even reach recovery because
// HTTP-boot withholds an unknown serial. Such a device stays powered and on
// the network, invisible to the platform.
//
// An already-absent file is SUCCESS, not an error. The command is dispatched at
// the moment a node is deleted and may be redelivered; "there is no identity
// here" is the state it was asked to produce.
//
// The backup is removed too, and that is the point rather than tidiness: it
// carries node_id, account_id and the endpoints, so a file left behind is a
// device that still knows where it used to belong.
//
// It also leaves a marker (ReleasedMarkerPath) so the next start does not
// take the identity back out of the EEPROM — see ParseAdoptionFile. The
// marker is written BEFORE the files are removed: a crash between the two
// must leave the device released, never half-released with a live fallback.
func (p *Parser) ReleaseAdoption(filePath, reason string) error {
	marker := ReleasedMarkerPath(filePath)
	note := fmt.Sprintf("released_at=%s reason=%q\n", time.Now().UTC().Format(time.RFC3339), reason)
	if err := os.WriteFile(marker, []byte(note), 0o644); err != nil {
		return fmt.Errorf("failed to write the released marker %s: %w", marker, err)
	}
	removed := 0
	for _, path := range []string{filePath, filePath + ".pre-identity.bak"} {
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
		removed++
	}
	if removed == 0 {
		p.logger.Info("adoption identity already released, nothing to remove", "path", filePath, "reason", reason)
		return nil
	}
	// Logged deliberately loudly: someone reading this device later needs to be
	// able to tell a deliberate release from a corrupted or missing file.
	p.logger.Info("released this node's adoption identity — the device is now unadopted",
		"path", filePath, "files_removed", removed, "reason", reason)
	return nil
}
