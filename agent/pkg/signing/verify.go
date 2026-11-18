// Package signing verifies orchestrator agent artifacts before they are installed
// as root. The trusted public keys are embedded at build time; a detached
// signature (ASN.1-DER ECDSA over SHA-384) is accepted iff it matches ANY trusted
// key (multi-trust — a backup/rotated YubiKey key just adds another PEM here).
//
// The private keys live only on YubiKeys (PIV slot 9c, non-exportable); signing is
// done off-line with tools/agent-signer. This package NEVER touches a private key.
package signing

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
)

//go:embed keys/*.pem
var keyFS embed.FS

// ErrUntrusted means the signature did not match any embedded trusted key.
var ErrUntrusted = errors.New("agent artifact signature does not match any trusted key")

// trustedKeys parses every embedded trusted public key. An empty or malformed set
// is a build-time mistake and is surfaced as an error (fail-closed).
func trustedKeys() ([]*ecdsa.PublicKey, error) {
	entries, err := keyFS.ReadDir("keys")
	if err != nil {
		return nil, fmt.Errorf("read embedded keys: %w", err)
	}
	var keys []*ecdsa.PublicKey
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := keyFS.ReadFile("keys/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", e.Name(), err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, fmt.Errorf("no PEM block in %s", e.Name())
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", e.Name(), err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key %s is not ECDSA", e.Name())
		}
		keys = append(keys, ec)
	}
	if len(keys) == 0 {
		return nil, errors.New("no trusted signing keys embedded")
	}
	return keys, nil
}

// VerifyDetached returns nil iff sig is a valid ECDSA-P384 / SHA-384 signature of
// data under any embedded trusted key. Any other outcome is a non-nil error — the
// caller MUST refuse to install on error (fail-closed).
func VerifyDetached(data, sig []byte) error {
	keys, err := trustedKeys()
	if err != nil {
		return err
	}
	return verifyWithKeys(keys, data, sig)
}

// verifyWithKeys is the multi-trust core: accept if sig matches ANY key.
func verifyWithKeys(keys []*ecdsa.PublicKey, data, sig []byte) error {
	if len(sig) == 0 {
		return errors.New("empty signature")
	}
	digest := sha512.Sum384(data)
	for _, k := range keys {
		if ecdsa.VerifyASN1(k, digest[:], sig) {
			return nil
		}
	}
	return ErrUntrusted
}
