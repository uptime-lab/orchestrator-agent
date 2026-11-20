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
	"crypto/elliptic"
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

// ErrNotP384 means a trusted key is ECDSA on a curve other than P-384. The
// signature scheme is ECDSA P-384 over SHA-384; a key on another curve is a
// misconfigured trust set, and verification refuses rather than accepting a
// signature made under a weaker or unexpected curve.
var ErrNotP384 = errors.New("trusted signing key is not ECDSA P-384")

// requireP384 refuses a key whose curve is not P-384.
func requireP384(k *ecdsa.PublicKey) error {
	if k == nil || k.Curve != elliptic.P384() {
		return ErrNotP384
	}
	return nil
}

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
		if err := requireP384(ec); err != nil {
			return nil, fmt.Errorf("key %s: %w", e.Name(), err)
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

// verifyWithKeys is the multi-trust core: accept if sig matches ANY key. A key
// that is not P-384 refuses the whole verification (fail-closed).
func verifyWithKeys(keys []*ecdsa.PublicKey, data, sig []byte) error {
	if len(sig) == 0 {
		return errors.New("empty signature")
	}
	for _, k := range keys {
		if err := requireP384(k); err != nil {
			return err
		}
	}
	digest := sha512.Sum384(data)
	for _, k := range keys {
		if ecdsa.VerifyASN1(k, digest[:], sig) {
			return nil
		}
	}
	return ErrUntrusted
}
