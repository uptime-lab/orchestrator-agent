package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"testing"
)

// signP384 mimics the YubiKey signer: ASN.1-DER ECDSA over SHA-384.
func signP384(t *testing.T, k *ecdsa.PrivateKey, data []byte) []byte {
	t.Helper()
	d := sha512.Sum384(data)
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sig
}

func TestVerifyWithKeys(t *testing.T) {
	k1, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	k2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	data := []byte("orchestrator-agent.deb contents")
	trust := []*ecdsa.PublicKey{&k1.PublicKey, &k2.PublicKey}

	t.Run("valid signature from a trusted key passes", func(t *testing.T) {
		if err := verifyWithKeys(trust, data, signP384(t, k1, data)); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})
	t.Run("multi-trust: the second key also passes", func(t *testing.T) {
		if err := verifyWithKeys(trust, data, signP384(t, k2, data)); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})
	t.Run("an untrusted key is rejected", func(t *testing.T) {
		if err := verifyWithKeys(trust, data, signP384(t, other, data)); err != ErrUntrusted {
			t.Fatalf("want ErrUntrusted, got %v", err)
		}
	})
	t.Run("a tampered artifact is rejected", func(t *testing.T) {
		sig := signP384(t, k1, data)
		if err := verifyWithKeys(trust, append(data, 'x'), sig); err != ErrUntrusted {
			t.Fatalf("want ErrUntrusted for tampered data, got %v", err)
		}
	})
	t.Run("empty signature is rejected", func(t *testing.T) {
		if err := verifyWithKeys(trust, data, nil); err == nil {
			t.Fatal("want error for empty signature")
		}
	})
}

// A key on another curve must be refused even when the signature under it is
// mathematically valid: the scheme is ECDSA P-384, and accepting any curve
// would let a P-256 key in the trust set sign artifacts.
func TestVerifyRefusesANonP384Key(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("orchestrator-agent.deb contents")
	sig := signP384(t, p256, data) // valid ASN.1 ECDSA over SHA-384, on P-256

	digest := sha512.Sum384(data)
	if !ecdsa.VerifyASN1(&p256.PublicKey, digest[:], sig) {
		t.Fatal("precondition: the P-256 signature must be valid under its own key")
	}
	if err := verifyWithKeys([]*ecdsa.PublicKey{&p256.PublicKey}, data, sig); !errors.Is(err, ErrNotP384) {
		t.Fatalf("P-256 key: want ErrNotP384, got %v", err)
	}
	trust := []*ecdsa.PublicKey{&p384.PublicKey, &p256.PublicKey}
	if err := verifyWithKeys(trust, data, signP384(t, p384, data)); !errors.Is(err, ErrNotP384) {
		t.Fatalf("mixed trust set: want ErrNotP384, got %v", err)
	}
}

// TestEmbeddedTrustedKeys guards the go:embed set: at least one P-384 key must be
// present and parse (a build with no/broken keys must fail closed, not silently
// accept nothing).
func TestEmbeddedTrustedKeys(t *testing.T) {
	keys, err := trustedKeys()
	if err != nil {
		t.Fatalf("trustedKeys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("no embedded trusted keys")
	}
	for i, k := range keys {
		if k.Curve != elliptic.P384() {
			t.Errorf("key %d: want P-384, got %v", i, k.Curve.Params().Name)
		}
	}
}
