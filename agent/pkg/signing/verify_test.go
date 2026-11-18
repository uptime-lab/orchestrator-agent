package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
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
