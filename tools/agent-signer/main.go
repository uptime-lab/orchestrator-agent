// agent-signer signs (and verifies) orchestrator agent artifacts with a YubiKey
// PIV key (slot 9c, ECDSA P-384). The private key never leaves the token. The
// detached signature is ASN.1-DER ECDSA over SHA-384, so it is verifiable by both
// `openssl dgst -sha384 -verify <pub.pem> -signature <sig> <file>` (install.sh /
// managed-OS path) and Go crypto/ecdsa (the agent's own verify path).
//
//	agent-signer sign   -serial 12345678 -in orchestrator-agent.deb
//	agent-signer verify -pub key.pem -in orchestrator-agent.deb -sig orchestrator-agent.deb.sig
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "sign":
		signCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  agent-signer sign   -serial N -in FILE [-out FILE.sig]")
	fmt.Fprintln(os.Stderr, "  agent-signer verify -pub KEY.pem -in FILE -sig FILE.sig")
	os.Exit(2)
}

func signCmd(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	serial := fs.Uint("serial", 0, "YubiKey serial to sign with")
	in := fs.String("in", "", "file to sign")
	out := fs.String("out", "", "detached signature output (default: <in>.sig)")
	_ = fs.Parse(args)
	if *serial == 0 || *in == "" {
		usage()
	}
	sigPath := *out
	if sigPath == "" {
		sigPath = *in + ".sig"
	}

	data, err := os.ReadFile(*in)
	must(err)

	yk := openBySerial(uint32(*serial))
	defer yk.Close()

	cert, err := yk.Certificate(piv.SlotSignature)
	must(err)
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fatal("slot 9c does not hold an ECDSA key")
	}

	fmt.Fprint(os.Stderr, "PIV PIN: ")
	pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	must(err)

	priv, err := yk.PrivateKey(piv.SlotSignature, pub, piv.KeyAuth{PIN: string(pinBytes)})
	must(err)
	signer, ok := priv.(crypto.Signer)
	if !ok {
		fatal("PIV private key is not a crypto.Signer")
	}

	digest := sha512.Sum384(data)
	fmt.Fprintln(os.Stderr, "touch the YubiKey if it is blinking…")
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384)
	must(err)

	must(os.WriteFile(sigPath, sig, 0o644))
	fmt.Fprintf(os.Stderr, "signed %s -> %s (%d bytes, ECDSA-P384 / SHA-384)\n", *in, sigPath, len(sig))
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key PEM")
	in := fs.String("in", "", "file")
	sigPath := fs.String("sig", "", "detached signature")
	_ = fs.Parse(args)
	if *pubPath == "" || *in == "" || *sigPath == "" {
		usage()
	}
	pub := loadPub(*pubPath)
	data, err := os.ReadFile(*in)
	must(err)
	sig, err := os.ReadFile(*sigPath)
	must(err)
	digest := sha512.Sum384(data)
	if ecdsa.VerifyASN1(pub, digest[:], sig) {
		fmt.Println("OK: signature valid")
		return
	}
	fatal("BAD: signature invalid")
}

func openBySerial(serial uint32) *piv.YubiKey {
	cards, err := piv.Cards()
	must(err)
	for _, c := range cards {
		yk, err := piv.Open(c)
		if err != nil {
			continue
		}
		if s, err := yk.Serial(); err == nil && s == serial {
			return yk
		}
		yk.Close()
	}
	fatal(fmt.Sprintf("no YubiKey with serial %d found (plugged in?)", serial))
	return nil
}

func loadPub(path string) *ecdsa.PublicKey {
	b, err := os.ReadFile(path)
	must(err)
	block, _ := pem.Decode(b)
	if block == nil {
		fatal("no PEM block in " + path)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	must(err)
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		fatal("not an ECDSA public key")
	}
	// The scheme is ECDSA P-384 over SHA-384; a key on another curve is not
	// one the agent or the server would accept.
	if pub.Curve != elliptic.P384() {
		fatal("not an ECDSA P-384 public key")
	}
	return pub
}

func must(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "error:", msg)
	os.Exit(1)
}
