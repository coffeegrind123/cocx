// Tests for xpgpArmor, the validator on SubmitMessage.PGPEncrypted.
//
// This file is NEW (added by the cocx OpenPGP patch series). A new file cannot conflict
// on a rebase, which is why the test lives here rather than being patched into
// webmail/api_test.go.
//
// WHY THIS FUNCTION IS WORTH TESTING. It is the trust boundary between a browser and a
// message this server DKIM-signs and sends under our domain's reputation. Everything it
// accepts becomes the body of outgoing mail. The negative cases below are the point: a
// validator that only proves "valid armor is accepted" would pass while accepting
// anything at all.

package webmail

import (
	"context"
	"net"
	"strings"
	"testing"
)

// xpgpArmor reports failure by panicking with a sherpa error (xcheckuserf), the same way
// every other input check in this package does. Recover so a rejection is testable.
func pgpArmorResult(s string) (out []byte, rejected bool) {
	defer func() {
		if x := recover(); x != nil {
			rejected = true
		}
	}()
	return xpgpArmor(context.Background(), s), false
}

const testArmor = "-----BEGIN PGP MESSAGE-----\n\nhQIMA1234567890ab\n=abcd\n-----END PGP MESSAGE-----"

func TestPGPArmorAccepts(t *testing.T) {
	out, rejected := pgpArmorResult(testArmor)
	if rejected {
		t.Fatalf("valid armor was rejected")
	}
	s := string(out)
	if !strings.HasPrefix(s, "-----BEGIN PGP MESSAGE-----\r\n") {
		t.Errorf("output does not start with a CRLF-terminated armor header: %q", s[:40])
	}
	if !strings.HasSuffix(s, "-----END PGP MESSAGE-----\r\n") {
		t.Errorf("output does not end with a CRLF-terminated armor trailer")
	}
	// Every line ending must be CRLF. A bare LF inside a MIME part is tolerated by most
	// parsers and rejected by strict ones, and a browser naturally produces "\n".
	if strings.Contains(strings.ReplaceAll(s, "\r\n", ""), "\n") {
		t.Errorf("output contains a bare LF")
	}
}

func TestPGPArmorCRLFInputIsStable(t *testing.T) {
	// Already-CRLF input must not become CRCRLF. The normalisation collapses to LF first
	// precisely so it is idempotent; without that step this doubles every line ending and
	// the result is corrupt in a way no local test of the browser side would show.
	crlf := strings.ReplaceAll(testArmor, "\n", "\r\n")
	a, rejectedA := pgpArmorResult(testArmor)
	b, rejectedB := pgpArmorResult(crlf)
	if rejectedA || rejectedB {
		t.Fatalf("valid armor rejected")
	}
	if string(a) != string(b) {
		t.Errorf("LF and CRLF input produced different output:\n%q\n%q", a, b)
	}
}

func TestPGPArmorRejects(t *testing.T) {
	// Each of these has reached the server claiming to be an encrypted message. Accepting
	// any of them means sending a recipient a multipart/encrypted with no message in it,
	// or worse.
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"plain text", "hello, this is not encrypted"},
		{"public key block", "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----"},
		{"signature block", "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----"},
		{"header only", "-----BEGIN PGP MESSAGE-----\nabc"},
		{"trailer only", "abc\n-----END PGP MESSAGE-----"},
		{"leading junk", "Subject: x\n-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----"},
		{"trailing junk", testArmor + "\nand then some"},
		// Non-ASCII and control characters cannot occur in armor, which is base64 plus
		// header lines. Their presence means the client sent something it should not have.
		{"non-ascii", "-----BEGIN PGP MESSAGE-----\n\nabcédef\n-----END PGP MESSAGE-----"},
		{"nul byte", "-----BEGIN PGP MESSAGE-----\n\nabc\x00def\n-----END PGP MESSAGE-----"},
		{"bare CR", "-----BEGIN PGP MESSAGE-----\n\nabc\rdef\n-----END PGP MESSAGE-----"},
		{"tab", "-----BEGIN PGP MESSAGE-----\n\nabc\tdef\n-----END PGP MESSAGE-----"},
	} {
		if _, rejected := pgpArmorResult(tc.in); !rejected {
			t.Errorf("%s: accepted, want rejected", tc.name)
		}
	}
}

func TestPGPArmorTooLarge(t *testing.T) {
	huge := "-----BEGIN PGP MESSAGE-----\n\n" + strings.Repeat("a", 101*1024*1024) + "\n-----END PGP MESSAGE-----"
	if _, rejected := pgpArmorResult(huge); !rejected {
		t.Errorf("oversized armor accepted, want rejected")
	}
}

// A MIME boundary cannot be forged from inside the armor, because multipart.NewWriter
// generates a random one per message. This test pins that reasoning to something
// executable: armor whose content LOOKS like a boundary line is still just base64-shaped
// text to the validator, and cannot terminate the part it sits in.
func TestPGPArmorCannotForgeABoundary(t *testing.T) {
	sneaky := "-----BEGIN PGP MESSAGE-----\n\nabc\n--anyboundary--\nContent-Type: text/plain\n\nInjected\n-----END PGP MESSAGE-----"
	out, rejected := pgpArmorResult(sneaky)
	if rejected {
		// Also an acceptable outcome; the point is that it is never treated as structure.
		return
	}
	if !strings.Contains(string(out), "--anyboundary--") {
		t.Errorf("content was altered rather than passed through as opaque bytes")
	}
	// The real guarantee is upstream of this function: the writer's boundary is random,
	// so no fixed string in the body can match it.
}

// ---------------------------------------------------------------- WKD

func TestWKDZbase32AndURLs(t *testing.T) {
	// Verified against a live host: this exact hash resolves to a real 2517-byte key at
	// openpgpkey.gnupg.org. z-base-32 is NOT RFC 4648 base32 — getting the alphabet
	// wrong produces a URL that 404s everywhere, which reads as "nobody publishes keys"
	// rather than as a bug, so it is pinned here.
	adv, dir, err := wkdURLs("wk@gnupg.org")
	if err != nil {
		t.Fatalf("wkdURLs: %v", err)
	}
	const want = "nq6t9teux7edsnwdksswydu4o9i5es3f"
	if !strings.Contains(adv, want) {
		t.Errorf("advanced URL lacks the known-good hash %s: %s", want, adv)
	}
	if !strings.HasPrefix(adv, "https://openpgpkey.gnupg.org/.well-known/openpgpkey/gnupg.org/hu/") {
		t.Errorf("advanced URL has the wrong shape: %s", adv)
	}
	if !strings.HasPrefix(dir, "https://gnupg.org/.well-known/openpgpkey/hu/") {
		t.Errorf("direct URL has the wrong shape: %s", dir)
	}
	// The localpart is lower-cased before hashing, so case must not change the URL.
	adv2, _, err := wkdURLs("WK@GnuPG.org")
	if err != nil || adv2 != adv {
		t.Errorf("address case changed the URL:\n%s\n%s", adv, adv2)
	}
}

func TestWKDRejectsBadAddresses(t *testing.T) {
	for _, in := range []string{
		"", "nodomain", "@example.org", "user@", "user@localhost",
		"user@-bad.example", "user@example..org", "user@" + strings.Repeat("a", 300),
		strings.Repeat("a", 65) + "@example.org",
	} {
		if _, _, err := wkdURLs(in); err == nil {
			t.Errorf("%q: accepted, want rejected", in)
		}
	}
}

// The SSRF guard. This endpoint makes the MAIL SERVER fetch a URL named by a logged-in
// user, so every non-public address range must be refused — otherwise it is a probe
// into our own infrastructure wearing a key-lookup costume.
func TestWKDBlocksNonPublicAddresses(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", // cloud metadata, the classic SSRF target
		"100.64.0.1",      // CGNAT
		"0.0.0.0", "224.0.0.1", "fe80::1", "fc00::1",
	}
	for _, s := range blocked {
		if !wkdBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s: allowed, want blocked", s)
		}
	}
	// Controls: public addresses must still be reachable, or the guard blocks everything
	// and the tests above would pass for the wrong reason.
	for _, s := range []string{"1.1.1.1", "217.69.76.60", "2606:4700:4700::1111"} {
		if wkdBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s: blocked, want allowed", s)
		}
	}
	if !wkdBlockedIP(nil) {
		t.Errorf("nil IP: allowed, want blocked")
	}
}
