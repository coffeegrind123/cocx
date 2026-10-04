// Web Key Directory (WKD) lookup proxy, for the webmail's OpenPGP key discovery.
//
// This file is NEW (added by the cocx OpenPGP patch series), so it cannot conflict on a
// rebase; only a 4-line route hook goes into webmail.go.
//
// WHY THE SERVER HAS TO DO THIS AT ALL
//   Everything else in this feature happens in the browser, deliberately. WKD cannot:
//   it is defined for mail clients, and WKD hosts do not send CORS headers. Measured
//   against a live host — https://openpgpkey.gnupg.org/.well-known/openpgpkey/gnupg.org/
//   hu/nq6t9teux7edsnwdksswydu4o9i5es3f returns 200 with a real 2517-byte key and NO
//   Access-Control-Allow-Origin, so a fetch() from the webmail is blocked by the browser
//   before it ever sees the bytes. (keys.openpgp.org DOES send `*`, which is why the
//   HKPS half of discovery needs no proxy and is not here.)
//
// THIS IS AN SSRF SURFACE AND IS TREATED AS ONE
//   It makes the mail server issue an outbound HTTPS request to a host named by whoever
//   is logged into the webmail. That is exactly the shape of a server-side request
//   forgery primitive, so:
//     * it is behind the webmail session (registered after authentication in handle());
//     * the domain is validated syntactically before anything is dialled;
//     * every connection is checked AT DIAL TIME against private, loopback, link-local
//       and unspecified address ranges — not by pre-resolving the name, which loses to
//       DNS rebinding because the address that gets dialled can differ from the one that
//       was checked;
//     * redirects are refused outright rather than re-validated, because a redirect is
//       a second request to a host nobody validated and WKD has no legitimate need for
//       one;
//     * the response is capped and the timeout is short, so it cannot be used to tie up
//       the server or to read something enormous.
//
//   The bytes are returned unvalidated as an OpenPGP key ON PURPOSE: mox vendors no
//   OpenPGP implementation, and the browser has one. openpgp.js parses it and rejects
//   anything that is not a key, which is the check that matters. What this endpoint
//   guarantees is only that it fetched something small from a public host.

package webmail

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/mjl-/mox/mlog"
)

const (
	wkdTimeout  = 6 * time.Second
	wkdMaxBytes = 256 * 1024
)

var wkdDomainRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// zbase32 encodes with the alphabet WKD uses (RFC 6189 §5.1.6), which is NOT RFC 4648
// base32. Getting this wrong yields a URL that 404s on every domain, which looks
// exactly like "nobody publishes keys" rather than like a bug.
func wkdZbase32(b []byte) string {
	const alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
	var sb strings.Builder
	bits, value := 0, 0
	for _, c := range b {
		value = value<<8 | int(c)
		bits += 8
		for bits >= 5 {
			sb.WriteByte(alphabet[(value>>(bits-5))&0x1f])
			bits -= 5
		}
	}
	if bits > 0 {
		sb.WriteByte(alphabet[(value<<(5-bits))&0x1f])
	}
	return sb.String()
}

// wkdURLs returns the advanced and direct WKD URLs for an address, in the order they
// should be tried. The advanced method (a dedicated openpgpkey. host) is preferred by
// the spec because it lets a domain delegate key hosting without touching its main site.
func wkdURLs(addr string) (advanced, direct string, err error) {
	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return "", "", fmt.Errorf("address has no localpart or domain")
	}
	// Lower-cased ONCE, here, and used for both the hash and the ?l= parameter.
	//
	// The hash is defined over the lower-cased localpart, so an address typed with
	// different capitalisation resolves to the same `hu/` path either way. If ?l= then
	// carried the ORIGINAL case, the two spellings would produce two different URLs for
	// the same key — and since `l` is advisory, some hosts ignore it and some do not, so
	// the failure would be per-domain and intermittent: "WK@gnupg.org finds nothing,
	// wk@gnupg.org works". Localparts are technically case-sensitive per RFC 5321, but
	// WKD has already committed to folding them by hashing the folded form.
	localpart := strings.ToLower(addr[:at])
	domain := strings.ToLower(addr[at+1:])
	if len(domain) > 253 || !wkdDomainRe.MatchString(domain) {
		return "", "", fmt.Errorf("invalid domain")
	}
	if len(localpart) > 64 {
		return "", "", fmt.Errorf("localpart too long")
	}
	sum := sha1.Sum([]byte(localpart))
	h := wkdZbase32(sum[:])
	q := url.QueryEscape(localpart)
	advanced = fmt.Sprintf("https://openpgpkey.%s/.well-known/openpgpkey/%s/hu/%s?l=%s", domain, domain, h, q)
	direct = fmt.Sprintf("https://%s/.well-known/openpgpkey/hu/%s?l=%s", domain, h, q)
	return advanced, direct, nil
}

// wkdBlockedIP reports whether an address must not be dialled. Anything that is not a
// routable public unicast address is refused: those are the addresses that turn an
// outbound fetch into a read of our own infrastructure.
func wkdBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// 100.64.0.0/10 (CGNAT) and 169.254/16 are not covered by IsPrivate.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return true
		}
		if v4[0] == 0 || v4[0] == 127 {
			return true
		}
	}
	return false
}

func wkdClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: wkdTimeout,
		// Checked at dial time, on the address actually being connected to. Resolving
		// the name ourselves and checking that instead would leave a window where the
		// second resolution returns something different (DNS rebinding).
		Control: func(network, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("wkd: bad dial address")
			}
			if wkdBlockedIP(net.ParseIP(host)) {
				return fmt.Errorf("wkd: refusing to connect to non-public address %s", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   wkdTimeout,
		Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("wkd: redirects are not followed")
		},
	}
}

func wkdFetch(ctx context.Context, c *http.Client, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "mox-webmail-wkd")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	buf, err := io.ReadAll(io.LimitReader(resp.Body, wkdMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	if len(buf) > wkdMaxBytes {
		return nil, fmt.Errorf("response too large")
	}
	return buf, nil
}

// wkdHandler serves GET /wkd?addr=user@example.org, returning the raw key bytes.
//
// A miss is 404 with a plain-text reason, not an error page: "this domain publishes no
// key for this address" is the ordinary outcome for most addresses and the UI says so.
func wkdHandler(log mlog.Log, w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "405 - method not allowed - use get", http.StatusMethodNotAllowed)
		return
	}
	addr := r.URL.Query().Get("addr")
	if addr == "" || len(addr) > 320 {
		http.Error(w, "400 - bad request - missing or oversized addr", http.StatusBadRequest)
		return
	}
	advanced, direct, err := wkdURLs(addr)
	if err != nil {
		http.Error(w, "400 - bad request - "+err.Error(), http.StatusBadRequest)
		return
	}

	c := wkdClient()
	var buf []byte
	var lastErr error
	for _, u := range []string{advanced, direct} {
		buf, lastErr = wkdFetch(r.Context(), c, u)
		if lastErr == nil {
			break
		}
		buf = nil
	}
	if buf == nil {
		log.Debugx("wkd lookup found no key", lastErr)
		http.Error(w, "404 - not found - no key published for this address", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	// The body is third-party bytes echoed through our origin. It is never rendered —
	// the browser hands it straight to openpgp.js — but say so anyway, so a mistake
	// downstream cannot turn it into content the browser tries to interpret.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", `attachment; filename="wkd-key.pgp"`)
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write(buf); err != nil {
		log.Debugx("writing wkd key", err)
	}
}
