package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
)

// MinLen is the shortest value we will search for. Shorter values ("true",
// "dev", "8080") would redact ordinary text.
const MinLen = 8

// valueTerms lists every form of a secret value that we search for: the raw
// value, URL-encoded forms, JSON-escaped forms (for tool output that is JSON
// text, such as `cat config.json`), and base64 (see base64Forms). A value spanning
// several lines (a PEM key) is also searched line by line, because the
// Monitor filter and many tools see one line at a time.
func valueTerms(value string) []string {
	pieces := []string{value}
	if strings.Contains(value, "\n") {
		for _, line := range strings.Split(value, "\n") {
			if line = strings.TrimRight(line, "\r"); len(line) >= MinLen {
				pieces = append(pieces, line)
			}
		}
	}
	var out []string
	for _, p := range pieces {
		out = append(out, p)
		forms := []string{url.QueryEscape(p), url.PathEscape(p), percentStrict(p, upperHex), percentStrict(p, lowerHex)}
		for _, esc := range append(forms, jsonForms(p)...) {
			if esc != p {
				out = append(out, esc)
			}
		}
		out = append(out, base64Forms(p)...)
	}
	return out
}

const (
	upperHex = "0123456789ABCDEF"
	lowerHex = "0123456789abcdef"
)

// jsonForms returns the value as it appears inside a JSON string: with and
// without HTML escaping (\u003c for "<"), and with "/" escaped as "\/".
func jsonForms(s string) []string {
	var forms []string
	for _, escapeHTML := range []bool{false, true} {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(escapeHTML)
		if enc.Encode(s) != nil {
			continue
		}
		inner := strings.TrimSuffix(buf.String(), "\n")
		inner = inner[1 : len(inner)-1]
		forms = append(forms, inner, strings.ReplaceAll(inner, "/", `\/`))
	}
	return forms
}

// percentStrict escapes every byte except the unreserved characters
// (letters, digits, "-_.~"), the way encodeURIComponent and curl do, with the
// given hex digits (tools differ on case). Go's own escapers leave some of
// "@&=+:$" alone, so on their own they would miss it.
func percentStrict(s, hex string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// base64Forms returns the base64 text a value leaves behind when it sits
// inside a longer base64 string (a Basic auth header, a Kubernetes secret).
// What the encoding looks like depends on the value's offset in its 3-byte
// group, so all three offsets are produced, for both alphabets, unpadded.
// Characters whose bits are shared with the unknown neighbouring bytes are
// dropped, leaving only characters that are the same in every context.
func base64Forms(value string) []string {
	var out []string
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		for offset := 0; offset < 3; offset++ {
			s := enc.EncodeToString([]byte(strings.Repeat("\x00", offset) + value))
			head := [3]int{0, 2, 3}[offset] // chars that mix in the unknown leading byte(s)
			tail := 0
			if (offset+len(value))%3 != 0 {
				tail = 1 // last char mixes in the unknown following byte
			}
			if head+tail < len(s) {
				if s = s[head : len(s)-tail]; len(s) >= MinLen {
					out = append(out, s)
				}
			}
		}
	}
	return out
}
