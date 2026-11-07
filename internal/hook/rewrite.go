package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

// maxDepth bounds JSON nesting. The rewriter is iterative (no recursion), so
// this only limits memory for the frame stack.
const maxDepth = 1000

// leafFunc receives every object key (isKey) and string value in document
// order and returns its replacement. For a value, parent is the name of the
// innermost enclosing object member ("" at top level and for keys), which lets
// callers group sibling values such as the "text" of MCP content blocks.
type leafFunc func(s string, isKey bool, parent string) (string, error)

// rewriteJSON re-emits raw with every object key and string value passed
// through fn. Structure and key order are preserved exactly, and so is number text unless fn changes it (then it becomes 0);
// insignificant whitespace is dropped and strings are re-encoded without HTML
// escaping. raw must be exactly one JSON value.
func rewriteJSON(raw []byte, fn leafFunc) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	type frame struct {
		obj bool
		n   int    // tokens seen in this container (keys and values)
		key string // obj: current member key; array: enclosing member key
	}
	var (
		out   = make([]byte, 0, len(raw)+len(raw)/8+16)
		stack []frame
		done  bool
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil || done {
			return nil, errInvalidInput
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			out = append(out, byte(d))
			stack = stack[:len(stack)-1]
			done = len(stack) == 0
			continue
		}
		isKey, parent := false, ""
		if len(stack) > 0 {
			f := &stack[len(stack)-1]
			isKey = f.obj && f.n%2 == 0
			switch {
			case f.obj && !isKey:
				out = append(out, ':')
			case f.n > 0:
				out = append(out, ',')
			}
			f.n++
			parent = f.key
		}
		switch v := tok.(type) {
		case json.Delim:
			if len(stack) >= maxDepth {
				return nil, errInvalidInput
			}
			out = append(out, byte(v))
			fr := frame{obj: v == '{'}
			if !fr.obj {
				fr.key = parent
			}
			stack = append(stack, fr)
			continue
		case string:
			s, err := fn(v, isKey, parent)
			if err != nil {
				return nil, err
			}
			out = appendJSONString(out, s)
			if isKey {
				stack[len(stack)-1].key = v
			}
		case json.Number:
			// A numeric secret (a PIN, an account number) is replaced by 0, which
			// keeps the value a number so the result still fits the tool's schema.
			ns, err := fn(string(v), false, parent)
			if err != nil {
				return nil, err
			}
			if ns != string(v) {
				out = append(out, '0')
			} else {
				out = append(out, v...)
			}
		case bool:
			if v {
				out = append(out, "true"...)
			} else {
				out = append(out, "false"...)
			}
		case nil:
			out = append(out, "null"...)
		}
		done = len(stack) == 0
	}
	if !done {
		return nil, errInvalidInput
	}
	return out, nil
}

const hexDigits = "0123456789abcdef"

// appendJSONString appends s as a JSON string literal without HTML escaping.
// Invalid UTF-8 (which a fragment redaction can produce) becomes U+FFFD so the
// result is always valid JSON.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				dst = append(dst, '\\', c)
			case c == '\n':
				dst = append(dst, '\\', 'n')
			case c == '\r':
				dst = append(dst, '\\', 'r')
			case c == '\t':
				dst = append(dst, '\\', 't')
			case c < 0x20 || c == 0x7f:
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			default:
				dst = append(dst, c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			dst = append(dst, "\xef\xbf\xbd"...)
		case r == 0x2028 || r == 0x2029:
			dst = append(dst, '\\', 'u', '2', '0', '2', hexDigits[r&0xf])
		default:
			dst = append(dst, s[i:i+size]...)
		}
		i += size
	}
	return append(dst, '"')
}
