// Package vault holds the secrets that must never reach the model, and finds
// and hides them in text.
//
// It reads the values of the configured environment variables into memory and
// never writes them anywhere. For each variable it searches for the value (in
// a few encodings) and, unless the variable is value-only, for the variable's
// name. Everything is found in a single pass by one Aho-Corasick automaton
// that is rebuilt on every run: building it costs about as much as loading a
// saved copy would, and a saved copy would be the secrets in readable form.
package vault

import (
	"slices"
	"strings"
)

// Placeholder replaces every hidden value and name. It is deliberately
// anonymous: it must not say which variable was hidden.
const Placeholder = "[REDACTED]"

// Withheld replaces output that could not be verified clean.
const Withheld = "[ctxward: output withheld]"

// Stats describes a loaded vault. It holds counts only, so it is safe to show.
type Stats struct {
	Variables     int // lines in the config
	ValuesSkipped int // variables whose value is unset or shorter than MinLen
}

type term struct {
	name bool // a variable name: matches only as a whole identifier
}

// Vault finds and hides the configured secrets. The zero value matches nothing.
type Vault struct {
	ac    *automaton
	terms []term
}

// New builds a Vault for specs, reading values with getenv.
//
// A variable whose value is unset or shorter than MinLen has no value term,
// but its name is still hidden unless it is value-only. Terms that appear in
// our own placeholders are dropped, or redacting would never settle.
func New(specs []Spec, getenv func(string) string) (*Vault, Stats) {
	var (
		texts []string
		terms []term
		seen  = map[string]bool{}
		st    = Stats{Variables: len(specs)}
	)
	add := func(text string, isName bool) {
		key := text
		if isName {
			key = "\x00" + text
		}
		if seen[key] || strings.Contains(Placeholder, text) || strings.Contains(Withheld, text) {
			return
		}
		seen[key] = true
		texts = append(texts, text)
		terms = append(terms, term{name: isName})
	}
	for _, s := range specs {
		if value := getenv(s.Name); len(value) >= MinLen {
			for _, t := range valueTerms(value) {
				add(t, false)
			}
		} else {
			st.ValuesSkipped++
		}
		if s.Mode == Both {
			add(s.Name, true)
		}
	}
	if len(texts) == 0 {
		return &Vault{}, st
	}
	return &Vault{ac: newAutomaton(texts), terms: terms}, st
}

// Contains reports whether text holds any hidden value or name.
func (v *Vault) Contains(text string) bool {
	found := false
	v.find(text, func(int, int) bool { found = true; return false })
	return found
}

// Redact replaces every hidden value and name in text with Placeholder.
// It reports whether anything was replaced.
func (v *Vault) Redact(text string) (string, bool) {
	type span struct{ start, end int }
	var spans []span
	v.find(text, func(start, end int) bool {
		spans = append(spans, span{start, end})
		return true
	})
	if len(spans) == 0 {
		return text, false
	}
	slices.SortFunc(spans, func(a, b span) int { return a.start - b.start })

	var b strings.Builder
	pos := 0
	for i := 0; i < len(spans); {
		start, end := spans[i].start, spans[i].end
		for i++; i < len(spans) && spans[i].start <= end; i++ {
			end = max(end, spans[i].end) // overlapping matches become one
		}
		b.WriteString(text[pos:start])
		b.WriteString(Placeholder)
		pos = end
	}
	b.WriteString(text[pos:])
	return b.String(), true
}

// find reports every real match to found; found returns false to stop.
// A name only counts as a match when it is a whole identifier, so hiding
// API_KEY leaves MY_API_KEY2 alone.
func (v *Vault) find(text string, found func(start, end int) bool) {
	if v.ac == nil {
		return
	}
	v.ac.scan(text, func(start, end, ti int) bool {
		if v.terms[ti].name && (start > 0 && identByte(text[start-1]) || end < len(text) && identByte(text[end])) {
			return true
		}
		return found(start, end)
	})
}

func identByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
