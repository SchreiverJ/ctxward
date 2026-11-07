package vault

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Mode says what is hidden from the model for one variable.
type Mode int

const (
	// ValueOnly hides the value; the name stays visible. This is the default.
	ValueOnly Mode = iota
	// Both hides the value and the variable's name.
	Both
)

// Spec is one config line: an environment variable and what to hide.
type Spec struct {
	Name string
	Mode Mode
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ParseConfig reads the config file: one "NAME [both|value]" per line, "#"
// starts a comment. Errors carry the line number only, never the line, because
// a name must not reach the model through an error message.
func ParseConfig(r io.Reader) ([]Spec, error) {
	var specs []Spec
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) > 2 || !envName.MatchString(f[0]) {
			return nil, fmt.Errorf("config line %d: expected NAME [both|value]", n)
		}
		spec := Spec{Name: f[0]}
		if len(f) == 2 {
			switch f[1] {
			case "value":
			case "both":
				spec.Mode = Both
			default:
				return nil, fmt.Errorf("config line %d: mode must be both or value", n)
			}
		}
		specs = append(specs, spec)
	}
	return specs, sc.Err()
}
