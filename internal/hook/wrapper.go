package hook

import (
	"path/filepath"
	"regexp"
	"strings"
)

// wrapperTail runs after the wrapped command. It reports a non-zero status as
// text (the tool result is no longer flagged is_error) and always exits 0, so
// Claude Code delivers the output through PostToolUse, which can be rewritten,
// instead of PostToolUseFailure, which cannot.
const wrapperTail = `__rc=$?; [ $__rc -ne 0 ] && echo "[exit code $__rc]"; true`

// exitToken finds a shell exit or exec word, or errexit being switched on
// (set -e, set -eu, set -o errexit, ...). Any of these would terminate or
// replace the persistent shell that a { } group runs in. The match is token-ish
// and deliberately ignores quoting, so the word inside a string or comment is a
// false positive; the only cost of a false positive is that cd does not persist
// for that command.
var exitToken = regexp.MustCompile(
	`(?:^|[\s;&|(){}` + "`" + `!])(?:` +
		`(?:exit|exec)(?:$|[\s;&|()<>])` + // exit / exec words
		`|set\s+-[A-Za-z]*e[A-Za-z]*(?:$|[\s;&|()])` + // set -e, set -euo pipefail
		`|set\s+(?:-\S+\s+)*-o\s+errexit\b` + // set -o errexit
		`)`)

// heredocStart matches the start of a here-document operator (not <<<).
var heredocStart = regexp.MustCompile(`<<(-?)[ \t]*(?:'([^']*)'|"([^"]*)"|\\?([A-Za-z_][A-Za-z0-9_]*))`)

// WrapBashCommand wraps a Bash tool command so that it always exits 0 and a
// failure is reported as a trailing "[exit code N]" line:
//
//	{
//	<cmd>
//	}
//	__rc=$?; [ $__rc -ne 0 ] && echo "[exit code $__rc]"; true
//
// The { } group runs in the persistent shell, so cd and variables survive. When
// the command contains an exit/exec token or turns on errexit, a ( ) subshell is
// used instead, because those would kill or replace the shell before the tail
// runs; the cost is that cd does not persist for such commands.
//
// The command is returned unwrapped (ok false) when wrapping would change its
// meaning: an empty command, a here-document with no terminating line, or a
// trailing line continuation. Those commands keep Claude Code's default
// failure path, whose output this package cannot rewrite.
func WrapBashCommand(cmd string) (wrapped string, ok bool) {
	if strings.TrimSpace(cmd) == "" || hasUnterminatedHeredoc(cmd) || endsWithContinuation(cmd) {
		return cmd, false
	}
	open, closer := "{", "}"
	if exitToken.MatchString(cmd) {
		open, closer = "(", ")"
	}
	return open + "\n" + cmd + "\n" + closer + "\n" + wrapperTail, true
}

// endsWithContinuation reports whether cmd ends in an odd run of backslashes
// (ignoring trailing spaces and newlines would change bash semantics only for
// the newline itself, which is what the wrapper adds).
func endsWithContinuation(cmd string) bool {
	n := 0
	for i := len(cmd) - 1; i >= 0 && cmd[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// hasUnterminatedHeredoc reports whether some here-document opened in cmd has
// no terminating delimiter line before the end. Bash tolerates that (it ends
// the body at EOF), but appended wrapper lines would become part of the body.
// Operators inside quotes are matched too; that false positive leaves the
// command unwrapped.
func hasUnterminatedHeredoc(cmd string) bool {
	type pending struct {
		delim string
		strip bool
	}
	var open []pending
	for _, line := range strings.Split(cmd, "\n") {
		if len(open) > 0 {
			p := open[0]
			l := strings.TrimSuffix(line, "\r")
			if p.strip {
				l = strings.TrimLeft(l, "\t")
			}
			if l == p.delim {
				open = open[1:]
			}
			continue
		}
		for _, m := range heredocStart.FindAllStringSubmatchIndex(line, -1) {
			if m[0] > 0 && line[m[0]-1] == '<' {
				continue // here-string <<<
			}
			d := ""
			for g := 2; g <= 4; g++ {
				if m[2*g] >= 0 {
					d = line[m[2*g]:m[2*g+1]]
					break
				}
			}
			open = append(open, pending{delim: d, strip: line[m[2]:m[3]] == "-"})
		}
	}
	return len(open) > 0
}

// WrapMonitorCommand pipes a Monitor tool command's output through the ctxward
// scrubber, because Monitor events reach the model as task notifications that
// no hook can rewrite:
//
//	{ <cmd>
//	} 2>&1 | '<exe>' filter
//
// stderr is merged first so it is scrubbed too. exe is single-quoted for the
// shell (embedded quotes, spaces and newlines are safe). It is returned
// unwrapped (ok false) when exe is not usable (empty, relative, or containing
// NUL) or when the command cannot be enclosed in a group without changing its
// meaning (see WrapBashCommand: unterminated here-document, trailing
// backslash, empty command). The Bash wrapper is never applied to Monitor
// commands: the exit-code tail would be filtered output, and Monitor does not
// use the failure path.
func WrapMonitorCommand(cmd, exe string) (wrapped string, ok bool) {
	if !usableFilterExe(exe) || strings.TrimSpace(cmd) == "" || hasUnterminatedHeredoc(cmd) || endsWithContinuation(cmd) {
		return cmd, false
	}
	return "{ " + cmd + "\n} 2>&1 | " + shellQuote(exe) + " filter", true
}

func usableFilterExe(exe string) bool {
	return filepath.IsAbs(exe) && !strings.ContainsRune(exe, 0)
}

// shellQuote single-quotes s for POSIX shells.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
