package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ctxward/internal/vault"
)

// preToolInput is the tool call a PreToolUse or PermissionRequest event carries.
type preToolInput struct {
	ToolName  string                     `json:"tool_name"`
	ToolInput map[string]json.RawMessage `json:"tool_input"`
	Cwd       string                     `json:"cwd"`

	SessionID      string `json:"session_id"`
	PermissionMode string `json:"permission_mode"`
}

// runPreToolUse applies the guards first (a denial wins), then the Bash and
// Monitor wrappers. The wrappers set no permissionDecision, so the user's
// permission rules keep applying to the ORIGINAL command.
func runPreToolUse(env Env, in []byte, _ *[]byte) ([]byte, error) {
	var ev preToolInput
	if err := json.Unmarshal(in, &ev); err != nil || ev.ToolName == "" {
		return nil, errInvalidInput
	}
	if reason := guard(ev, env.ConfigDir); reason != "" {
		return deny(reason), nil
	}
	if ev.ToolName == "Bash" && redactionPending(env, ev) {
		return askForManual(), nil
	}
	if env.Vault == nil && !env.Configured {
		return nil, nil // nothing to protect: leave commands alone
	}
	var rewrite func(string) (string, bool)
	switch ev.ToolName {
	case "Bash":
		rewrite = WrapBashCommand
	case "Monitor":
		if !usableFilterExe(env.FilterExe) {
			return nil, nil
		}
		rewrite = func(cmd string) (string, bool) { return WrapMonitorCommand(cmd, env.FilterExe) }
	default:
		return nil, nil
	}
	cmd, ok := stringField(ev.ToolInput, "command")
	if !ok {
		return nil, nil
	}
	wrapped, ok := rewrite(cmd)
	if !ok {
		if ev.ToolName == "Monitor" && strings.TrimSpace(cmd) != "" {
			// An unfiltered Monitor stream reaches the model raw; refuse rather than leak.
			return deny(reasonMonitor), nil
		}
		return nil, nil
	}
	updated := make(map[string]json.RawMessage, len(ev.ToolInput))
	for k, v := range ev.ToolInput {
		updated[k] = v
	}
	updated["command"] = appendJSONString(nil, wrapped)
	return encode(output{HookSpecificOutput: &hookSpecificOut{
		HookEventName: "PreToolUse",
		UpdatedInput:  updated,
	}}), nil
}

func deny(reason string) []byte {
	return encode(output{HookSpecificOutput: &hookSpecificOut{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}})
}

func failPreToolUse(env Env, _ []byte) []byte {
	if !env.failClosed() {
		return nil
	}
	return deny("ctxward could not inspect this tool call, so it was blocked. Try again; if it keeps happening, tell the user.")
}

func stringField(m map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := m[key]
	if !ok {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

const (
	reasonConfig      = "ctxward: access to its config directory is blocked."
	reasonMonitor     = "ctxward: this Monitor command cannot be wrapped in the output filter (unterminated here-document or trailing backslash), so it was blocked; rewrite it without those."
	reasonPlaceholder = "ctxward: refusing to write a redaction placeholder into a file. Reference the variable through the environment instead."
)

// guard returns a denial reason for tool calls it refuses: touching the config
// directory, or writing a redaction placeholder into a file (the model saw
// "[REDACTED]" where a name or value was, and would otherwise save that into
// the user's code). It is a speed bump against accidents, not a boundary:
// shell obfuscation defeats it.
func guard(ev preToolInput, configDir string) string {
	switch ev.ToolName {
	case "Read", "Edit", "Write", "NotebookEdit":
		for _, k := range []string{"file_path", "notebook_path"} {
			if p, ok := stringField(ev.ToolInput, k); ok && touchesDir(p, ev.Cwd, configDir, false) {
				return reasonConfig
			}
		}
	case "Grep":
		// A recursive search rooted above the config directory would read it.
		p, _ := stringField(ev.ToolInput, "path")
		if touchesDir(p, ev.Cwd, configDir, true) {
			return reasonConfig
		}
		if g, ok := stringField(ev.ToolInput, "glob"); ok && mentionsDir(g, configDir) {
			return reasonConfig
		}
	case "Glob":
		for _, k := range []string{"path", "pattern"} {
			if p, ok := stringField(ev.ToolInput, k); ok && (touchesDir(p, ev.Cwd, configDir, false) || mentionsDir(p, configDir)) {
				return reasonConfig
			}
		}
	case "Bash", "Monitor":
		if cmd, ok := stringField(ev.ToolInput, "command"); ok && mentionsDir(cmd, configDir) {
			return reasonConfig
		}
	}
	switch ev.ToolName {
	case "Write", "Edit", "NotebookEdit":
		for _, k := range []string{"content", "new_string", "new_source"} {
			if s, ok := stringField(ev.ToolInput, k); ok && hasPlaceholder(s) {
				return reasonPlaceholder
			}
		}
	}
	return ""
}

func hasPlaceholder(s string) bool {
	return strings.Contains(s, vault.Placeholder) || strings.Contains(s, vault.Withheld)
}

// configFile matches the config file name reached through any spelling of the
// directory (relative, variable-expanded, or symlinked path).
var configFile = regexp.MustCompile(`(?i)(?:^|[/\\\s"'=:])ctxward[/\\]+vars(?:$|[^A-Za-z0-9_-])`)

// touchesDir reports whether the path (resolved against cwd, ~, symlinks) is
// the directory or inside it. With ancestor set, a path that contains the
// directory also counts, and an empty path means cwd.
func touchesDir(path, cwd, dir string, ancestor bool) bool {
	if dir == "" {
		return false
	}
	if path == "" {
		if !ancestor {
			return false
		}
		path = cwd
	}
	p := resolvePath(path, cwd)
	d := resolvePath(dir, "")
	if p == "" || d == "" {
		return false
	}
	return within(p, d) || (ancestor && within(d, p))
}

func within(p, dir string) bool {
	if strings.EqualFold(p, dir) {
		return true
	}
	return len(p) > len(dir) && strings.EqualFold(p[:len(dir)], dir) && p[len(dir)] == filepath.Separator
}

// resolvePath expands ~, anchors a relative path at cwd, cleans it, and
// resolves symlinks in the longest existing prefix.
func resolvePath(p, cwd string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	if !filepath.IsAbs(p) {
		if cwd == "" || !filepath.IsAbs(cwd) {
			return ""
		}
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)
	rest := ""
	for cur := p; ; {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(real, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// mentionsDir reports whether free text (a shell command, a glob) names the
// config directory: literally, via ~ / $HOME / $XDG_CONFIG_HOME spellings, or
// as ctxward/vars.
func mentionsDir(text, dir string) bool {
	if dir == "" {
		return false
	}
	t := strings.ToLower(collapseSlashes(text))
	if configFile.MatchString(t) {
		return true
	}
	for _, n := range dirSpellings(dir) {
		if i := strings.Index(t, n); i >= 0 {
			end := i + len(n)
			if end == len(t) || !isNameByte(t[end]) {
				return true
			}
		}
	}
	return false
}

func isNameByte(c byte) bool {
	return c == '_' || c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
}

// collapseSlashes collapses "//" and "/./" so trivially respelled paths match.
func collapseSlashes(s string) string {
	for _, pair := range [][2]string{{"/./", "/"}, {"//", "/"}} {
		for strings.Contains(s, pair[0]) {
			s = strings.ReplaceAll(s, pair[0], pair[1])
		}
	}
	return s
}

func dirSpellings(dir string) []string {
	d := filepath.ToSlash(filepath.Clean(dir))
	out := []string{strings.ToLower(d)}
	add := func(root, prefixes string) {
		if root == "" {
			return
		}
		root = filepath.ToSlash(filepath.Clean(root))
		if rel, ok := strings.CutPrefix(d, root+"/"); ok {
			for _, pre := range strings.Fields(prefixes) {
				out = append(out, strings.ToLower(pre+"/"+rel))
			}
		}
	}
	home, _ := os.UserHomeDir()
	add(home, "~ $HOME ${HOME}")
	add(os.Getenv("XDG_CONFIG_HOME"), "$XDG_CONFIG_HOME ${XDG_CONFIG_HOME}")
	return out
}
