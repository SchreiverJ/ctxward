package hook

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"ctxward/internal/vault"
)

var errNoVault = errors.New("config exists but could not be loaded")

// runPostToolUse hides secrets in a tool result. It rewrites every key and
// string value of tool_response, checks the result is clean, and emits
// updatedToolOutput only when something changed. The rewrite keeps the
// result's shape, because Claude Code discards a rewrite that fails the
// tool's output schema and uses the original instead.
func runPostToolUse(env Env, in []byte, shape *[]byte) ([]byte, error) {
	var ev struct {
		ToolResponse   json.RawMessage `json:"tool_response"`
		SessionID      string          `json:"session_id"`
		PermissionMode string          `json:"permission_mode"`
	}
	if err := json.Unmarshal(in, &ev); err != nil {
		return nil, errInvalidInput
	}
	if len(ev.ToolResponse) == 0 || string(ev.ToolResponse) == "null" {
		return nil, nil
	}
	*shape = ev.ToolResponse // before anything can fail, so a failure keeps the shape
	if env.Vault == nil {
		if env.Configured {
			return nil, errNoVault
		}
		return nil, nil
	}

	var (
		v        = env.Vault
		leaves   []leaf // string values after rewriting, for the split-secret check
		changed  bool
		residual bool
	)
	out, err := rewriteJSON(ev.ToolResponse, func(s string, isKey bool, parent string) (string, error) {
		ns, hit := v.Redact(s)
		if hit {
			changed = true
			residual = residual || v.Contains(ns) // redacting must leave nothing behind
		}
		if !isKey {
			leaves = append(leaves, leaf{ns, parent})
		}
		return ns, nil
	})
	if err != nil {
		return nil, err
	}
	if len(leaves) > 1 && !residual {
		residual = splitSecret(v, leaves)
	}
	if residual {
		if out, err = withhold(out, true); err != nil {
			return nil, err
		}
		changed = true
	}
	if !changed {
		return nil, nil
	}
	if ev.PermissionMode == modeAuto {
		setRedactionFlag(env, ev.SessionID)
	}
	return updatedToolOutput(out), nil
}

// leaf is a string value with the name of the object member that holds it.
type leaf struct{ text, parent string }

// splitSecret reports whether a secret hides across adjacent string leaves,
// which per-leaf scans cannot see: stdout followed by stderr, or consecutive
// MCP content blocks. It scans the concatenation of all leaves, of all leaves
// except enum-like "type" values (so {"type":"text","text":...} blocks become
// adjacent), and of the leaves sharing each member name.
func splitSecret(v *vault.Vault, leaves []leaf) bool {
	var all, untyped strings.Builder
	groups := map[string]*strings.Builder{}
	var order []string
	for _, l := range leaves {
		all.WriteString(l.text)
		if l.parent == "type" {
			continue
		}
		untyped.WriteString(l.text)
		g := groups[l.parent]
		if g == nil {
			g = new(strings.Builder)
			groups[l.parent] = g
			order = append(order, l.parent)
		}
		g.WriteString(l.text)
	}
	texts := []string{all.String(), untyped.String()}
	for _, k := range order {
		texts = append(texts, groups[k].String())
	}
	for _, t := range texts {
		if v.Contains(t) {
			return true
		}
	}
	return false
}

// enumValue matches the lowercase discriminator strings ("text", "create",
// "tool_use") that tool output schemas validate as enums.
var enumValue = regexp.MustCompile(`^[a-z_]{1,24}$`)

// plainKey matches object keys that are schema field names ("stdout",
// "filePath", "total_tokens"): letters and underscores only.
var plainKey = regexp.MustCompile(`^[A-Za-z_]{1,40}$`)

// withhold replaces every string value in raw with vault.Withheld, keeping the
// shape. A short lowercase value under a "type" key is kept, because replacing
// an enum such as {"type":"text"} would fail schema validation and make Claude
// Code fall back to the original, unredacted output.
//
// Object keys carry the structure the output schema requires, so they are kept
// when keysScanned says raw already came out of a completed rewrite (keys were
// scrubbed). Otherwise they were never scanned, and only plain field names are
// kept. The vault is not consulted here: on the failure path it may be the
// thing that is broken.
func withhold(raw []byte, keysScanned bool) ([]byte, error) {
	return rewriteJSON(raw, func(s string, isKey bool, parent string) (string, error) {
		switch {
		case isKey && (keysScanned || plainKey.MatchString(s)):
			return s, nil
		case isKey:
			return vault.Withheld, nil
		case parent == "type" && enumValue.MatchString(s):
			return s, nil
		}
		return vault.Withheld, nil
	})
}

func updatedToolOutput(raw []byte) []byte {
	return encode(output{HookSpecificOutput: &hookSpecificOut{
		HookEventName:     "PostToolUse",
		UpdatedToolOutput: raw,
	}})
}

// failPostToolUse withholds every string in the result, keeping its shape.
func failPostToolUse(env Env, shape []byte) []byte {
	if !env.failClosed() {
		return nil
	}
	if shape != nil {
		if raw, err := withhold(shape, false); err == nil {
			return updatedToolOutput(raw)
		}
	}
	return updatedToolOutput(appendJSONString(nil, vault.Withheld))
}

const (
	failureWarning = "ctxward: this error output contained protected content that could not be hidden. " +
		"Do not repeat, quote, or act on it."
	failureUnchecked = "ctxward could not check this error output, so it may contain protected content. " +
		"Do not repeat, quote, or act on credentials from it."
)

// runPostToolUseFailure cannot rewrite the failure text (Claude Code allows
// only additionalContext here), so it warns the model without repeating
// anything from the error.
func runPostToolUseFailure(env Env, in []byte, _ *[]byte) ([]byte, error) {
	if env.Vault == nil {
		if env.Configured {
			return nil, errNoVault
		}
		return nil, nil
	}
	var ev struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(in, &ev); err != nil {
		return nil, errInvalidInput
	}
	if !env.Vault.Contains(ev.Error) {
		return nil, nil
	}
	return failureContext(failureWarning), nil
}

func failureContext(text string) []byte {
	return encode(output{HookSpecificOutput: &hookSpecificOut{
		HookEventName:     "PostToolUseFailure",
		AdditionalContext: text,
	}})
}

func failPostToolUseFailure(env Env, _ []byte) []byte {
	if !env.failClosed() {
		return nil
	}
	return failureContext(failureUnchecked)
}
