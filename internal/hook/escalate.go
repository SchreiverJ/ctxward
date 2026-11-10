package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
)

// Leaving auto mode after a redaction.
//
// When a protected value shows up in a tool result while the session is in
// auto mode, PostToolUse leaves a flag file for the session. The next Bash call
// then gets a PreToolUse "ask", which sends it to the permission prompt instead
// of the auto mode classifier, and that fires PermissionRequest. There we
// approve a harmless echo in place of the real command and switch the session
// to manual mode, so a person decides what happens next. The flag is removed
// at that point.
//
// The flags live in the config directory, which tools may not touch, and hold
// nothing: the file name is the session id.

const modeAuto = "auto"

// sessionIDPattern keeps a hostile or odd session id from escaping the flags directory.
var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func flagPath(env Env, session string) string {
	if env.ConfigDir == "" || !sessionIDPattern.MatchString(session) {
		return ""
	}
	return filepath.Join(env.ConfigDir, "flags", session)
}

func setRedactionFlag(env Env, session string) {
	p := flagPath(env, session)
	if p == "" || os.MkdirAll(filepath.Dir(p), 0o700) != nil {
		return
	}
	_ = os.WriteFile(p, nil, 0o600)
}

func hasRedactionFlag(env Env, session string) bool {
	p := flagPath(env, session)
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func clearRedactionFlag(env Env, session string) {
	if p := flagPath(env, session); p != "" {
		_ = os.Remove(p)
	}
}

// redactionPending reports that this call should be sent to the permission prompt.
// If the user has already left auto mode themselves, the flag is stale and
// is removed.
func redactionPending(env Env, ev preToolInput) bool {
	if !hasRedactionFlag(env, ev.SessionID) {
		return false
	}
	if ev.PermissionMode != modeAuto {
		clearRedactionFlag(env, ev.SessionID)
		return false
	}
	return true
}

func askForManual() []byte {
	return encode(output{HookSpecificOutput: &hookSpecificOut{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "ask",
		PermissionDecisionReason: "ctxward: protected content was hidden from earlier output. need to switch to manual mode",
	}})
}

const switchedMessage = "echo 'ctxward: protected content was hidden earlier, so this session is now in manual mode. " +
	"This command did not run; re-issue it if needed.'"

// runPermissionRequest only acts on the ask that askForManual caused. Any other
// permission request, in any mode, is left to the normal prompt.
func runPermissionRequest(env Env, in []byte, _ *[]byte) ([]byte, error) {
	var ev preToolInput
	if err := json.Unmarshal(in, &ev); err != nil {
		return nil, errInvalidInput
	}
	if ev.ToolName != "Bash" || !redactionPending(env, ev) {
		return nil, nil
	}
	// Only the command: nothing else from the original call (background, timeout, sandbox flags) rides along.
	updated := map[string]json.RawMessage{"command": appendJSONString(nil, switchedMessage)}
	out, err := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PermissionRequest",
		"decision": map[string]any{
			"behavior":     "allow",
			"updatedInput": updated,
			"updatedPermissions": []any{
				map[string]any{"type": "setMode", "mode": "manual", "destination": "session"},
			},
		},
	}})
	if err != nil {
		return nil, err
	}
	clearRedactionFlag(env, ev.SessionID)
	return out, nil
}

// failPermissionRequest does nothing: without a decision the normal prompt appears.
func failPermissionRequest(Env, []byte) []byte { return nil }
