// Package hook implements the Claude Code hook events ctxward uses. Each
// event reads one JSON document from stdin and may print one JSON response.
//
//	post-tool-use          hide secrets in every tool result
//	post-tool-use-failure  warn the model (a failure result cannot be rewritten)
//	pre-tool-use           wrap Bash/Monitor so their output can be hidden;
//	                       keep the model away from the config; refuse to write
//	                       placeholders into files
//	permission-request     after a redaction in auto mode, switch the session to manual
//	user-prompt-submit     block a prompt that contains a secret
//	session-start          tell the user what is protected (counts only)
//
// Nothing in a response that reaches the model may contain a variable name or
// value, so every message here is fixed text.
package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"ctxward/internal/vault"
)

// maxStdin caps hook input. Larger input is a failure, not a pass.
const maxStdin = 32 << 20

var (
	errInvalidInput = errors.New("invalid hook input")
	errOversize     = errors.New("hook input too large")
)

// Env is everything a hook call needs from the outside world.
type Env struct {
	// Vault finds secrets. Nil when there is no usable config.
	Vault *vault.Vault
	Stats vault.Stats
	// ConfigErr says why a config that exists could not be used. It names a
	// line number at most, never a variable.
	ConfigErr error
	// Configured reports that a config file exists. Once it does, any failure
	// fails closed: output is withheld rather than passed through unchecked.
	Configured bool
	// ConfigDir is the directory holding the config (the variable names).
	// Tools may not touch it.
	ConfigDir string
	// FilterExe is this binary's absolute path, used to pipe Monitor commands
	// through `ctxward filter`. Empty disables the Monitor rewrite.
	FilterExe string
}

// handler is one event's behaviour. run returns the stdout payload (nil for
// none); onFailure builds the payload for any failure or panic.
type handler struct {
	run       func(env Env, in []byte, shape *[]byte) ([]byte, error)
	onFailure func(env Env, shape []byte) []byte
}

func lookup(event string) (handler, bool) {
	switch event {
	case "post-tool-use":
		return handler{runPostToolUse, failPostToolUse}, true
	case "post-tool-use-failure":
		return handler{runPostToolUseFailure, failPostToolUseFailure}, true
	case "pre-tool-use":
		return handler{runPreToolUse, failPreToolUse}, true
	case "permission-request":
		return handler{runPermissionRequest, failPermissionRequest}, true
	case "user-prompt-submit":
		return handler{runUserPromptSubmit, failUserPromptSubmit}, true
	case "session-start":
		return handler{runSessionStart, failSessionStart}, true
	}
	return handler{}, false
}

// Handle runs one hook event. It returns the process exit code: 0 for every
// handled event (Claude Code reads the decision from the JSON) and 1 for an
// unknown event name. It never panics and writes nothing but the response.
func Handle(event string, stdin io.Reader, stdout io.Writer, env Env) int {
	h, ok := lookup(event)
	if !ok {
		return 1
	}
	if out := execute(h, stdin, env); len(out) > 0 {
		_, _ = stdout.Write(append(out, '\n'))
	}
	return 0
}

func execute(h handler, stdin io.Reader, env Env) (out []byte) {
	var shape []byte // post-tool-use: the raw tool_response, once parsed, so a failure can keep its shape
	defer func() {
		if recover() != nil {
			out = safely(h, env, shape)
		}
	}()
	in, err := readCapped(stdin)
	if err == nil {
		out, err = h.run(env, in, &shape)
	}
	if err != nil {
		return safely(h, env, shape)
	}
	return out
}

// safely runs the failure path, which must not panic either.
func safely(h handler, env Env, shape []byte) (out []byte) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	return h.onFailure(env, shape)
}

func readCapped(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxStdin+1))
	if err != nil {
		return nil, errInvalidInput
	}
	if len(b) > maxStdin {
		return nil, errOversize
	}
	return b, nil
}

// output is the hook JSON response envelope.
type output struct {
	Decision           string           `json:"decision,omitempty"`
	Reason             string           `json:"reason,omitempty"`
	SystemMessage      string           `json:"systemMessage,omitempty"`
	HookSpecificOutput *hookSpecificOut `json:"hookSpecificOutput,omitempty"`
}

type hookSpecificOut struct {
	HookEventName            string                     `json:"hookEventName"`
	PermissionDecision       string                     `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string                     `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]json.RawMessage `json:"updatedInput,omitempty"`
	UpdatedToolOutput        json.RawMessage            `json:"updatedToolOutput,omitempty"`
	AdditionalContext        string                     `json:"additionalContext,omitempty"`
	SuppressOriginalPrompt   bool                       `json:"suppressOriginalPrompt,omitempty"`
}

// encode marshals o without HTML escaping.
func encode(o output) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(o) != nil {
		return nil
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// failClosed reports whether a failure must block rather than pass through.
func (e Env) failClosed() bool { return e.Configured }
