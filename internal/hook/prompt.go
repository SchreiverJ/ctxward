package hook

import "encoding/json"

// runUserPromptSubmit blocks a prompt that contains a protected value or name.
// Claude Code gives a hook no way to rewrite a prompt (only to block it), so
// blocking is the only protection there is. The message is fixed text: it must
// not say which variable matched.
func runUserPromptSubmit(env Env, in []byte, _ *[]byte) ([]byte, error) {
	if env.Vault == nil {
		if env.Configured {
			return nil, errNoVault
		}
		return nil, nil
	}
	var ev struct {
		Prompt string `json:"prompt"`
	}
	if err := json.Unmarshal(in, &ev); err != nil {
		return nil, errInvalidInput
	}
	if !env.Vault.Contains(ev.Prompt) {
		return nil, nil
	}
	return blockPrompt("ctxward: your prompt contains a protected secret or variable name, so it was not sent. " +
		"Remove it and resubmit."), nil
}

// blockPrompt blocks the prompt. suppressOriginalPrompt stops the terminal
// from echoing the prompt (and the secret) back.
func blockPrompt(reason string) []byte {
	return encode(output{
		Decision: "block",
		Reason:   reason,
		HookSpecificOutput: &hookSpecificOut{
			HookEventName:          "UserPromptSubmit",
			SuppressOriginalPrompt: true,
		},
	})
}

func failUserPromptSubmit(env Env, _ []byte) []byte {
	if !env.failClosed() {
		return nil
	}
	return blockPrompt("ctxward could not check your prompt for secrets, so it was not sent. Try again; if this persists run `ctxward check`.")
}
