package hook

import "fmt"

// runSessionStart tells the user what is protected. The message goes to
// systemMessage (shown to the user, never to the model) and holds counts only.
func runSessionStart(env Env, _ []byte, _ *[]byte) ([]byte, error) {
	switch {
	case env.Vault == nil && env.Configured:
		return nil, errNoVault
	case env.Vault == nil:
		return encode(output{SystemMessage: "ctxward: no config found, so nothing is protected. Run " + env.checkCmd() + " for the expected path."}), nil
	}
	msg := fmt.Sprintf("ctxward: protecting %d %s.", env.Stats.Variables, plural(env.Stats.Variables, "variable"))
	if n := env.Stats.ValuesSkipped; n > 0 {
		msg += fmt.Sprintf(" %d have no usable value (unset, or under 8 bytes), so their values cannot be searched for.", n)
	}
	return encode(output{SystemMessage: msg}), nil
}

func failSessionStart(env Env, _ []byte) []byte {
	return encode(output{SystemMessage: "ctxward: WARNING - the config could not be loaded. Tool output is withheld and prompts are blocked until it is fixed. Run " + env.checkCmd() + "."})
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// checkCmd is how the user runs `ctxward check` from Claude Code. The plugin's
// bin/ directory puts `ctxward` on PATH there, and the "!" runs it as a shell command.
func (Env) checkCmd() string { return "`! ctxward check`" }
