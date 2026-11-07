package hook

import "fmt"

// runSessionStart tells the user what is protected. The message goes to
// systemMessage (shown to the user, never to the model) and holds counts only.
func runSessionStart(env Env, _ []byte, _ *[]byte) ([]byte, error) {
	switch {
	case env.Vault == nil && env.Configured:
		return nil, errNoVault
	case env.Vault == nil:
		return encode(output{SystemMessage: "ctxward: no config found, so nothing is protected. Run `ctxward check` for the expected path."}), nil
	}
	msg := fmt.Sprintf("ctxward: protecting %d variables.", env.Stats.Variables)
	if n := env.Stats.ValuesSkipped; n > 0 {
		msg += fmt.Sprintf(" %d have no usable value (unset, or under 8 bytes), so their values cannot be searched for.", n)
	}
	return encode(output{SystemMessage: msg}), nil
}

func failSessionStart(Env, []byte) []byte {
	return encode(output{SystemMessage: "ctxward: WARNING - the config could not be loaded; tool output is being withheld. Run `ctxward check`."})
}
