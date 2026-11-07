package hook

import (
	"strings"
	"testing"
)

const sid = "fbb5d416-ea75-4491-b66f-2432431ff9a2"

func escalationEnv(t *testing.T) Env {
	env := testEnv()
	env.ConfigDir = t.TempDir()
	return env
}

func post(mode string) string {
	return `{"session_id":"` + sid + `","permission_mode":"` + mode + `","tool_response":{"stdout":"` + secret + `"}}`
}

func bash(mode string) string {
	return `{"session_id":"` + sid + `","permission_mode":"` + mode + `","tool_name":"Bash","cwd":"/work","tool_input":{"command":"ls","description":"d"}}`
}

func TestLeakInAutoModeSwitchesToManualOnce(t *testing.T) {
	env := escalationEnv(t)
	if resp := run(t, "pre-tool-use", env, bash("auto")); strings.Contains(resp, `"ask"`) {
		t.Fatal("no leak yet, nothing should be asked:", resp)
	}
	run(t, "post-tool-use", env, post("auto"))
	if !hasLeakFlag(env, sid) {
		t.Fatal("a redaction in auto mode must leave the flag")
	}
	if resp := run(t, "pre-tool-use", env, bash("auto")); !strings.Contains(resp, `"permissionDecision":"ask"`) {
		t.Fatal("next Bash call must be sent to the prompt:", resp)
	}
	resp := run(t, "permission-request", env, bash("auto"))
	for _, want := range []string{`"behavior":"allow"`, `"mode":"manual"`, "did not run"} {
		if !strings.Contains(resp, want) {
			t.Fatalf("missing %s in %s", want, resp)
		}
	}
	if strings.Contains(resp, `"command":"ls"`) {
		t.Fatal("the real command must not be approved:", resp)
	}
	if hasLeakFlag(env, sid) {
		t.Fatal("the flag must be removed once the session is switched")
	}
	if resp := run(t, "permission-request", env, bash("auto")); resp != "" {
		t.Fatal("back to normal operation:", resp)
	}
}

func TestEscalationStaysOutOfTheWay(t *testing.T) {
	env := escalationEnv(t)
	run(t, "post-tool-use", env, post("default"))
	if hasLeakFlag(env, sid) {
		t.Fatal("a leak outside auto mode needs no flag")
	}
	run(t, "post-tool-use", env, post("auto"))
	// The user took over before the next call: the flag is dropped, nothing is asked.
	if resp := run(t, "pre-tool-use", env, bash("default")); strings.Contains(resp, `"ask"`) || hasLeakFlag(env, sid) {
		t.Fatal(resp)
	}
	// Other permission requests are not ours to answer.
	run(t, "post-tool-use", env, post("auto"))
	if resp := run(t, "permission-request", env, strings.Replace(bash("auto"), `"Bash"`, `"Write"`, 1)); resp != "" {
		t.Fatal(resp)
	}
	// A session id that is not a plain id never reaches the file system.
	if flagPath(env, "../x") != "" || flagPath(Env{}, sid) != "" {
		t.Fatal("unsafe flag path")
	}
}
