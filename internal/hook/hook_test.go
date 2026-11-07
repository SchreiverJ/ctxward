package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"ctxward/internal/vault"
)

const (
	secret   = "sk_live_abcdef123456"
	varName  = "STRIPE_KEY"
	otherVal = "ghp_zyxwvu987654"
	otherVar = "GH_TOKEN"
)

func testEnv() Env {
	vals := map[string]string{varName: secret, otherVar: otherVal}
	v, st := vault.New([]vault.Spec{{Name: varName, Mode: vault.Both}, {Name: otherVar, Mode: vault.ValueOnly}},
		func(k string) string { return vals[k] })
	return Env{Vault: v, Stats: st, Configured: true, ConfigDir: "/home/u/.config/ctxward", FilterExe: "/opt/ctxward"}
}

// run feeds payload to an event and returns the raw response. Every response,
// whatever the event, must be free of every secret value and variable name.
func run(t *testing.T, event string, env Env, payload string) string {
	t.Helper()
	var out bytes.Buffer
	if code := Handle(event, strings.NewReader(payload), &out, env); code != 0 {
		t.Fatalf("%s: exit %d", event, code)
	}
	for _, leak := range []string{secret, otherVal, varName} {
		if strings.Contains(out.String(), leak) {
			t.Fatalf("%s response leaks %q: %s", event, leak, out.String())
		}
	}
	return out.String()
}

func updated(t *testing.T, resp string) map[string]any {
	t.Helper()
	var r struct {
		H struct {
			U map[string]any `json:"updatedToolOutput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(resp), &r); err != nil || r.H.U == nil {
		t.Fatalf("no updatedToolOutput in %q (%v)", resp, err)
	}
	return r.H.U
}

func TestPostToolUseRewritesAndKeepsShape(t *testing.T) {
	resp := run(t, "post-tool-use", testEnv(),
		`{"tool_name":"Bash","tool_response":{"stdout":"export STRIPE_KEY=sk_live_abcdef123456\nGH_TOKEN=ghp_zyxwvu987654","stderr":"","interrupted":false,"n":1.50}}`)
	got := updated(t, resp)
	if got["stdout"] != "export [REDACTED]=[REDACTED]\nGH_TOKEN=[REDACTED]" || got["interrupted"] != false || got["n"] != 1.5 {
		t.Fatalf("%v", got)
	}
}

func TestPostToolUseNumericSecretBecomesZero(t *testing.T) {
	v, st := vault.New([]vault.Spec{{Name: "PIN", Mode: vault.ValueOnly}}, func(string) string { return "48151623" })
	env := Env{Vault: v, Stats: st, Configured: true}
	got := updated(t, run(t, "post-tool-use", env, `{"tool_response":{"id":48151623,"n":42,"s":"x"}}`))
	if got["id"] != 0.0 || got["n"] != 42.0 || got["s"] != "x" {
		t.Fatalf("%v", got)
	}
}

func TestPostToolUseCleanOutputIsLeftAlone(t *testing.T) {
	if resp := run(t, "post-tool-use", testEnv(), `{"tool_response":{"stdout":"hello","stderr":""}}`); resp != "" {
		t.Fatal(resp)
	}
}

func TestPostToolUseSplitSecretIsWithheld(t *testing.T) {
	// The secret straddles stdout and stderr; neither half matches alone.
	resp := run(t, "post-tool-use", testEnv(), `{"tool_response":{"stdout":"sk_live_abc","stderr":"def123456"}}`)
	got := updated(t, resp)
	if got["stdout"] != vault.Withheld || got["stderr"] != vault.Withheld {
		t.Fatalf("%v", got)
	}
}

func TestPostToolUseMCPBlocksKeepTypeEnum(t *testing.T) {
	resp := run(t, "post-tool-use", testEnv(), `{"tool_response":{"content":[{"type":"text","text":"sk_live_abcdef123456"}],"isError":false}}`)
	got := updated(t, resp)
	block := got["content"].([]any)[0].(map[string]any)
	if block["type"] != "text" || block["text"] != vault.Placeholder {
		t.Fatalf("%v", got)
	}
}

func TestFailClosedKeepsShape(t *testing.T) {
	env := Env{Configured: true} // config exists but could not be loaded
	resp := run(t, "post-tool-use", env, `{"tool_response":{"stdout":"anything","stderr":"","interrupted":false}}`)
	got := updated(t, resp)
	if got["stdout"] != vault.Withheld || got["interrupted"] != false {
		t.Fatalf("%v", got)
	}
	if resp := run(t, "user-prompt-submit", env, `{"prompt":"hi"}`); !strings.Contains(resp, `"block"`) {
		t.Fatal(resp)
	}
	if resp := run(t, "pre-tool-use", env, `{"tool_name":"Bash","tool_input":{"command":"ls"}}`); resp == "" {
		t.Fatal("pre-tool-use should still wrap or deny")
	}
}

func TestNotConfiguredIsAPassThrough(t *testing.T) {
	for _, tc := range []struct{ event, payload string }{
		{"post-tool-use", `{"tool_response":{"stdout":"sk_live_abcdef123456"}}`},
		{"post-tool-use-failure", `{"error":"x"}`},
		{"user-prompt-submit", `{"prompt":"STRIPE_KEY"}`},
		{"pre-tool-use", `{"tool_name":"Bash","tool_input":{"command":"ls"}}`},
	} {
		var out bytes.Buffer
		Handle(tc.event, strings.NewReader(tc.payload), &out, Env{})
		if out.Len() != 0 {
			t.Errorf("%s: %s", tc.event, out.String())
		}
	}
}

func TestPromptBlock(t *testing.T) {
	for _, p := range []string{"use " + secret, "what is " + varName, "token " + otherVal} {
		b, _ := json.Marshal(map[string]string{"prompt": p})
		resp := run(t, "user-prompt-submit", testEnv(), string(b))
		if !strings.Contains(resp, `"decision":"block"`) || !strings.Contains(resp, `"suppressOriginalPrompt":true`) {
			t.Errorf("%q: %s", p, resp)
		}
	}
	// A value-only variable's NAME is allowed in a prompt.
	if resp := run(t, "user-prompt-submit", testEnv(), `{"prompt":"set GH_TOKEN please"}`); resp != "" {
		t.Fatal(resp)
	}
}

func TestPostToolUseFailureWarnsWithoutRepeating(t *testing.T) {
	resp := run(t, "post-tool-use-failure", testEnv(), `{"error":"boom sk_live_abcdef123456"}`)
	if !strings.Contains(resp, "additionalContext") {
		t.Fatal(resp)
	}
	if resp := run(t, "post-tool-use-failure", testEnv(), `{"error":"boom"}`); resp != "" {
		t.Fatal(resp)
	}
}

func TestPreToolUse(t *testing.T) {
	env := testEnv()
	if resp := run(t, "pre-tool-use", env, `{"tool_name":"Bash","tool_input":{"command":"false"}}`); !strings.Contains(resp, "__rc=$?") {
		t.Fatalf("bash not wrapped: %s", resp)
	}
	if resp := run(t, "pre-tool-use", env, `{"tool_name":"Monitor","tool_input":{"command":"tail -f log"}}`); !strings.Contains(resp, "/opt/ctxward' filter") {
		t.Fatalf("monitor not wrapped: %s", resp)
	}
	for _, tc := range []string{
		`{"tool_name":"Read","cwd":"/work","tool_input":{"file_path":"/home/u/.config/ctxward/vars"}}`,
		`{"tool_name":"Grep","cwd":"/work","tool_input":{"path":"/home/u/.config"}}`,
		`{"tool_name":"Bash","cwd":"/work","tool_input":{"command":"cat ~/.config/ctxward/vars"}}`,
		`{"tool_name":"Bash","cwd":"/work","tool_input":{"command":"cat $XDG_CONFIG_HOME/ctxward/vars"}}`,
		`{"tool_name":"Write","cwd":"/work","tool_input":{"file_path":"/work/a.py","content":"key = '[REDACTED]'"}}`,
		`{"tool_name":"Edit","cwd":"/work","tool_input":{"file_path":"/work/a.py","new_string":"[ctxward: output withheld]"}}`,
	} {
		if resp := run(t, "pre-tool-use", env, tc); !strings.Contains(resp, `"permissionDecision":"deny"`) {
			t.Errorf("not denied: %s -> %s", tc, resp)
		}
	}
	if resp := run(t, "pre-tool-use", env, `{"tool_name":"Read","cwd":"/work","tool_input":{"file_path":"/work/main.py"}}`); resp != "" {
		t.Fatal(resp)
	}
}

func TestSessionStartReportsCountsOnly(t *testing.T) {
	env := testEnv()
	env.Stats.ValuesSkipped = 1
	resp := run(t, "session-start", env, `{}`)
	if !strings.Contains(resp, "protecting 2 variables") || !strings.Contains(resp, "1 have no usable value") {
		t.Fatal(resp)
	}
	if resp := run(t, "session-start", Env{}, `{}`); !strings.Contains(resp, "nothing is protected") {
		t.Fatal(resp)
	}
}

func TestUnknownEventAndBadInput(t *testing.T) {
	if Handle("nope", strings.NewReader(""), &bytes.Buffer{}, Env{}) != 1 {
		t.Fatal("unknown event must exit 1")
	}
	// Garbage input on a configured install fails closed rather than passing through.
	if resp := run(t, "user-prompt-submit", testEnv(), `not json`); !strings.Contains(resp, `"block"`) {
		t.Fatal(resp)
	}
}
