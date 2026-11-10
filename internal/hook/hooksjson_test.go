package hook

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// The handlers only run for tools that hooks/hooks.json matches. This ties the
// two together, so a tool the guard or wrapper handles cannot go unhooked.
func TestPreToolUseMatchersCoverHandledTools(t *testing.T) {
	raw, err := os.ReadFile("../../plugin/hooks/hooks.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"Bash", "Monitor", "Read", "Write", "Edit", "NotebookEdit", "Grep", "Glob"} {
		matched := false
		for _, m := range cfg.Hooks["PreToolUse"] {
			if regexp.MustCompile("^(?:" + m.Matcher + ")$").MatchString(tool) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("no PreToolUse matcher in hooks.json covers %s", tool)
		}
	}
}

// escalate.go answers PermissionRequest only for Bash; the hook must be registered for it.
func TestPermissionRequestIsRegisteredForBash(t *testing.T) {
	raw, err := os.ReadFile("../../plugin/hooks/hooks.json")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, m := range cfg.Hooks["PermissionRequest"] {
		if regexp.MustCompile("^(?:" + m.Matcher + ")$").MatchString("Bash") {
			return
		}
	}
	t.Error("no PermissionRequest matcher in hooks.json covers Bash")
}
