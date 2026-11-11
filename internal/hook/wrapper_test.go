package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const tail = "\n__rc=$?; [ $__rc -ne 0 ] && echo \"[exit code $__rc]\"; true"

func TestWrapBashCommandTable(t *testing.T) {
	tests := []struct {
		name  string
		cmd   string
		open  string // "{" or "(" ; "" = must be left unwrapped
		close string
	}{
		{"simple", "ls -la", "{", "}"},
		{"pipe", "cat f | grep x | wc -l", "{", "}"},
		{"multiline", "cd /tmp\nls\npwd", "{", "}"},
		{"trailing comment", "echo hi # done", "{", "}"},
		{"trailing newline", "echo hi\n", "{", "}"},
		{"heredoc", "cat <<EOF\nhello\nEOF", "{", "}"},
		{"heredoc quoted dash", "cat <<-'EOT'\n\tbody\n\tEOT\necho after", "{", "}"},
		{"two heredocs", "cat <<A <<B\na\nA\nb\nB", "{", "}"},
		{"here-string", "cat <<<hello", "{", "}"},
		{"quotes", `echo "it's" 'a "b"'`, "{", "}"},
		{"background", "sleep 1 &", "{", "}"},
		{"subshell already", "(cd /tmp; ls)", "{", "}"},
		{"exit", "exit 3", "(", ")"},
		{"exit in list", "false || exit 2", "(", ")"},
		{"exit after semicolon", "echo a;exit", "(", ")"},
		{"exec", "exec ls", "(", ")"},
		{"exec redirect only", "exec >/dev/null", "(", ")"},
		{"set -e", "set -e\nfalse\necho no", "(", ")"},
		{"set -euo pipefail", "set -euo pipefail; make", "(", ")"},
		{"set -o errexit", "set -o errexit; make", "(", ")"},
		{"set -x is fine", "set -x; make", "{", "}"},
		{"word contains exit", "echo exitcode; ./exit.sh; git diff --exit-code", "{", "}"},
		{"exit inside string false positive", `echo "please exit now"`, "(", ")"},
		{"empty", "", "", ""},
		{"blank", " \n\t ", "", ""},
		{"unterminated heredoc", "cat <<EOF\nnever ends", "", ""},
		{"line continuation", "echo a \\", "", ""},
		{"escaped backslash end", `echo a \\`, "{", "}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := WrapBashCommand(tt.cmd)
			if tt.open == "" {
				if ok || got != tt.cmd {
					t.Fatalf("want unwrapped, got ok=%v %q", ok, got)
				}
				return
			}
			want := tt.open + "\n" + tt.cmd + "\n" + tt.close + "\n" + strings.TrimPrefix(tail, "\n")
			if !ok || got != want {
				t.Fatalf("got ok=%v\n%q\nwant\n%q", ok, got, want)
			}
		})
	}
}

// TestWrapperBehaviourInBash runs wrapped commands in a real bash.
func TestWrapperBehaviourInBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	tmp := t.TempDir()
	tests := []struct {
		name    string
		cmd     string
		want    string // stdout of the wrapped command, before the trailing pwd
		wantPwd string // "" = original dir, otherwise the cd target persists
	}{
		{"success", "echo hi", "hi\n", ""},
		{"failure", "echo out; false", "out\n[exit code 1]\n", ""},
		{"exit code", "echo a; (exit 7)", "a\n[exit code 7]\n", ""},
		{"exit builtin", "echo a; exit 3; echo b", "a\n[exit code 3]\n", ""},
		{"exec", "exec echo replaced", "replaced\n", ""},
		{"errexit", "set -e; echo a; false; echo b", "a\n[exit code 1]\n", ""},
		{"pipe fail", "echo x | grep y", "[exit code 1]\n", ""},
		{"heredoc", "cat <<EOF\nhello $((1+1))\nEOF", "hello 2\n", ""},
		{"quoted heredoc", "cat <<'EOF'\n$HOME\nEOF", "$HOME\n", ""},
		{"trailing comment fail", "false # trailing", "[exit code 1]\n", ""},
		{"multiline", "echo 1\necho 2\nfalse", "1\n2\n[exit code 1]\n", ""},
		{"quotes", `echo "it's" 'a "b"'`, "it's a \"b\"\n", ""},
		{"cd persists", "cd " + tmp, "", tmp},
		{"cd persists on failure", "cd " + tmp + " && false", "[exit code 1]\n", tmp},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped, ok := WrapBashCommand(tt.cmd)
			if !ok {
				t.Fatal("not wrapped")
			}
			start := t.TempDir()
			// Git Bash reports /tmp/... for $PWD; `pwd -W` gives the Windows path to compare against.
			pwdExpr := `"$PWD"`
			if runtime.GOOS == "windows" {
				pwdExpr = `"$(pwd -W)"`
			}
			cmd := exec.Command(bash, "-c", wrapped+"\necho ::pwd="+pwdExpr)
			cmd.Dir = start
			out, err := cmd.CombinedOutput()
			if _, isExit := err.(*exec.ExitError); err != nil && !isExit {
				t.Fatal(err)
			}
			got, pwd, _ := strings.Cut(string(out), "::pwd=")
			pwd = strings.TrimSpace(pwd)
			if got != tt.want {
				t.Errorf("stdout %q, want %q", got, tt.want)
			}
			wantPwd := tt.wantPwd
			if wantPwd == "" {
				wantPwd = start
			}
			// Compare resolved paths: temp dirs are symlinks on macOS and 8.3 short names on Windows.
			resolve := func(p string) string {
				p = filepath.FromSlash(p)
				if r, err := filepath.EvalSymlinks(p); err == nil {
					return r
				}
				return p
			}
			if resolve(pwd) != resolve(wantPwd) {
				t.Errorf("pwd %q, want %q", pwd, wantPwd)
			}
		})
	}
}

func TestWrapMonitorCommandTable(t *testing.T) {
	const exe = "/opt/safe env/it's/ctxward"
	const q = `'/opt/safe env/it'\''s/ctxward'`
	tests := []struct {
		name string
		cmd  string
		exe  string
		want string // "" = left unwrapped
	}{
		{"simple", "tail -f app.log", exe, "{ tail -f app.log\n} 2>&1 | " + q + " filter"},
		{"multiline", "while true; do\n  date\n  sleep 1\ndone", exe, "{ while true; do\n  date\n  sleep 1\ndone\n} 2>&1 | " + q + " filter"},
		{"heredoc", "cat <<EOF\nhi\nEOF", exe, "{ cat <<EOF\nhi\nEOF\n} 2>&1 | " + q + " filter"},
		{"quotes", `echo "a 'b'" 'c "d"'`, exe, "{ echo \"a 'b'\" 'c \"d\"'\n} 2>&1 | " + q + " filter"},
		{"trailing comment", "tail -f x # note", exe, "{ tail -f x # note\n} 2>&1 | " + q + " filter"},
		{"exit is not special", "exit 3", exe, "{ exit 3\n} 2>&1 | " + q + " filter"},
		{"plain exe", "ls", "/usr/bin/ctxward", "{ ls\n} 2>&1 | '/usr/bin/ctxward' filter"},
		{"newline in exe", "ls", "/a\nb/ctxward", "{ ls\n} 2>&1 | '/a\nb/ctxward' filter"},
		{"empty exe", "ls", "", ""},
		{"relative exe", "ls", "ctxward", ""},
		{"nul exe", "ls", "/a\x00b", ""},
		{"empty cmd", " ", exe, ""},
		{"unterminated heredoc", "cat <<EOF\nx", exe, ""},
		{"continuation", "echo a \\", exe, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := WrapMonitorCommand(tt.cmd, tt.exe)
			if tt.want == "" {
				if ok || got != tt.cmd {
					t.Fatalf("want unwrapped, got ok=%v %q", ok, got)
				}
				return
			}
			if !ok || got != tt.want {
				t.Fatalf("got ok=%v\n%q\nwant\n%q", ok, got, tt.want)
			}
		})
	}
}

// TestWrapMonitorInBash runs wrapped commands against a stand-in filter that
// uppercases stdin, proving stdout and stderr both pass through it and the
// quoting of awkward executable paths holds.
func TestWrapMonitorInBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := filepath.Join(t.TempDir(), "sp ace", "it's")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "ctxward")
	script := "#!/bin/sh\n[ \"$1\" = filter ] || exit 9\ntr a-z A-Z\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"stdout+stderr": "echo out; echo err >&2",
		"heredoc":       "cat <<EOF\nout\nEOF\necho err >&2",
		"multiline":     "for i in 1; do\n echo out\ndone\necho err >&2",
		"comment":       "echo out; echo err >&2 # c",
	}
	for name, cmd := range tests {
		t.Run(name, func(t *testing.T) {
			wrapped, ok := WrapMonitorCommand(cmd, exe)
			if !ok {
				t.Fatal("not wrapped")
			}
			out, err := exec.Command(bash, "-c", wrapped).Output()
			if err != nil {
				t.Fatal(err)
			}
			if got := string(out); got != "OUT\nERR\n" {
				t.Errorf("got %q", got)
			}
		})
	}
}
