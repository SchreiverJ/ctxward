#!/bin/sh
# plugin-test.sh: test ctxward the way Claude Code runs it. POSIX sh; works on Linux and macOS.
#
#   scripts/plugin-test.sh           hooks only: drives plugin/scripts/ctxward-launch with hook JSON (no Claude needed)
#   scripts/plugin-test.sh live      also starts `claude -p --plugin-dir` and checks what the model gets back
#
# Everything uses a throwaway config directory and made-up secrets. Your own config is never read.

root=$(cd "$(dirname "$0")/.." && pwd -P) || exit 1
plugin="$root/plugin"
launch="$plugin/scripts/ctxward-launch"

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT
# Where the binary looks for its config: $XDG_CONFIG_HOME on Linux, but under $HOME on macOS
# (Go's os.UserConfigDir ignores XDG there), so point HOME at the throwaway directory instead.
case $(uname -s) in
  Darwin) export HOME="$work/home"; cfg="$HOME/Library/Application Support" ;;
  *)      cfg="$work/cfg"; export XDG_CONFIG_HOME="$cfg" ;;
esac
mkdir -p "$cfg/ctxward"
printf 'TEST_DB_PASSWORD both\nTEST_API_TOKEN\n' > "$cfg/ctxward/vars"

PW='hunter2-Prod!9xQ'
TOKEN='tok_live_ABCDEF123456'
export TEST_DB_PASSWORD="$PW" TEST_API_TOKEN="$TOKEN"

fail=0
pass() { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fail=$((fail + 1)); }

# hook EVENT JSON: print the hook's stdout.
hook() { printf '%s' "$2" | sh "$launch" hook "$1" 2>/dev/null; }

has()    { case $2 in *"$1"*) return 0 ;; esac; return 1; }
# check LABEL OUTPUT: no secret value and no hidden name may appear.
clean() {
  for s in "$PW" "$TOKEN" TEST_DB_PASSWORD; do
    if has "$s" "$2"; then bad "$1 leaks '$s'"; return; fi
  done
  pass "$1"
}

echo "hooks (via plugin/scripts/ctxward-launch)"

post() { hook post-tool-use "{\"tool_name\":\"Bash\",\"tool_response\":{\"stdout\":\"$1\",\"stderr\":\"\"}}"; }

out=$(post "export TEST_DB_PASSWORD=$PW TEST_API_TOKEN=$TOKEN")
clean "tool output: raw values and the hidden name" "$out"
has "TEST_API_TOKEN=[REDACTED]" "$out" && pass "value-only variable keeps its name" || bad "value-only name should stay visible"

b64=$(printf 'user:%s' "$PW" | base64 | tr -d '\n')
clean "tool output: url-encoded value" "$(post "q=hunter2-Prod%219xQ")"
clean "tool output: base64 value"      "$(post "Authorization: Basic $b64")"
clean "tool output: clean text is untouched" "$(post "nothing secret here")"
[ -z "$(post "nothing secret here")" ] && pass "clean output is not rewritten" || bad "clean output was rewritten"

clean "prompt with a secret is blocked" "$(hook user-prompt-submit "{\"prompt\":\"my password is $PW\"}")"
has '"block"' "$(hook user-prompt-submit "{\"prompt\":\"my password is $PW\"}")" && pass "prompt decision is block" || bad "prompt was not blocked"
[ -z "$(hook user-prompt-submit '{"prompt":"hello"}')" ] && pass "ordinary prompt is allowed" || bad "ordinary prompt was blocked"

out=$(hook pre-tool-use "{\"tool_name\":\"Read\",\"cwd\":\"/tmp\",\"tool_input\":{\"file_path\":\"$cfg/ctxward/vars\"}}")
has '"deny"' "$out" && pass "reading the config is denied" || bad "config read was not denied"

out=$(hook pre-tool-use '{"tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"false"}}')
has 'exit code' "$out" && pass "Bash command is wrapped" || bad "Bash command was not wrapped"
out=$(hook pre-tool-use '{"tool_name":"Monitor","cwd":"/tmp","tool_input":{"command":"tail -f x"}}')
has ' filter' "$out" && pass "Monitor command is piped through the filter" || bad "Monitor command was not filtered"

clean "session start reports counts only" "$(hook session-start '{}')"

echo "fail-closed"
printf 'not a valid line !!\n' > "$cfg/ctxward/vars"
out=$(post "export TEST_DB_PASSWORD=$PW")
clean "broken config: output withheld" "$out"
has 'withheld' "$out" && pass "broken config: withheld marker present" || bad "broken config: output not withheld"
has '"block"' "$(hook user-prompt-submit '{"prompt":"hi"}')" && pass "broken config: prompts blocked" || bad "broken config: prompt not blocked"
rm -f "$cfg/ctxward/vars"
[ -z "$(post "export TEST_DB_PASSWORD=$PW")" ] && pass "no config: nothing happens" || bad "no config: output was changed"

printf 'TEST_DB_PASSWORD both\nTEST_API_TOKEN\n' > "$cfg/ctxward/vars"

echo "leaving auto mode"
sid=test-session-1
flag="$cfg/ctxward/flags/$sid"
hit="{\"session_id\":\"$sid\",\"permission_mode\":\"MODE\",\"tool_response\":{\"stdout\":\"$PW\"}}"
bashcall="{\"session_id\":\"$sid\",\"permission_mode\":\"auto\",\"tool_name\":\"Bash\",\"cwd\":\"/tmp\",\"tool_input\":{\"command\":\"ls\"}}"

hook post-tool-use "${hit%MODE*}default${hit#*MODE}" >/dev/null
[ ! -e "$flag" ] && pass "redaction outside auto mode: no flag" || bad "flag set outside auto mode"
hook pre-tool-use "$bashcall" | grep -q '"ask"' && bad "ask before any redaction" || pass "nothing redacted yet: Bash call is not asked"
hook post-tool-use "${hit%MODE*}auto${hit#*MODE}" >/dev/null
[ -e "$flag" ] && pass "redaction in auto mode: flag set" || bad "flag not set after a redaction in auto mode"
has '"permissionDecision":"ask"' "$(hook pre-tool-use "$bashcall")" && pass "next Bash call goes to the prompt" || bad "next Bash call was not asked"
out=$(hook permission-request "$bashcall")
clean "permission request response" "$out"
has '"mode":"manual"' "$out" && pass "session is switched to manual" || bad "no switch to manual"
has '"command":"ls"' "$out" && bad "the real command was approved" || pass "the real command is not approved"
[ ! -e "$flag" ] && pass "flag removed after the switch" || bad "flag left behind"
[ -z "$(hook permission-request "$bashcall")" ] && pass "back to normal: later requests untouched" || bad "later permission request was answered"

if [ "$1" = live ]; then
  echo "live (claude -p --plugin-dir)"
  if ! command -v claude >/dev/null 2>&1; then
    bad "claude is not on PATH"
  else
    cd "$work" || exit 1
    ask() { claude -p --model haiku --plugin-dir "$plugin" --allowedTools Bash "$1" 2>&1; }
    out=$(ask 'Run `printenv | grep TEST_` and then `python3 -c "import os; print(os.environ[\"TEST_DB_PASSWORD\"])"`. Quote both outputs exactly.')
    clean "model never sees the values or the hidden name" "$out"
    has '[REDACTED]' "$out" && pass "model saw [REDACTED]" || bad "no [REDACTED] in the model's answer (hooks may not have run)"
    out=$(ask "My database password is $PW, please remember it.")
    clean "prompt containing a secret is blocked" "$out"
    has "$PW" "$out" && bad "blocked prompt was echoed back"
  fi
fi

echo
if [ "$fail" -eq 0 ]; then echo "all checks passed"; else echo "$fail check(s) failed"; fi
exit "$fail"
