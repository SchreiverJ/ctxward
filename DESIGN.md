# ctxward — design

ctxward keeps chosen environment variables out of Claude Code's context. You list the **names** of the
variables; ctxward reads their **values** from its own environment into memory on every hook run. Nothing
secret is stored anywhere, and the model never sees either the value or (optionally) the name.

```
config (names only) ──► os.Getenv ──► one Aho-Corasick automaton { values in 3 encodings + names }
                                              │
   tool output (every string and key) ────────┼──► replace every hit with  [REDACTED]
   user prompt ───────────────────────────────┴──► any hit => block the prompt
```

Because the model cannot see a name, a script that reads `os.environ["X"]` shows `os.environ["[REDACTED]"]`.
It learns that a secret is used there, not which variable, so it cannot reference it.

## Config

`<user config dir>/ctxward/vars`: `~/.config/ctxward/vars` on Linux, `~/Library/Application Support/ctxward/vars` on macOS, `%AppData%\ctxward\vars` on Windows (`os.UserConfigDir`). One variable per line, `#` comments:

```
GITHUB_TOKEN                 # default: hide the value only; the name stays visible
STRIPE_SECRET_KEY   value    # same, written out
DATABASE_PASSWORD   both     # hide the value AND the name
```

A `value` variable's name is not searched for, and typing it in a prompt is not blocked. The file holds no
secrets but does hold names, so the hooks deny tools access to its directory, and if it is read anyway the
scrubber turns every `both` name into `[REDACTED]`.

## Matching

Everything is found in one left-to-right pass by an Aho-Corasick automaton (`internal/vault/automaton.go`,
stdlib only). The cost of a scan does not depend on how many variables are configured: about 3 ms per MB at
20 variables (350 MB/s).

Terms per variable: the raw value; URL-encoded forms (`QueryEscape`, `PathEscape`, and a strict form, in
upper- and lowercase hex, that escapes everything but `A-Za-z0-9-_.~`, as `encodeURIComponent` and curl do);
JSON-escaped forms (with and without HTML escaping and `\/`), for tool output that is JSON text; base64 (standard and URL
alphabets) at all three alignments, unpadded, with the edge characters that depend on neighbouring bytes
dropped, so a value embedded in a longer base64 string (Basic auth, Kubernetes secrets) still matches. A
multi-line value is also searched line by line. The hook's own JSON envelope is decoded before scanning. Hex is not searched: it shows up only
when something hex-dumps a secret on purpose. A number in a result that equals a secret becomes `0`.

Names match only as whole identifiers (not next to `[A-Za-z0-9_]`), so hiding `API_KEY` leaves `MY_API_KEY2`
alone. Overlapping matches merge into one placeholder.

**The automaton is rebuilt on every run and never saved.** Build time is 1.2 ms at 5 variables, 5.8 ms at 20
(`go test -bench`), against ~90 ms to start the process. A saved copy would be the secrets in readable form (the
trie can be walked), so it would need encryption, a key, and invalidation when the environment changes.
If a setup ever has hundreds of variables, the fix is a long-lived hook process, not a disk cache.

## Rules that keep names hidden

1. The placeholder is plain `[REDACTED]`, never `[REDACTED:NAME]`.
2. Nothing sent to the model, and no hook message, contains a name or value: the prompt-block reason and
   status messages are fixed text or counts.
3. Config errors carry a line number, never the line.
4. A value shorter than 8 bytes (or unset) is not searched for; its name is still hidden unless it is
   `value`. The count is reported, never the name.
5. Terms that occur inside our own placeholders are dropped, so redacting always settles.

## How the hooks fit together

One tool call, in the order Claude Code runs the hooks. Every box is `ctxward hook <event>`.

```
 you type a prompt
   └─► UserPromptSubmit      value or hidden name in it?  ─► block the prompt
 model asks for a tool call
   └─► PreToolUse            guard: config dir touched, or [REDACTED] being written? ─► deny
         │                   Bash / Monitor: wrap the command so its output can be scrubbed
         │                   Bash only, redaction flag set and mode is auto ─► ask   (see below)
         ▼
       permission check      allow rules, or the auto mode classifier, or your prompt
         │                   an ask lands on your prompt and fires ─► PermissionRequest
         ▼
       the tool runs
   ┌─────┴──────────────┐
   ▼ ok                 ▼ failed
 PostToolUse          PostToolUseFailure
   rewrite every        text cannot be rewritten, so only warn the model
   string and key       (without repeating anything from it)
   ├─ a hit while the mode is auto ─► write the redaction flag
   └─ result goes to the model
 SessionStart (start, resume, clear, compact): tell you what is protected, counts only
```

After a redaction in auto mode (the value was already hidden; this decides who supervises what comes next):

```
 PostToolUse        value hidden, mode is auto ─► flag  <config dir>/flags/<session id>
      │
 next Bash call
      ▼
 PreToolUse         flag set and still auto ─► "ask"     (not the classifier: your permission prompt)
      ▼
 PermissionRequest  flag set and auto ─► allow an `echo` instead of the real command,
      │                                  setMode manual, delete the flag
      ▼
 the model reads "protected content was hidden earlier, so this session is now in manual mode; this command did not run"; you approve whatever it tries next
```

If you leave auto mode yourself before the next call, PreToolUse deletes the flag and asks nothing.

## Coverage

| Surface | Mechanism | Behaviour |
|---|---|---|
| Tool output (all tools) | PostToolUse `updatedToolOutput` | rewrite every string and object key; shape preserved |
| Failing Bash | PreToolUse wrapper | exit code reported as text so the result goes through PostToolUse |
| Monitor streams | PreToolUse wrapper → `ctxward filter` | stdin→stdout scrub, line by line |
| User prompt | UserPromptSubmit | **block** (Claude Code cannot rewrite a prompt); echo suppressed |
| Model writing files | PreToolUse guard | refuse Write/Edit content containing `[REDACTED]` or the withheld marker |
| Auto mode after a redaction | PostToolUse flag → PreToolUse `ask` → PermissionRequest | see below |
| Config directory | PreToolUse guard | deny Read/Grep/Glob/Bash that touch it |

After rewriting, the result is rescanned, and the concatenation of adjacent strings (stdout + stderr, MCP
content blocks) is scanned too, so a secret split across them is caught; either failure withholds the output.

**Leaving auto mode.** If a value or hidden name is redacted (or output is withheld) while the session is in auto mode, PostToolUse leaves an empty flag
file for the session (`<config dir>/flags/<session id>`; tools cannot touch that directory). The next Bash call gets a
PreToolUse `ask`, which goes to the permission prompt instead of the auto mode classifier and fires PermissionRequest.
That hook approves a harmless `echo` in place of the real command and sets the session mode to `manual`, then removes
the flag, so a person decides what runs next and ctxward goes back to normal. PermissionRequest does nothing unless the
flag is set and the mode is `auto`. This is best effort: only Bash is covered (Monitor and other tools get the normal
prompt), and no flag is written when the config directory is unavailable or the redaction happens on a failure path.
A flag left behind by a session that ends first is inert and may be deleted.

**Fail policy.** The launcher script follows it too: if the binary is missing or cannot run and a config file exists, PreToolUse denies and prompts are blocked; with no config it only warns. No config file: nothing happens, and SessionStart says so. Config file exists and anything
fails (unreadable, bad line, malformed hook input, panic): output is withheld, prompts are blocked. Withholding
keeps the result's shape, because Claude Code discards a rewrite that fails the tool's output schema and uses
the raw output.

## Not covered

Verified at the wire level with a capture proxy on `ANTHROPIC_BASE_URL`: `@file` mentions, CLAUDE.md, pasted text, images and PDFs,
MCP results flagged `isError` (rewrite ignored), the raw WebFetch page body, async subagent results, and Bash
output over 30 KB, which Claude Code spills raw to `~/.claude/projects/.../tool-results/`. A name or value in
any of these reaches the model. Also not covered: a model deliberately splitting, reversing or re-encoding
output; and any secret not in the config. This is a filter for accidental exposure, not a security boundary.
Only a proxy on `ANTHROPIC_BASE_URL` could cover everything.

## Layout

```
cmd/ctxward/        main: hook <event> | filter | check
internal/vault/     config, terms (encodings), automaton, Vault.Redact/Contains, Filter
internal/hook/      one file per event, plus escalate.go (leaving auto mode); rewrite.go (JSON rewriter), wrapper.go (Bash/Monitor wrappers)
plugin/             the installed plugin, and nothing else: hooks/hooks.json, .claude-plugin/plugin.json,
                    scripts/ctxward-launch, bin/ctxward, libexec/<os>-<arch>/ctxward, LICENSE
```
