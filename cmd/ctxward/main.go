// Command ctxward keeps chosen environment variables out of Claude Code's
// context using Claude Code Hooks
//
//	ctxward hook <event>   one Claude Code hook event (JSON on stdin)
//	ctxward filter         scrub stdin to stdout, line by line (Monitor streams)
//	ctxward check          show what the config protects (counts only; --names lists them, outside Claude Code)
//
// The config is <user config dir>/ctxward/vars (see the README; `check` prints it). Nothing printed by
// any command contains a variable name or value.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"ctxward/internal/hook"
	"ctxward/internal/vault"
)

func main() {
	debug.SetTraceback("none") // a crash must not print memory contents
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "ctxward: internal error")
			os.Exit(2)
		}
	}()
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ctxward hook <event> | filter | check [--names]")
		return 2
	}
	env := loadEnv()
	switch args[0] {
	case "hook":
		if len(args) != 2 {
			return 2
		}
		return hook.Handle(args[1], os.Stdin, os.Stdout, env)
	case "filter":
		return filter(env)
	case "check":
		return check(env, args[1:])
	}
	fmt.Fprintf(os.Stderr, "ctxward: unknown command %q\n", args[0])
	return 2
}

// configPath is where the list of protected env variables lives.
func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "ctxward", "vars")
}

// loadEnv reads the config and then the variables it names from this
// process's environment. No config file means nothing is protected;
func loadEnv() hook.Env {
	path := configPath()
	env := hook.Env{}
	if path != "" {
		env.ConfigDir = filepath.Dir(path)
	}
	if exe, err := os.Executable(); err == nil {
		env.FilterExe = exe
	}
	if path == "" {
		return env
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return env
	}
	env.Configured = true
	if err != nil {
		env.ConfigErr = errors.New("cannot open the config file")
		return env
	}
	defer f.Close()
	specs, err := vault.ParseConfig(f)
	if err != nil {
		env.ConfigErr = err
		return env
	}
	env.Vault, env.Stats = vault.New(specs, os.Getenv)
	return env
}

func filter(env hook.Env) int {
	if env.Vault == nil {
		if env.Configured {
			return 1 // fail closed: pass nothing
		}
		env.Vault = &vault.Vault{}
	}
	if err := env.Vault.Filter(os.Stdin, os.Stdout); err != nil {
		return 1
	}
	return 0
}

func check(env hook.Env, args []string) int {
	names := len(args) > 0 && args[0] == "--names"
	if names && os.Getenv("CLAUDECODE") != "" {
		// Output of the shell tool, and of `!` commands, becomes part of the model's context.
		fmt.Fprintf(os.Stderr, "ctxward: --names is not available inside Claude Code, because the output would reach the model.\nIn a normal terminal (with your variables exported), run:\n  %s check --names\n", selfCommand())
		return 2
	}
	fmt.Println("config:", configPath())
	switch {
	case env.Vault != nil:
		var unset, short int
		var rows []vault.VarStatus
		if f, err := os.Open(configPath()); err == nil {
			if specs, err := vault.ParseConfig(f); err == nil {
				rows = vault.Inspect(specs, os.Getenv)
			}
			f.Close()
		}
		for _, r := range rows {
			switch r.State {
			case vault.Unset:
				unset++
			case vault.TooShort:
				short++
			}
		}
		fmt.Printf("protecting %d variables; %d have no usable value (%d unset, %d under %d bytes)\n",
			env.Stats.Variables, env.Stats.ValuesSkipped, unset, short, vault.MinLen)
		if names {
			label := map[vault.VarState]string{vault.Protected: "protected", vault.Unset: "UNSET", vault.TooShort: fmt.Sprintf("UNDER %d BYTES", vault.MinLen)}
			for _, r := range rows {
				mode := "value"
				if r.Mode == vault.Both {
					mode = "both"
				}
				fmt.Printf("  %-32s %-6s %s\n", r.Name, mode, label[r.State])
			}
		} else if env.Stats.ValuesSkipped > 0 {
			fmt.Printf("to see which, run in a normal terminal:\n  %s check --names\n", selfCommand())
		}
		return 0
	case env.Configured:
		fmt.Println("problem:", env.ConfigErr)
		fmt.Println("tool output is withheld and prompts are blocked until the config is fixed")
		return 1
	}
	fmt.Println("no config file: nothing is protected")
	return 1
}

// selfCommand is this binary's full path, quoted for a shell, so it can be pasted
// into a terminal where `ctxward` is not on PATH.
func selfCommand() string {
	exe, err := os.Executable()
	if err != nil {
		return "ctxward"
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
}
