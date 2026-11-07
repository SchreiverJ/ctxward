// Command ctxward keeps chosen environment variables out of Claude Code's
// context. Claude Code runs it as hooks; a person runs `check`.
//
//	ctxward hook <event>   one Claude Code hook event (JSON on stdin)
//	ctxward filter         scrub stdin to stdout, line by line (Monitor streams)
//	ctxward check          show what the config protects (counts only)
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
		fmt.Fprintln(os.Stderr, "usage: ctxward hook <event> | filter | check")
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
		return check(env)
	}
	fmt.Fprintf(os.Stderr, "ctxward: unknown command %q\n", args[0])
	return 2
}

// configPath is where the list of protected variables lives. It is outside any
// project, and the hooks keep tools away from it.
func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "ctxward", "vars")
}

// loadEnv reads the config and then the variables it names from this
// process's environment. No config file means nothing is protected; a config
// that exists but cannot be used leaves Vault nil with Configured set, which
// the hooks treat as a reason to withhold output.
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

func check(env hook.Env) int {
	fmt.Println("config:", configPath())
	switch {
	case env.Vault != nil:
		fmt.Printf("protecting %d variables; %d have no usable value (unset, or under %d bytes)\n",
			env.Stats.Variables, env.Stats.ValuesSkipped, vault.MinLen)
		return 0
	case env.Configured:
		fmt.Println("problem:", env.ConfigErr)
		fmt.Println("tool output is withheld until the config is fixed")
		return 1
	}
	fmt.Println("no config file: nothing is protected")
	return 1
}
