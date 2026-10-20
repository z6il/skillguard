// Package target turns a command-line argument into a local directory to scan.
package target

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Target is a resolved scan location.
type Target struct {
	Arg     string // what the user typed
	Label   string // how it is shown in reports and stored in lockfiles
	Path    string // local path to scan
	cleanup func()
}

// Close removes any temporary clone.
func (t *Target) Close() {
	if t.cleanup != nil {
		t.cleanup()
	}
}

var (
	shorthand = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$`)
	treeURL   = regexp.MustCompile(`^(https://(github\.com|gitlab\.com)/[^/]+/[^/]+?)(?:\.git)?/(?:-/)?tree/([^/]+)(?:/(.+))?$`)
)

// Resolve accepts a local path, a git URL, a GitHub tree URL or GitHub owner/repo shorthand.
func Resolve(arg string) (*Target, error) {
	if _, err := os.Stat(arg); err == nil {
		abs, err := filepath.Abs(arg)
		if err != nil {
			return nil, err
		}
		return &Target{Arg: arg, Label: arg, Path: abs}, nil
	}

	repo, ref, sub := "", "", ""
	switch {
	case treeURL.MatchString(arg):
		m := treeURL.FindStringSubmatch(arg)
		repo, ref, sub = m[1], m[3], m[4]
	case isGitURL(arg):
		repo = arg
	case shorthand.MatchString(arg):
		repo = "https://github.com/" + arg
	default:
		return nil, fmt.Errorf("%s: no such file or directory, and not a git URL or owner/repo", arg)
	}

	dir, err := os.MkdirTemp("", "skillguard-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	args := []string{"clone", "--quiet", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, "--", repo, dir)
	cmd := exec.Command("git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return nil, fmt.Errorf("git clone %s: %v: %s", repo, err, strings.TrimSpace(string(out)))
	}
	p := dir
	if sub != "" {
		p = filepath.Join(dir, filepath.FromSlash(sub))
		if rel, err := filepath.Rel(dir, p); err != nil || strings.HasPrefix(rel, "..") {
			cleanup()
			return nil, fmt.Errorf("%s: path escapes the repository", arg)
		}
		if _, err := os.Stat(p); err != nil {
			cleanup()
			return nil, fmt.Errorf("%s: %s not found in the repository", arg, sub)
		}
	}
	return &Target{Arg: arg, Label: arg, Path: p, cleanup: cleanup}, nil
}

func isGitURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") ||
		strings.HasPrefix(s, "git@") || strings.HasPrefix(s, "ssh://") || strings.HasPrefix(s, "git://")
}
