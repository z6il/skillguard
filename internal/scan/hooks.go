package scan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/z6il/skillguard/internal/finding"
	"github.com/z6il/skillguard/internal/rules"
)

// Hook is one command an agent runs on an event.
type Hook struct {
	Event   string
	Matcher string
	Command string
}

// HooksFromJSON reads Claude Code style hooks: {"hooks": {"Event": [{"matcher": "...", "hooks": [{"command": "..."}]}]}}.
func HooksFromJSON(data []byte) []Hook {
	var doc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	var out []Hook
	for event, groups := range doc.Hooks {
		for _, g := range groups {
			for _, h := range g.Hooks {
				if h.Command != "" {
					out = append(out, Hook{Event: event, Matcher: g.Matcher, Command: h.Command})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Event < out[j].Event })
	return out
}

var (
	networkCall = regexp.MustCompile(`(?i)\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|requests\.(get|post|put|patch)|urllib\.request|http\.client|urlopen|\bfetch\s*\(|\baxios\b|https?\.request|net\.connect|socket\.(socket|create_connection)|XMLHttpRequest|new\s+WebSocket`)
	scriptRef   = regexp.MustCompile(`\$\{?CLAUDE_PLUGIN_ROOT\}?[/\\]([^"'\s]+)`)
)

// AnalyzeHooks checks hook commands. root is the directory scripts are resolved against.
func AnalyzeHooks(file, content, root string, hooks []Hook) []finding.Finding {
	var out []finding.Finding
	for _, h := range hooks {
		line := lineOf(content, h.Command)
		if line == 0 {
			line = lineOf(content, `"`+h.Event+`"`)
		}
		label := h.Event
		if h.Matcher != "" {
			label += " [" + h.Matcher + "]"
		}
		snip := label + " → " + clip(h.Command, 110)

		switch h.Event {
		case "PreToolUse", "PostToolUse", "PostToolUseFailure":
			if h.Matcher == "" || h.Matcher == "*" || h.Matcher == ".*" {
				out = append(out, rules.New(rules.HookEveryTool, file, line, snip))
			}
		case "UserPromptSubmit":
			out = append(out, rules.New(rules.HookEveryPrompt, file, line, snip))
		case "SessionStart":
			out = append(out, rules.New(rules.HookSession, file, line, snip))
		}

		if networkCall.MatchString(h.Command) {
			out = append(out, rules.New(rules.HookNetwork, file, line, snip))
		} else if script := referencedScript(root, h.Command); script != "" {
			if b, err := os.ReadFile(script); err == nil && networkCall.Match(b) {
				rel, _ := filepath.Rel(root, script)
				out = append(out, rules.New(rules.HookNetwork, file, line, snip+"  (network calls in "+filepath.ToSlash(rel)+")"))
			}
		}
	}
	return out
}

// referencedScript resolves ${CLAUDE_PLUGIN_ROOT}/path in a hook command to a file inside root.
func referencedScript(root, command string) string {
	if root == "" {
		return ""
	}
	m := scriptRef.FindStringSubmatch(command)
	if m == nil {
		return ""
	}
	p := filepath.Join(root, filepath.FromSlash(strings.TrimRight(m[1], `"'`)))
	if rel, err := filepath.Rel(root, p); err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return p
}
