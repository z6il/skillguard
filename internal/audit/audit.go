// Package audit finds the skills, plugins, hooks and MCP servers installed for each coding agent.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/z6il/skillguard/internal/finding"
	"github.com/z6il/skillguard/internal/scan"
)

// Mode says how a location is read.
type Mode int

const (
	Dir        Mode = iota // scan every file
	File                   // scan one file
	ClaudeJSON             // only the MCP servers in ~/.claude.json (the rest is history)
	CodexTOML              // Codex config.toml with [mcp_servers]
)

// Location is a place an agent loads add-ons or instructions from.
type Location struct {
	Agent string
	What  string
	Path  string
	Mode  Mode
}

// Locations lists every known place for the user's home and the current project.
func Locations(home, cwd, configDir string) []Location {
	h := func(p ...string) string { return filepath.Join(append([]string{home}, p...)...) }
	locs := []Location{
		{"Claude Code", "skills", h(".claude", "skills"), Dir},
		{"Claude Code", "plugins and marketplaces", h(".claude", "plugins"), Dir},
		{"Claude Code", "commands", h(".claude", "commands"), Dir},
		{"Claude Code", "agents", h(".claude", "agents"), Dir},
		{"Claude Code", "settings and hooks", h(".claude", "settings.json"), File},
		{"Claude Code", "local settings and hooks", h(".claude", "settings.local.json"), File},
		{"Claude Code", "global instructions", h(".claude", "CLAUDE.md"), File},
		{"Claude Code", "MCP servers", h(".claude.json"), ClaudeJSON},
		{"Cursor", "MCP servers", h(".cursor", "mcp.json"), File},
		{"Cursor", "rules", h(".cursor", "rules"), Dir},
		{"Codex", "config and MCP servers", h(".codex", "config.toml"), CodexTOML},
		{"Codex", "global instructions", h(".codex", "AGENTS.md"), File},
		{"Codex", "skills", h(".codex", "skills"), Dir},
		{"Codex", "prompts", h(".codex", "prompts"), Dir},
		{"Gemini CLI", "settings and MCP servers", h(".gemini", "settings.json"), File},
		{"Gemini CLI", "global instructions", h(".gemini", "GEMINI.md"), File},
		{"Gemini CLI", "extensions", h(".gemini", "extensions"), Dir},
		{"Windsurf", "MCP servers", h(".codeium", "windsurf", "mcp_config.json"), File},
		{"Shared", "agent skills", h(".agents", "skills"), Dir},
	}
	if configDir != "" {
		locs = append(locs, Location{"Claude Desktop", "MCP servers", filepath.Join(configDir, "Claude", "claude_desktop_config.json"), File})
	}
	if cwd != "" && !samePath(cwd, home) {
		c := func(p ...string) string { return filepath.Join(append([]string{cwd}, p...)...) }
		locs = append(locs,
			Location{"This project", ".claude folder", c(".claude"), Dir},
			Location{"This project", "MCP servers", c(".mcp.json"), File},
			Location{"This project", ".cursor folder", c(".cursor"), Dir},
			Location{"This project", "Cursor rules", c(".cursorrules"), File},
			Location{"This project", "CLAUDE.md", c("CLAUDE.md"), File},
			Location{"This project", "AGENTS.md", c("AGENTS.md"), File},
			Location{"This project", "GEMINI.md", c("GEMINI.md"), File},
		)
	}
	return locs
}

func samePath(a, b string) bool {
	a, _ = filepath.Abs(a)
	b, _ = filepath.Abs(b)
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

// Item is the audit result for one location that exists.
type Item struct {
	Location
	Display string
	Result  *scan.Result
}

// Run scans every location that exists.
func Run(s *scan.Scanner, home string, locs []Location) []Item {
	var out []Item
	for _, l := range locs {
		if _, err := os.Stat(l.Path); err != nil {
			continue
		}
		display := Tilde(l.Path, home)
		var res *scan.Result
		switch l.Mode {
		case ClaudeJSON:
			res = mcpOnly(l.Path, display, ClaudeServers)
		case CodexTOML:
			res = codex(s, l.Path, display)
		default:
			r, err := s.Dir(l.Path, display)
			if err != nil {
				continue
			}
			res = r
		}
		if res == nil {
			continue
		}
		out = append(out, Item{Location: l, Display: display, Result: res})
	}
	return out
}

// Tilde shortens a path under home to ~/...
func Tilde(p, home string) string {
	if home != "" && strings.HasPrefix(strings.ToLower(p), strings.ToLower(home)) {
		return "~" + filepath.ToSlash(p[len(home):])
	}
	return filepath.ToSlash(p)
}

func mcpOnly(path, display string, parse func([]byte) []scan.Server) *scan.Result {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	servers := parse(b)
	res := &scan.Result{Target: display, Files: 1}
	res.Findings = scan.AnalyzeServers(filepath.Base(path), string(b), servers)
	finding.Sort(res.Findings)
	res.Verdict = finding.VerdictOf(res.Findings)
	return res
}

// ClaudeServers reads user-level and per-project MCP servers from ~/.claude.json.
func ClaudeServers(b []byte) []scan.Server {
	var doc struct {
		MCPServers json.RawMessage `json:"mcpServers"`
		Projects   map[string]struct {
			MCPServers json.RawMessage `json:"mcpServers"`
		} `json:"projects"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}
	wrap := func(raw json.RawMessage) []byte {
		return []byte(`{"mcpServers":` + string(raw) + `}`)
	}
	var out []scan.Server
	if len(doc.MCPServers) > 0 {
		out = append(out, scan.ServersFromJSON("", wrap(doc.MCPServers))...)
	}
	keys := make([]string, 0, len(doc.Projects))
	for k := range doc.Projects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if raw := doc.Projects[k].MCPServers; len(raw) > 0 && string(raw) != "{}" {
			out = append(out, scan.ServersFromJSON("", wrap(raw))...)
		}
	}
	return out
}

func codex(s *scan.Scanner, path, display string) *scan.Result {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	res := &scan.Result{Target: display, Files: 1}
	name := filepath.Base(path)
	res.Findings = s.Content(filepath.Dir(path), path, name, b)
	var doc struct {
		MCPServers map[string]any `toml:"mcp_servers"`
	}
	if _, err := toml.Decode(string(b), &doc); err == nil && len(doc.MCPServers) > 0 {
		wrapped, _ := json.Marshal(map[string]any{"mcpServers": doc.MCPServers})
		res.Findings = append(res.Findings, scan.AnalyzeServers(name, string(b), scan.ServersFromJSON("", wrapped))...)
	}
	finding.Sort(res.Findings)
	res.Verdict = finding.VerdictOf(res.Findings)
	return res
}
