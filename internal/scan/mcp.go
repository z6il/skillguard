package scan

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/z6il/skillguard/internal/finding"
	"github.com/z6il/skillguard/internal/rules"
)

// Server is an MCP server entry in any agent's config format.
type Server struct {
	Name    string
	Command string
	Args    []string
	Env     map[string]string
	URL     string
	Headers map[string]string
}

// ServersFromJSON finds MCP servers in a JSON config.
// It understands {"mcpServers": {...}} and, for files named mcp.json, a bare map of servers.
func ServersFromJSON(file string, data []byte) []Server {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	if m, ok := doc["mcpServers"].(map[string]any); ok {
		return serversFrom(m)
	}
	base := strings.ToLower(filepath.Base(file))
	if base == ".mcp.json" || base == "mcp.json" {
		return serversFrom(doc)
	}
	return nil
}

func serversFrom(m map[string]any) []Server {
	var out []Server
	for name, v := range m {
		e, ok := v.(map[string]any)
		if !ok {
			continue
		}
		s := Server{Name: name, Env: map[string]string{}, Headers: map[string]string{}}
		s.Command, _ = e["command"].(string)
		for _, k := range []string{"url", "httpUrl", "serverUrl"} {
			if u, ok := e[k].(string); ok && u != "" {
				s.URL = u
				break
			}
		}
		if s.Command == "" && s.URL == "" {
			continue
		}
		if args, ok := e["args"].([]any); ok {
			for _, a := range args {
				s.Args = append(s.Args, fmt.Sprint(a))
			}
		}
		copyStrings(e["env"], s.Env)
		copyStrings(e["headers"], s.Headers)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func copyStrings(v any, into map[string]string) {
	if m, ok := v.(map[string]any); ok {
		for k, x := range m {
			into[k] = fmt.Sprint(x)
		}
	}
}

var (
	exactVersion = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)
	secretKey    = regexp.MustCompile(`(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|auth|bearer|credential)|(^|_)(pat|PAT|key|KEY)$`)
	localHost    = regexp.MustCompile(`^https?://(localhost|127\.|0\.0\.0\.0|\[::1\])`)
)

// AnalyzeServers checks MCP servers. content is the raw file, used to find line numbers.
func AnalyzeServers(file, content string, servers []Server) []finding.Finding {
	var out []finding.Finding
	for _, s := range servers {
		line := lineOf(content, `"`+s.Name+`"`)
		if line == 0 {
			line = lineOf(content, s.Name)
		}
		label := s.Name + ": "

		if s.URL != "" {
			if strings.HasPrefix(strings.ToLower(s.URL), "http://") && !localHost.MatchString(s.URL) {
				out = append(out, rules.New(rules.MCPPlainHTTP, file, line, label+s.URL))
			} else if !localHost.MatchString(s.URL) {
				out = append(out, rules.New(rules.MCPRemote, file, line, label+s.URL))
			}
		}

		if s.Command != "" {
			cmd := strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
			if pkg, pinned := packageOf(s.Command, s.Args); pkg != "" && !pinned {
				out = append(out, rules.New(rules.MCPUnpinned, file, line, label+pkg))
			}
			if inlineShell(s.Command, s.Args) {
				out = append(out, rules.New(rules.MCPInlineShell, file, line, label+clip(cmd, 120)))
			}
		}

		for _, kv := range []map[string]string{s.Env, s.Headers} {
			for k, v := range kv {
				if looksLikeSecret(k, v) {
					out = append(out, rules.New(rules.MCPSecret, file, lineOf(content, `"`+k+`"`), label+k+"="+rules.Redact(v)))
				}
			}
		}
	}
	return out
}

func looksLikeSecret(key, val string) bool {
	v := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(val, "Bearer "), "bearer "))
	if len(v) < 16 || strings.ContainsAny(v, "${}%<>") || strings.Contains(v, " ") {
		return false
	}
	if rules.Placeholder(v) {
		return false
	}
	return secretKey.MatchString(key)
}

func commandBase(c string) string {
	b := strings.ToLower(filepath.Base(strings.ReplaceAll(c, `\`, "/")))
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		b = strings.TrimSuffix(b, ext)
	}
	return b
}

// packageOf returns the package a runner command installs and whether its version is pinned.
func packageOf(command string, args []string) (pkg string, pinned bool) {
	base := commandBase(command)
	if inner, rest, ok := unwrapShell(command, args); ok {
		return packageOf(inner, rest)
	}
	switch base {
	case "pnpm", "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			return packageOf("npx", args[1:])
		}
		return "", true
	case "npx", "bunx", "pnpx":
		pkg = firstPositional(args, map[string]bool{"-p": true, "--package": true}, true)
		if pkg == "" || isLocal(pkg) {
			return "", true
		}
		return pkg, npmPinned(pkg)
	case "uvx", "pipx":
		rest := args
		if base == "pipx" {
			if len(args) == 0 || args[0] != "run" {
				return "", true
			}
			rest = args[1:]
		}
		pkg = firstPositional(rest, map[string]bool{"--from": true, "--with": true, "--python": true, "-p": true, "--spec": true}, false)
		if from := flagValue(rest, "--from", "--spec"); from != "" {
			pkg = from
		}
		if pkg == "" || isLocal(pkg) {
			return "", true
		}
		return pkg, pyPinned(pkg)
	case "docker", "podman":
		if len(args) == 0 || args[0] != "run" {
			return "", true
		}
		img := firstPositional(args[1:], map[string]bool{
			"-e": true, "--env": true, "-v": true, "--volume": true, "-p": true, "--publish": true,
			"-w": true, "--workdir": true, "--name": true, "--network": true, "--mount": true,
			"-u": true, "--user": true, "--env-file": true, "--platform": true, "--entrypoint": true,
		}, false)
		if img == "" {
			return "", true
		}
		return img, imagePinned(img)
	}
	return "", true
}

func firstPositional(args []string, takesValue map[string]bool, valueIsPackage bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if takesValue[a] {
			if valueIsPackage && i+1 < len(args) {
				return args[i+1]
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

func flagValue(args []string, names ...string) string {
	for i, a := range args {
		for _, n := range names {
			if a == n && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(a, n+"=") {
				return strings.TrimPrefix(a, n+"=")
			}
		}
	}
	return ""
}

func isLocal(p string) bool {
	return strings.HasPrefix(p, ".") || strings.HasPrefix(p, "/") || strings.Contains(p, "${") ||
		strings.Contains(p, `\`) || (len(p) > 1 && p[1] == ':')
}

func npmPinned(pkg string) bool {
	if strings.HasPrefix(pkg, "github:") || strings.HasPrefix(pkg, "git+") || strings.HasPrefix(pkg, "https://") {
		return strings.Contains(pkg, "#")
	}
	name := pkg
	if strings.HasPrefix(name, "@") {
		name = name[1:]
	}
	i := strings.LastIndex(name, "@")
	if i < 0 {
		return false
	}
	return exactVersion.MatchString(name[i+1:])
}

func pyPinned(spec string) bool {
	if i := strings.Index(spec, "=="); i >= 0 {
		return exactVersion.MatchString(spec[i+2:]) || regexp.MustCompile(`^\d+(\.\d+)*$`).MatchString(spec[i+2:])
	}
	if i := strings.LastIndex(spec, "@"); i > 0 {
		return exactVersion.MatchString(spec[i+1:])
	}
	return false
}

func imagePinned(img string) bool {
	if strings.Contains(img, "@sha256:") {
		return true
	}
	slash := strings.LastIndex(img, "/")
	colon := strings.LastIndex(img, ":")
	if colon <= slash {
		return false
	}
	tag := img[colon+1:]
	return tag != "" && tag != "latest" && tag != "main" && tag != "master"
}

var runners = map[string]bool{
	"npx": true, "bunx": true, "pnpx": true, "pnpm": true, "yarn": true, "uvx": true, "pipx": true,
	"node": true, "bun": true, "deno": true, "python": true, "python3": true, "uv": true, "docker": true, "podman": true,
}

// unwrapShell handles the Windows convention `cmd /c npx ...`: it returns the inner
// command when the shell only launches a single known runner.
func unwrapShell(command string, args []string) (string, []string, bool) {
	if commandBase(command) != "cmd" {
		return "", nil, false
	}
	for i, a := range args {
		if strings.EqualFold(a, "/c") || strings.EqualFold(a, "/k") {
			rest := args[i+1:]
			if len(rest) == 1 {
				rest = strings.Fields(rest[0])
			}
			if len(rest) == 0 || !runners[commandBase(rest[0])] {
				return "", nil, false
			}
			for _, r := range rest {
				if strings.ContainsAny(r, "&|><^") {
					return "", nil, false
				}
			}
			return rest[0], rest[1:], true
		}
	}
	return "", nil, false
}

func inlineShell(command string, args []string) bool {
	if _, _, ok := unwrapShell(command, args); ok {
		return false
	}
	switch commandBase(command) {
	case "sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh":
	default:
		return false
	}
	for _, a := range args {
		switch strings.ToLower(a) {
		case "-c", "/c", "-command", "/k":
			return true
		}
	}
	return false
}

// lineOf returns the 1-based line of the first occurrence of needle, or 0.
func lineOf(content, needle string) int {
	i := strings.Index(content, needle)
	if i < 0 {
		return 0
	}
	return strings.Count(content[:i], "\n") + 1
}
