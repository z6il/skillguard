// Package scan walks a directory and runs every check on the files agents load.
package scan

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/z6il/skillguard/internal/finding"
	"github.com/z6il/skillguard/internal/rules"
)

// MaxFileSize is the largest file that gets scanned.
const MaxFileSize = 2 << 20

// IgnoreFile lists extra paths to skip, one glob per line, relative to the scan root.
const IgnoreFile = ".skillguardignore"

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true, "venv": true, "__pycache__": true, ".trash": true,
}

// Skipped reports whether a directory name is never scanned.
func Skipped(name string) bool { return skipDirs[name] }

var kinds = map[string]string{
	".md": rules.KindText, ".mdc": rules.KindText, ".markdown": rules.KindText, ".txt": rules.KindText,
	".json": rules.KindConfig, ".jsonc": rules.KindConfig, ".yaml": rules.KindConfig, ".yml": rules.KindConfig, ".toml": rules.KindConfig,
	".sh": rules.KindCode, ".bash": rules.KindCode, ".zsh": rules.KindCode, ".fish": rules.KindCode,
	".ps1": rules.KindCode, ".psm1": rules.KindCode, ".bat": rules.KindCode, ".cmd": rules.KindCode,
	".py": rules.KindCode, ".js": rules.KindCode, ".mjs": rules.KindCode, ".cjs": rules.KindCode,
	".ts": rules.KindCode, ".mts": rules.KindCode, ".cts": rules.KindCode, ".tsx": rules.KindCode, ".jsx": rules.KindCode,
	".go": rules.KindCode, ".rb": rules.KindCode, ".pl": rules.KindCode, ".lua": rules.KindCode, ".rs": rules.KindCode,
}

var namedKinds = map[string]string{
	".cursorrules": rules.KindText, ".windsurfrules": rules.KindText, ".clinerules": rules.KindText,
	"dockerfile": rules.KindCode, "makefile": rules.KindCode,
}

// KindOf returns the kind of file at p, or "" when it is not scanned.
func KindOf(p string) string {
	base := strings.ToLower(filepath.Base(p))
	if k, ok := namedKinds[base]; ok {
		return k
	}
	return kinds[strings.ToLower(filepath.Ext(base))]
}

// Result is the outcome of scanning one target.
type Result struct {
	Target   string            `json:"target"`
	Files    int               `json:"files"`
	Verdict  finding.Verdict   `json:"verdict"`
	Findings []finding.Finding `json:"findings"`
}

// Scanner holds the rules used for every file.
type Scanner struct {
	Rules *rules.Set
}

// Dir scans every relevant file under root. label is how the target is shown in reports.
func (s *Scanner) Dir(root, label string) (*Result, error) {
	res := &Result{Target: label}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		res.Files = 1
		res.Findings = s.File(filepath.Dir(root), root, filepath.Base(root))
		return finish(res), nil
	}
	ignore := loadIgnore(root)
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || ignored(ignore, rel)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || KindOf(p) == "" || ignored(ignore, rel) {
			return nil
		}
		if fi, err := d.Info(); err != nil || fi.Size() > MaxFileSize {
			return nil
		}
		res.Files++
		res.Findings = append(res.Findings, s.File(root, p, rel)...)
		return nil
	})
	return finish(res), err
}

func finish(r *Result) *Result {
	finding.Sort(r.Findings)
	r.Verdict = finding.VerdictOf(r.Findings)
	if r.Findings == nil {
		r.Findings = []finding.Finding{}
	}
	return r
}

// File scans one file. rel is the path shown in findings.
func (s *Scanner) File(root, p, rel string) []finding.Finding {
	data, err := os.ReadFile(p)
	if err != nil || bytes.IndexByte(data, 0) >= 0 {
		return nil
	}
	return s.Content(root, p, rel, data)
}

// Content scans file data that has already been read.
func (s *Scanner) Content(root, p, rel string, data []byte) []finding.Finding {
	kind := KindOf(p)
	if kind == "" {
		kind = rules.KindText
	}
	content := string(data)
	out := s.Rules.Match(rel, kind, content)
	out = append(out, invisible(rel, content)...)
	out = append(out, encoded(rel, content)...)
	if kind == rules.KindText {
		out = append(out, hiddenComments(rel, content)...)
	}
	if strings.HasSuffix(strings.ToLower(p), ".json") {
		if servers := ServersFromJSON(p, data); len(servers) > 0 {
			out = append(out, AnalyzeServers(rel, content, servers)...)
		}
		if hooks := HooksFromJSON(data); len(hooks) > 0 {
			out = append(out, AnalyzeHooks(rel, content, pluginRoot(root, p), hooks)...)
		}
	}
	return adjust(rel, out)
}

// adjust lowers findings in files agents don't load: tests, fixtures and docs written for people.
func adjust(rel string, fs []finding.Finding) []finding.Finding {
	switch {
	case IsTest(rel):
		for i := range fs {
			fs[i].Severity = finding.Info
			fs[i].Reason = "Test or fixture file, which agents don't load. " + fs[i].Reason
		}
	case isHumanDoc(rel):
		for i := range fs {
			if fs[i].Severity > finding.Info {
				fs[i].Severity--
			}
		}
	}
	return fs
}

var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true,
	"fixtures": true, "__fixtures__": true, "testdata": true, "test-data": true, "examples-malicious": true,
}

// IsTest reports whether rel is a test or fixture file.
func IsTest(rel string) bool {
	parts := strings.Split(strings.ToLower(rel), "/")
	for _, d := range parts[:len(parts)-1] {
		if testDirs[d] {
			return true
		}
	}
	base := parts[len(parts)-1]
	stem := strings.TrimSuffix(base, path.Ext(base))
	return strings.Contains(base, "_test.") || strings.Contains(base, ".test.") ||
		strings.Contains(base, ".spec.") || strings.HasPrefix(base, "test_") ||
		stem == "test" || stem == "tests" || strings.HasSuffix(stem, "_tests") ||
		strings.Contains(stem, "fixture")
}

func isHumanDoc(rel string) bool {
	base := strings.ToUpper(path.Base(rel))
	for _, n := range []string{"README", "CHANGELOG", "CONTRIBUTING", "SECURITY", "CODE_OF_CONDUCT", "LICENSE", "HISTORY"} {
		if strings.HasPrefix(base, n) {
			return true
		}
	}
	return false
}

// pluginRoot finds the nearest parent of p that holds a .claude-plugin folder, stopping at root.
func pluginRoot(root, p string) string {
	dir := filepath.Dir(p)
	for {
		if st, err := os.Stat(filepath.Join(dir, ".claude-plugin")); err == nil && st.IsDir() {
			return dir
		}
		if dir == root || len(dir) <= len(root) {
			return root
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return root
		}
		dir = parent
	}
}

func loadIgnore(root string) []string {
	f, err := os.Open(filepath.Join(root, IgnoreFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, strings.TrimSuffix(strings.TrimPrefix(l, "/"), "/"))
		}
	}
	return out
}

func ignored(patterns []string, rel string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, rel); ok {
			return true
		}
		if ok, _ := path.Match(p, path.Base(rel)); ok && !strings.Contains(p, "/") {
			return true
		}
		if strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}
