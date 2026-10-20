// Package rules loads pattern rules and matches them line by line.
package rules

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/z6il/skillguard/internal/finding"
)

//go:embed rules.yaml
var defaultRules []byte

// File kinds a rule can target.
const (
	KindText   = "text"
	KindCode   = "code"
	KindConfig = "config"
)

// Rule is one regular-expression check.
type Rule struct {
	ID         string           `yaml:"id"`
	Title      string           `yaml:"title"`
	Severity   finding.Severity `yaml:"severity"`
	Kinds      []string         `yaml:"kinds"`
	Pattern    string           `yaml:"pattern"`
	Exclude    string           `yaml:"exclude"`
	SkipLine   string           `yaml:"skip_line"`
	IgnoreCase bool             `yaml:"ignore_case"`
	Secret     bool             `yaml:"secret"`
	SkipQuoted bool             `yaml:"skip_quoted"`
	Reason     string           `yaml:"reason"`

	re       *regexp.Regexp
	exclude  *regexp.Regexp
	skipLine *regexp.Regexp
}

// Set is an ordered list of compiled rules.
type Set struct {
	Rules []*Rule
}

type file struct {
	Rules []*Rule `yaml:"rules"`
}

// Default returns the built-in rules.
func Default() (*Set, error) {
	return parse(defaultRules, "built-in rules")
}

// LoadFile adds the rules in path to s. A rule with an existing ID replaces it.
func (s *Set) LoadFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	extra, err := parse(b, path)
	if err != nil {
		return err
	}
	for _, r := range extra.Rules {
		replaced := false
		for i, old := range s.Rules {
			if old.ID == r.ID {
				s.Rules[i] = r
				replaced = true
				break
			}
		}
		if !replaced {
			s.Rules = append(s.Rules, r)
		}
	}
	return nil
}

func parse(b []byte, source string) (*Set, error) {
	var f file
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	for _, r := range f.Rules {
		if r.ID == "" || r.Pattern == "" {
			return nil, fmt.Errorf("%s: every rule needs an id and a pattern", source)
		}
		flags := ""
		if r.IgnoreCase {
			flags = "(?i)"
		}
		re, err := regexp.Compile(flags + r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: rule %s: %w", source, r.ID, err)
		}
		r.re = re
		if r.Exclude != "" {
			if r.exclude, err = regexp.Compile(flags + r.Exclude); err != nil {
				return nil, fmt.Errorf("%s: rule %s exclude: %w", source, r.ID, err)
			}
		}
		if r.SkipLine != "" {
			if r.skipLine, err = regexp.Compile(flags + r.SkipLine); err != nil {
				return nil, fmt.Errorf("%s: rule %s skip_line: %w", source, r.ID, err)
			}
		}
	}
	return &Set{Rules: f.Rules}, nil
}

func (r *Rule) applies(kind string) bool {
	if len(r.Kinds) == 0 {
		return true
	}
	for _, k := range r.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Match runs every rule that applies to kind over content.
// It reports at most one finding per rule per line.
func (s *Set) Match(file, kind, content string) []finding.Finding {
	var out []finding.Finding
	for n, line := range strings.Split(content, "\n") {
		if len(line) > 20000 {
			line = line[:20000]
		}
		for _, r := range s.Rules {
			if !r.applies(kind) || (r.skipLine != nil && r.skipLine.MatchString(line)) {
				continue
			}
			for _, loc := range r.re.FindAllStringIndex(line, -1) {
				m := line[loc[0]:loc[1]]
				if r.exclude != nil && r.exclude.MatchString(m) {
					continue
				}
				if r.Secret && Placeholder(m) {
					continue
				}
				if r.SkipQuoted && quoted(line, loc[0]) {
					continue
				}
				snip := Snippet(line, loc[0], loc[1])
				if r.Secret {
					snip = strings.Replace(snip, m, Redact(m), 1)
				}
				out = append(out, finding.Finding{
					RuleID: r.ID, Title: r.Title, Severity: r.Severity,
					File: file, Line: n + 1, Column: loc[0] + 1,
					Snippet: snip, Reason: r.Reason,
				})
				break
			}
		}
	}
	return out
}

// quoted reports whether the match at start opens a quotation, which is how
// docs and defensive prompts cite an attack phrase rather than use it.
func quoted(line string, start int) bool {
	if start == 0 {
		return false
	}
	before := strings.TrimRight(line[:start], " ")
	for _, q := range []string{`"`, "'", "`", "“", "‘", "«", "("} {
		if strings.HasSuffix(before, q) {
			return true
		}
	}
	return false
}

// Snippet returns the text around [start,end) trimmed to a readable length.
func Snippet(line string, start, end int) string {
	const ctx = 50
	from, to := start-ctx, end+ctx
	pre, post := "…", "…"
	if from <= 0 {
		from, pre = 0, ""
	}
	if to >= len(line) {
		to, post = len(line), ""
	}
	// Don't cut a UTF-8 sequence in half.
	for from > 0 && !isRuneStart(line[from]) {
		from--
	}
	for to < len(line) && !isRuneStart(line[to]) {
		to++
	}
	return pre + strings.TrimSpace(line[from:to]) + post
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Redact keeps the first few characters of a secret.
func Redact(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:6] + strings.Repeat("*", 8)
}

// Placeholder reports whether a token is an obvious example value.
func Placeholder(s string) bool {
	l := strings.ToLower(s)
	for _, w := range []string{"xxxx", "your", "example", "placeholder", "dummy", "redacted", "0000", "1234"} {
		if strings.Contains(l, w) {
			return true
		}
	}
	seen := map[rune]bool{}
	for _, c := range s {
		seen[c] = true
	}
	return len(seen) < 8
}
