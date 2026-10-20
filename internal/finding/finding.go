// Package finding defines what a scan reports.
package finding

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Severity orders findings from informational to critical.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var names = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return names[s]
}

// ParseSeverity accepts a severity name in any case.
func ParseSeverity(v string) (Severity, error) {
	for i, n := range names {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", v)
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p, err := ParseSeverity(v)
	*s = p
	return err
}

// UnmarshalYAML lets rule files spell severities as words.
func (s *Severity) UnmarshalYAML(unmarshal func(any) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}
	p, err := ParseSeverity(v)
	*s = p
	return err
}

// Finding is one problem at one place.
type Finding struct {
	RuleID   string   `json:"rule"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	Column   int      `json:"column,omitempty"`
	Snippet  string   `json:"snippet,omitempty"`
	Reason   string   `json:"reason"`
}

// Verdict summarises the worst finding.
type Verdict string

const (
	Pass   Verdict = "PASS"
	Review Verdict = "REVIEW"
	Block  Verdict = "BLOCK"
)

// Max returns the highest severity in fs, or -1 when fs is empty.
func Max(fs []Finding) Severity {
	m := Severity(-1)
	for _, f := range fs {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// VerdictOf maps the worst finding to a verdict.
func VerdictOf(fs []Finding) Verdict {
	switch m := Max(fs); {
	case m >= High:
		return Block
	case m == Medium:
		return Review
	default:
		return Pass
	}
}

// Counts returns how many findings there are per severity.
func Counts(fs []Finding) map[Severity]int {
	c := map[Severity]int{}
	for _, f := range fs {
		c[f.Severity]++
	}
	return c
}

// Filter keeps findings at or above min.
func Filter(fs []Finding, min Severity) []Finding {
	out := fs[:0:0]
	for _, f := range fs {
		if f.Severity >= min {
			out = append(out, f)
		}
	}
	return out
}

// Sort orders by file, then line, then severity (worst first).
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Severity > b.Severity
	})
}
