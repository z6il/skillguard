package report

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/z6il/skillguard/internal/finding"
	"github.com/z6il/skillguard/internal/rules"
	"github.com/z6il/skillguard/internal/scan"
)

// JSON writes results as one JSON document.
func JSON(w io.Writer, version string, results []*scan.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Tool    string         `json:"tool"`
		Version string         `json:"version"`
		Results []*scan.Result `json:"results"`
	}{"skillguard", version, results})
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription map[string]string `json:"shortDescription"`
	FullDescription  map[string]string `json:"fullDescription"`
	DefaultConfig    map[string]string `json:"defaultConfiguration"`
	Properties       map[string]any    `json:"properties"`
}

// SARIF writes results in SARIF 2.1.0 for GitHub code scanning and other tools.
func SARIF(w io.Writer, version string, set *rules.Set, results []*scan.Result) error {
	var ruleList []sarifRule
	index := map[string]int{}
	add := func(id, title, reason string, sev finding.Severity) {
		if _, ok := index[id]; ok {
			return
		}
		index[id] = len(ruleList)
		ruleList = append(ruleList, sarifRule{
			ID: id, Name: camel(title),
			ShortDescription: map[string]string{"text": title},
			FullDescription:  map[string]string{"text": reason},
			DefaultConfig:    map[string]string{"level": level(sev)},
			Properties:       map[string]any{"security-severity": score(sev), "tags": []string{"security"}},
		})
	}
	for _, r := range set.Rules {
		add(r.ID, r.Title, r.Reason, r.Severity)
	}
	for _, m := range rules.Builtins {
		add(m.ID, m.Title, m.Reason, m.Severity)
	}

	type region struct {
		StartLine   int `json:"startLine,omitempty"`
		StartColumn int `json:"startColumn,omitempty"`
	}
	type result struct {
		RuleID    string            `json:"ruleId"`
		RuleIndex int               `json:"ruleIndex"`
		Level     string            `json:"level"`
		Message   map[string]string `json:"message"`
		Locations []map[string]any  `json:"locations"`
	}
	var out []result
	for _, r := range results {
		prefix := ""
		if len(results) > 1 {
			prefix = strings.TrimSuffix(r.Target, "/") + "/"
		}
		for _, f := range r.Findings {
			msg := f.Title + ": " + f.Reason
			if f.Snippet != "" {
				msg += " (" + f.Snippet + ")"
			}
			line := f.Line
			if line == 0 {
				line = 1
			}
			out = append(out, result{
				RuleID: f.RuleID, RuleIndex: index[f.RuleID], Level: level(f.Severity),
				Message: map[string]string{"text": msg},
				Locations: []map[string]any{{"physicalLocation": map[string]any{
					"artifactLocation": map[string]string{"uri": prefix + f.File},
					"region":           region{StartLine: line, StartColumn: f.Column},
				}}},
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	if out == nil {
		out = []result{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name": "skillguard", "version": version,
				"informationUri": "https://github.com/z6il/skillguard",
				"rules":          ruleList,
			}},
			"results": out,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func level(s finding.Severity) string {
	switch {
	case s >= finding.High:
		return "error"
	case s == finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

func score(s finding.Severity) string {
	return map[finding.Severity]string{
		finding.Critical: "9.5", finding.High: "8.0", finding.Medium: "5.5", finding.Low: "3.0", finding.Info: "0.0",
	}[s]
}

func camel(s string) string {
	var b strings.Builder
	for _, w := range strings.Fields(s) {
		w = strings.Trim(w, "()-.,")
		if w == "" {
			continue
		}
		b.WriteString(strings.ToUpper(w[:1]) + w[1:])
	}
	return b.String()
}
