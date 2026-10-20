package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/z6il/skillguard/internal/finding"
	"github.com/z6il/skillguard/internal/scan"
)

// Header prints the tool banner.
func Header(w io.Writer, p Painter, version string) {
	fmt.Fprintf(w, "\n %s %s\n", p.Red("▌skillguard"), p.Dim(version))
}

// Text prints results for people.
func Text(w io.Writer, p Painter, results []*scan.Result, min finding.Severity) {
	var blocked, review, passed int
	for _, r := range results {
		shown := finding.Filter(r.Findings, min)
		TargetHeader(w, p, r.Target, r.Verdict, r.Files, r.Findings)
		Findings(w, p, shown)
		switch r.Verdict {
		case finding.Block:
			blocked++
		case finding.Review:
			review++
		default:
			passed++
		}
	}
	if len(results) > 1 {
		fmt.Fprintf(w, "\n %s %d targets · %s · %s · %s\n", p.Red("▌"), len(results),
			p.Red(fmt.Sprintf("%d blocked", blocked)), fmt.Sprintf("%d to review", review), fmt.Sprintf("%d passed", passed))
	}
	fmt.Fprintln(w)
}

// TargetHeader prints the line that introduces one target.
func TargetHeader(w io.Writer, p Painter, label string, v finding.Verdict, files int, all []finding.Finding) {
	fmt.Fprintf(w, "\n %s %s  %s\n", p.Red("▸"), p.Bold(label), p.Verdict(v))
	fmt.Fprintf(w, "   %s\n", p.Dim(Summary(files, all)))
}

// Summary is "12 files · 1 critical · 2 high".
func Summary(files int, fs []finding.Finding) string {
	parts := []string{plural(files, "file")}
	c := finding.Counts(fs)
	for s := finding.Critical; s >= finding.Low; s-- {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], s))
		}
	}
	if len(parts) == 1 {
		parts = append(parts, "nothing found")
	}
	return strings.Join(parts, " · ")
}

// Findings prints findings grouped by file.
func Findings(w io.Writer, p Painter, fs []finding.Finding) {
	file := ""
	for _, f := range fs {
		if f.File != file {
			file = f.File
			fmt.Fprintf(w, "\n   %s\n", p.Faint(file))
		}
		loc := ""
		if f.Line > 0 {
			loc = fmt.Sprintf(":%d", f.Line)
		}
		fmt.Fprintf(w, "   %s %s  %s %s\n", p.Sev(f.Severity), p.Dim(f.RuleID), f.Title, p.Dim(loc))
		if f.Snippet != "" {
			fmt.Fprintf(w, "   %s%s\n", strings.Repeat(" ", 11), truncate(f.Snippet, 110))
		}
		fmt.Fprintf(w, "   %s%s\n", strings.Repeat(" ", 11), p.Dim(f.Reason))
	}
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// Pad right-pads s to width n, counting runes.
func Pad(s string, n int) string {
	if c := utf8.RuneCountInString(s); c < n {
		return s + strings.Repeat(" ", n-c)
	}
	return s
}
