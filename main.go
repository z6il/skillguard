// Command skillguard audits agent skills, plugins, hooks and MCP configs before you trust them.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/z6il/skillguard/internal/audit"
	"github.com/z6il/skillguard/internal/finding"
	"github.com/z6il/skillguard/internal/lock"
	"github.com/z6il/skillguard/internal/report"
	"github.com/z6il/skillguard/internal/rules"
	"github.com/z6il/skillguard/internal/scan"
	"github.com/z6il/skillguard/internal/target"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = ""

const usage = `skillguard: audit agent skills, plugins, hooks and MCP configs before you trust them.

Usage:
  skillguard scan [path|git-url|owner/repo]...   scan add-ons before you install them
  skillguard audit                               scan everything installed for Claude Code, Cursor, Codex, Gemini CLI
  skillguard lock [targets...] | --installed     record what you approved
  skillguard diff [targets...] | --installed     show what changed since you locked it
  skillguard rules                               list every check
  skillguard version

Run "skillguard <command> -h" for the options of a command.

Exit codes: 0 clean, 1 findings at or above --fail-on (or changes for diff), 2 error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return 0
	}
	var err error
	code := 0
	switch args[0] {
	case "scan":
		code, err = cmdScan(args[1:], stdout)
	case "audit":
		code, err = cmdAudit(args[1:], stdout)
	case "lock":
		code, err = cmdLock(args[1:], stdout)
	case "diff":
		code, err = cmdDiff(args[1:], stdout)
	case "rules":
		code, err = cmdRules(stdout)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "skillguard", getVersion())
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "skillguard: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "skillguard:", err)
		return 2
	}
	return code
}

func getVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// parse handles flags placed before or after positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func newScanner(rulesFile string) (*scan.Scanner, error) {
	set, err := rules.Default()
	if err != nil {
		return nil, err
	}
	if rulesFile != "" {
		if err := set.LoadFile(rulesFile); err != nil {
			return nil, err
		}
	}
	return &scan.Scanner{Rules: set}, nil
}

func threshold(v string) (finding.Severity, bool, error) {
	if strings.EqualFold(v, "none") || v == "" {
		return 0, false, nil
	}
	s, err := finding.ParseSeverity(v)
	return s, err == nil, err
}

func output(path string, stdout io.Writer) (io.Writer, *os.File, func() error, error) {
	if path == "" || path == "-" {
		f, _ := stdout.(*os.File)
		return stdout, f, func() error { return nil }, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, nil, err
	}
	return f, nil, f.Close, nil
}

func painter(f *os.File, noColor bool) report.Painter {
	if f == nil {
		return report.Painter{}
	}
	return report.AutoPainter(f, noColor)
}

func cmdScan(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text, json or sarif")
	out := fs.String("o", "", "write the report to this file instead of stdout")
	failOn := fs.String("fail-on", "high", "exit 1 when a finding is at least this severe (critical, high, medium, low, info or none)")
	minSev := fs.String("min", "low", "hide findings below this severity in text output")
	rulesFile := fs.String("rules", "", "extra rules file (YAML) to load")
	noColor := fs.Bool("no-color", false, "disable colors")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: skillguard scan [path|git-url|owner/repo]... [options]")
		fs.PrintDefaults()
	}
	targets, err := parse(fs, args)
	if err != nil {
		return 2, err
	}
	if len(targets) == 0 {
		targets = []string{"."}
	}
	fail, failEnabled, err := threshold(*failOn)
	if err != nil {
		return 2, err
	}
	min, err := finding.ParseSeverity(*minSev)
	if err != nil {
		return 2, err
	}
	sc, err := newScanner(*rulesFile)
	if err != nil {
		return 2, err
	}

	var results []*scan.Result
	for _, a := range targets {
		t, err := target.Resolve(a)
		if err != nil {
			return 2, err
		}
		res, err := sc.Dir(t.Path, t.Label)
		t.Close()
		if err != nil {
			return 2, err
		}
		results = append(results, res)
	}

	w, f, closeFn, err := output(*out, stdout)
	if err != nil {
		return 2, err
	}
	switch *format {
	case "text":
		p := painter(f, *noColor)
		report.Header(w, p, getVersion())
		report.Text(w, p, results, min)
	case "json":
		err = report.JSON(w, getVersion(), results)
	case "sarif":
		err = report.SARIF(w, getVersion(), sc.Rules, results)
	default:
		err = fmt.Errorf("unknown format %q (want text, json or sarif)", *format)
	}
	if cerr := closeFn(); err == nil {
		err = cerr
	}
	if err != nil {
		return 2, err
	}
	if failEnabled {
		for _, r := range results {
			if finding.Max(r.Findings) >= fail {
				return 1, nil
			}
		}
	}
	return 0, nil
}

func homeAndLocations() (string, []audit.Location) {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	cfg, _ := os.UserConfigDir()
	return home, audit.Locations(home, cwd, cfg)
}

func cmdAudit(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	details := fs.Bool("details", false, "show every finding, not just the summary")
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "none", "exit 1 when a finding is at least this severe")
	minSev := fs.String("min", "low", "hide findings below this severity")
	rulesFile := fs.String("rules", "", "extra rules file (YAML) to load")
	noColor := fs.Bool("no-color", false, "disable colors")
	if _, err := parse(fs, args); err != nil {
		return 2, err
	}
	fail, failEnabled, err := threshold(*failOn)
	if err != nil {
		return 2, err
	}
	min, err := finding.ParseSeverity(*minSev)
	if err != nil {
		return 2, err
	}
	sc, err := newScanner(*rulesFile)
	if err != nil {
		return 2, err
	}
	home, locs := homeAndLocations()
	items := audit.Run(sc, home, locs)

	if *format == "json" {
		var results []*scan.Result
		for _, it := range items {
			results = append(results, it.Result)
		}
		if err := report.JSON(stdout, getVersion(), results); err != nil {
			return 2, err
		}
	} else {
		f, _ := stdout.(*os.File)
		printAudit(stdout, painter(f, *noColor), items, min, *details)
	}

	if failEnabled {
		for _, it := range items {
			if finding.Max(it.Result.Findings) >= fail {
				return 1, nil
			}
		}
	}
	return 0, nil
}

func printAudit(w io.Writer, p report.Painter, items []audit.Item, min finding.Severity, details bool) {
	report.Header(w, p, getVersion())
	if len(items) == 0 {
		fmt.Fprintln(w, "\n No agent add-ons or configs found.")
		return
	}
	whatW, pathW := 0, 0
	for _, it := range items {
		whatW = max(whatW, len(it.What))
		pathW = max(pathW, len([]rune(it.Display)))
	}
	agent := ""
	var worst []finding.Finding
	for _, it := range items {
		if it.Agent != agent {
			agent = it.Agent
			fmt.Fprintf(w, "\n %s %s\n", p.Red("▸"), p.Bold(agent))
		}
		shown := finding.Filter(it.Result.Findings, min)
		fmt.Fprintf(w, "   %s  %s  %s %s\n", report.Pad(it.What, whatW), p.Dim(report.Pad(it.Display, pathW)),
			p.Verdict(it.Result.Verdict), p.Dim(report.Summary(it.Result.Files, shown)))
		worst = append(worst, shown...)
	}
	if details {
		for _, it := range items {
			shown := finding.Filter(it.Result.Findings, min)
			if len(shown) == 0 {
				continue
			}
			report.TargetHeader(w, p, it.Agent+" · "+it.What+" ("+it.Display+")", it.Result.Verdict, it.Result.Files, shown)
			report.Findings(w, p, shown)
		}
	} else if len(worst) > 0 {
		fmt.Fprintf(w, "\n   %s\n", p.Dim("Run `skillguard audit --details` to see every finding."))
	}
	fmt.Fprintln(w)
}

// locked is one thing that can be locked: a scan target or an installed location.
type locked struct {
	key     string
	path    string
	mode    audit.Mode
	cleanup func()
}

func installedLockfile() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir, _ = os.UserHomeDir()
	}
	return filepath.Join(dir, "skillguard", "installed.lock")
}

func hashOf(l locked) (map[string]string, error) {
	if l.mode != audit.ClaudeJSON {
		return lock.Hash(l.path)
	}
	b, err := os.ReadFile(l.path)
	if err != nil {
		return nil, err
	}
	canon, _ := json.Marshal(audit.ClaudeServers(b))
	sum := sha256.Sum256(canon)
	return map[string]string{"mcpServers": hex.EncodeToString(sum[:])}, nil
}

func installedTargets() []locked {
	home, locs := homeAndLocations()
	var out []locked
	for _, l := range locs {
		if _, err := os.Stat(l.Path); err == nil {
			out = append(out, locked{key: audit.Tilde(l.Path, home), path: l.Path, mode: l.Mode})
		}
	}
	return out
}

func resolveLocked(args []string) ([]locked, error) {
	var out []locked
	for _, a := range args {
		t, err := target.Resolve(expandHome(a))
		if err != nil {
			for _, o := range out {
				if o.cleanup != nil {
					o.cleanup()
				}
			}
			return nil, err
		}
		out = append(out, locked{key: a, path: t.Path, cleanup: t.Close})
	}
	return out, nil
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(p, "~")))
	}
	return p
}

func cmdLock(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("lock", flag.ContinueOnError)
	installed := fs.Bool("installed", false, "lock everything installed for your agents (same places as audit)")
	lockfile := fs.String("lockfile", "", "lockfile path (default ./skillguard.lock, or your config folder with --installed)")
	force := fs.Bool("force", false, "lock even when the scan finds high or critical problems")
	noColor := fs.Bool("no-color", false, "disable colors")
	targets, err := parse(fs, args)
	if err != nil {
		return 2, err
	}
	path := *lockfile
	var items []locked
	if *installed {
		if path == "" {
			path = installedLockfile()
		}
		items = installedTargets()
	} else {
		if path == "" {
			path = "skillguard.lock"
		}
		if len(targets) == 0 {
			targets = []string{"."}
		}
		if items, err = resolveLocked(targets); err != nil {
			return 2, err
		}
	}
	defer func() {
		for _, it := range items {
			if it.cleanup != nil {
				it.cleanup()
			}
		}
	}()

	lf, err := lock.Load(path)
	if err != nil {
		return 2, err
	}
	sc, err := newScanner("")
	if err != nil {
		return 2, err
	}
	f, _ := stdout.(*os.File)
	p := painter(f, *noColor)
	report.Header(stdout, p, getVersion())
	code := 0
	for _, it := range items {
		if it.mode != audit.ClaudeJSON {
			res, err := sc.Dir(it.path, it.key)
			if err != nil {
				return 2, err
			}
			if res.Verdict == finding.Block && !*force {
				report.TargetHeader(stdout, p, it.key, res.Verdict, res.Files, res.Findings)
				report.Findings(stdout, p, finding.Filter(res.Findings, finding.High))
				fmt.Fprintf(stdout, "\n   %s\n", p.Red("Not locked: fix or remove these first, or use --force."))
				code = 1
				continue
			}
		}
		hashes, err := hashOf(it)
		if err != nil {
			return 2, err
		}
		lf.Put(it.key, hashes)
		fmt.Fprintf(stdout, " %s %s %s\n", p.Red("▸"), it.key, p.Dim(fmt.Sprintf("locked %d files", len(hashes))))
	}
	if err := lf.Save(path); err != nil {
		return 2, err
	}
	fmt.Fprintf(stdout, "\n   %s\n\n", p.Dim("Saved "+path))
	return code, nil
}

func cmdDiff(args []string, stdout io.Writer) (int, error) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	installed := fs.Bool("installed", false, "compare everything installed for your agents against the installed lockfile")
	lockfile := fs.String("lockfile", "", "lockfile path (default ./skillguard.lock, or your config folder with --installed)")
	noColor := fs.Bool("no-color", false, "disable colors")
	targets, err := parse(fs, args)
	if err != nil {
		return 2, err
	}
	path := *lockfile
	if path == "" {
		path = "skillguard.lock"
		if *installed {
			path = installedLockfile()
		}
	}
	lf, err := lock.Load(path)
	if err != nil {
		return 2, err
	}
	if len(lf.Targets) == 0 {
		return 2, fmt.Errorf("%s has nothing locked yet; run skillguard lock first", path)
	}

	var items []locked
	if *installed {
		current := map[string]locked{}
		for _, it := range installedTargets() {
			current[it.key] = it
		}
		keys := map[string]bool{}
		for k := range lf.Targets {
			keys[k] = true
		}
		for k := range current {
			keys[k] = true
		}
		for k := range keys {
			if it, ok := current[k]; ok {
				items = append(items, it)
			} else {
				items = append(items, locked{key: k})
			}
		}
	} else {
		if len(targets) == 0 {
			for k := range lf.Targets {
				targets = append(targets, k)
			}
		}
		for _, k := range targets {
			res, err := resolveLocked([]string{k})
			if err != nil {
				items = append(items, locked{key: k})
				continue
			}
			items = append(items, res[0])
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].key < items[j].key })
	defer func() {
		for _, it := range items {
			if it.cleanup != nil {
				it.cleanup()
			}
		}
	}()

	sc, err := newScanner("")
	if err != nil {
		return 2, err
	}
	f, _ := stdout.(*os.File)
	p := painter(f, *noColor)
	report.Header(stdout, p, getVersion())
	changed := 0
	for _, it := range items {
		entry := lf.Targets[it.key]
		var current map[string]string
		if it.path != "" {
			if current, err = hashOf(it); err != nil {
				return 2, err
			}
		}
		var old map[string]string
		if entry != nil {
			old = entry.Files
		}
		c := lock.Compare(old, current)
		if c.Empty() {
			fmt.Fprintf(stdout, " %s %s %s\n", p.Dim("▸"), it.key, p.Dim("unchanged"))
			continue
		}
		changed++
		status := "changed"
		switch {
		case entry == nil:
			status = "new, never locked"
		case it.path == "":
			status = "gone"
		}
		fmt.Fprintf(stdout, "\n %s %s  %s\n", p.Red("▸"), p.Bold(it.key), p.Red(status))
		for _, x := range c.Added {
			fmt.Fprintf(stdout, "   %s %s\n", p.Red("+"), x)
		}
		for _, x := range c.Modified {
			fmt.Fprintf(stdout, "   %s %s\n", p.Red("~"), x)
		}
		for _, x := range c.Removed {
			fmt.Fprintf(stdout, "   %s %s\n", p.Dim("-"), p.Dim(x))
		}
		if it.path == "" {
			continue
		}
		// Show findings in what changed.
		touched := map[string]bool{}
		for _, x := range append(c.Added, c.Modified...) {
			touched[x] = true
		}
		var shown []finding.Finding
		if it.mode == audit.ClaudeJSON {
			home, _ := os.UserHomeDir()
			for _, item := range audit.Run(sc, home, []audit.Location{{Agent: "Claude Code", What: "MCP servers", Path: it.path, Mode: audit.ClaudeJSON}}) {
				shown = append(shown, item.Result.Findings...)
			}
		} else if res, err := sc.Dir(it.path, it.key); err == nil {
			for _, fnd := range res.Findings {
				if touched[fnd.File] || (len(current) == 1 && len(touched) > 0) {
					shown = append(shown, fnd)
				}
			}
		}
		shown = finding.Filter(shown, finding.Low)
		if len(shown) > 0 {
			report.Findings(stdout, p, shown)
		}
	}
	if changed == 0 {
		fmt.Fprintf(stdout, "\n   %s\n\n", p.Dim("Nothing changed since it was locked."))
		return 0, nil
	}
	fmt.Fprintf(stdout, "\n   %s\n\n", p.Dim("Review the changes, then run `skillguard lock` again to approve them."))
	return 1, nil
}

func cmdRules(stdout io.Writer) (int, error) {
	set, err := rules.Default()
	if err != nil {
		return 2, err
	}
	type row struct {
		id, sev, title string
	}
	var rows []row
	for _, r := range set.Rules {
		rows = append(rows, row{r.ID, r.Severity.String(), r.Title})
	}
	for _, m := range rules.Builtins {
		rows = append(rows, row{m.ID, m.Severity.String(), m.Title})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	for _, r := range rows {
		fmt.Fprintf(stdout, "%-6s %-9s %s\n", r.id, r.sev, r.title)
	}
	return 0, nil
}
