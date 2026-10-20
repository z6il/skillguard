// Package report renders scan results as text, JSON or SARIF.
package report

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/z6il/skillguard/internal/finding"
)

// Painter adds ANSI colors when they are enabled.
type Painter struct{ On bool }

// AutoPainter enables color for terminals unless NO_COLOR is set.
func AutoPainter(f *os.File, disable bool) Painter {
	if disable || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return Painter{}
	}
	if os.Getenv("FORCE_COLOR") != "" || os.Getenv("CLICOLOR_FORCE") == "1" {
		return Painter{On: true}
	}
	if !term.IsTerminal(int(f.Fd())) {
		return Painter{}
	}
	return Painter{On: enableVT(f)}
}

const reset = "\x1b[0m"

func (p Painter) wrap(code, s string) string {
	if !p.On {
		return s
	}
	return code + s + reset
}

func rgb(r, g, b int) string   { return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b) }
func onRGB(r, g, b int) string { return fmt.Sprintf("\x1b[48;2;%d;%d;%dm", r, g, b) }

// Palette: red-and-black terminal look.
func (p Painter) Red(s string) string   { return p.wrap("\x1b[1m"+rgb(255, 46, 77), s) }
func (p Painter) Dim(s string) string   { return p.wrap(rgb(120, 120, 135), s) }
func (p Painter) Bold(s string) string  { return p.wrap("\x1b[1m", s) }
func (p Painter) Faint(s string) string { return p.wrap(rgb(170, 170, 185), s) }

// Sev renders a fixed-width severity tag.
func (p Painter) Sev(s finding.Severity) string {
	label := fmt.Sprintf(" %-8s ", upper(s.String()))
	switch s {
	case finding.Critical:
		return p.wrap("\x1b[1m"+onRGB(255, 46, 77)+rgb(255, 255, 255), label)
	case finding.High:
		return p.wrap("\x1b[1m"+rgb(255, 46, 77), label)
	case finding.Medium:
		return p.wrap(rgb(240, 185, 11), label)
	case finding.Low:
		return p.wrap(rgb(38, 165, 228), label)
	default:
		return p.wrap(rgb(120, 120, 135), label)
	}
}

// Verdict renders PASS, REVIEW or BLOCK.
func (p Painter) Verdict(v finding.Verdict) string {
	label := " " + string(v) + " "
	switch v {
	case finding.Block:
		return p.wrap("\x1b[1m"+onRGB(255, 46, 77)+rgb(255, 255, 255), label)
	case finding.Review:
		return p.wrap("\x1b[1m"+onRGB(240, 185, 11)+rgb(0, 0, 0), label)
	default:
		return p.wrap("\x1b[1m"+rgb(61, 220, 151), label)
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
