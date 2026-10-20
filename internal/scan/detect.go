package scan

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/z6il/skillguard/internal/finding"
	"github.com/z6il/skillguard/internal/rules"
)

// invisible reports Unicode tag characters, bidi controls and stray zero-width characters.
func invisible(file, content string) []finding.Finding {
	var out []finding.Finding
	for n, line := range strings.Split(content, "\n") {
		var tags strings.Builder
		var bidi, zw int
		runes := []rune(line)
		for i, r := range runes {
			switch {
			case r >= 0xE0000 && r <= 0xE007F:
				if r >= 0xE0020 && r <= 0xE007E {
					tags.WriteRune(r - 0xE0000)
				}
			case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
				bidi++
			case r == 0x200B || r == 0x2060 || r == 0x2061 || r == 0x2062 || r == 0x2063 || r == 0x2064:
				zw++
			case r == 0xFEFF && !(n == 0 && i == 0):
				zw++
			case r == 0x200C || r == 0x200D:
				// Joiners are normal inside emoji and many scripts; only flag them next to ASCII.
				if nextToASCII(runes, i) {
					zw++
				}
			}
		}
		if s := tags.String(); s != "" {
			out = append(out, rules.New(rules.TagChars, file, n+1, fmt.Sprintf("hidden text: %q", clip(s, 120))))
		} else if strings.ContainsFunc(line, func(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }) {
			out = append(out, rules.New(rules.TagChars, file, n+1, "tag characters present"))
		}
		if bidi > 0 {
			out = append(out, rules.New(rules.Bidi, file, n+1, fmt.Sprintf("%d control character(s): %s", bidi, visible(line))))
		}
		if zw > 0 {
			out = append(out, rules.New(rules.ZeroWidth, file, n+1, fmt.Sprintf("%d character(s): %s", zw, visible(line))))
		}
	}
	return out
}

func nextToASCII(rs []rune, i int) bool {
	ascii := func(j int) bool { return j >= 0 && j < len(rs) && rs[j] < 0x80 && unicode.IsLetter(rs[j]) }
	return ascii(i-1) && ascii(i+1)
}

// visible replaces invisible characters with a marker so the snippet shows where they are.
func visible(line string) string {
	var b strings.Builder
	for _, r := range line {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			continue
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF ||
			(r >= 0x2061 && r <= 0x2064) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
			fmt.Fprintf(&b, "[U+%04X]", r)
		default:
			b.WriteRune(r)
		}
	}
	return clip(strings.TrimSpace(b.String()), 140)
}

var (
	htmlComment = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	commandish  = regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\s+(all|any|the|previous|prior|above|earlier|your)\b|\byou\s+(must|should|are now|will now)\b|\b(never|do not|don't)\s+(tell|inform|mention|reveal)\b|\bsecretly\b|\bwithout\s+(telling|asking)\b|\bsystem prompt\b|\b(curl|wget|Invoke-WebRequest)\b|\bexfiltrat\w*|\bsend\s+(it|this|that|them|all|the\s+\w+)\s+to\b|\.ssh\b|(^|[\s/])\.env\b`)
)

// hiddenComments flags HTML comments in Markdown that read like instructions.
func hiddenComments(file, content string) []finding.Finding {
	var out []finding.Finding
	for _, m := range htmlComment.FindAllStringSubmatchIndex(content, -1) {
		body := strings.TrimSpace(content[m[2]:m[3]])
		if body == "" || !commandish.MatchString(body) {
			continue
		}
		line := strings.Count(content[:m[0]], "\n") + 1
		out = append(out, rules.New(rules.HiddenComment, file, line, clip(oneLine(body), 140)))
	}
	return out
}

var (
	b64Block = regexp.MustCompile(`[A-Za-z0-9+/_-]{120,}={0,2}`)
	dataURI  = regexp.MustCompile(`(?i)data:[a-z]+/[a-z0-9.+-]+;base64,$`)
	alarming = regexp.MustCompile(`(?i)(curl|wget|https?://|/bin/(ba)?sh|powershell|eval|exec|ignore (all |the )?previous|system prompt|\.ssh|id_rsa|api[_-]?key|password)`)
)

// encoded decodes long base64 runs and reports the ones that hide text.
func encoded(file, content string) []finding.Finding {
	var out []finding.Finding
	for n, line := range strings.Split(content, "\n") {
		for _, loc := range b64Block.FindAllStringIndex(line, -1) {
			if dataURI.MatchString(line[max(0, loc[0]-60):loc[0]]) {
				continue
			}
			raw := line[loc[0]:loc[1]]
			if !mixed(raw) {
				continue
			}
			text, ok := decode(raw)
			if !ok {
				continue
			}
			id := rules.EncodedText
			if alarming.MatchString(text) {
				id = rules.EncodedPayload
			}
			out = append(out, rules.New(id, file, n+1, fmt.Sprintf("decodes to: %q", clip(oneLine(text), 120))))
		}
	}
	return out
}

// mixed filters out hex strings, long words and other runs that are not base64 in practice.
func mixed(s string) bool {
	var up, low, dig bool
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= 'a' && r <= 'z':
			low = true
		case r >= '0' && r <= '9':
			dig = true
		}
	}
	return up && low && dig
}

// decode returns the decoded text when it is mostly printable.
func decode(s string) (string, bool) {
	trimmed := strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(trimmed)
		if err != nil {
			continue
		}
		if !utf8.Valid(b) {
			return "", false
		}
		printable := 0
		total := 0
		for _, r := range string(b) {
			total++
			if unicode.IsPrint(r) || r == '\n' || r == '\t' || r == '\r' {
				printable++
			}
		}
		if total > 0 && printable*100/total >= 95 {
			return string(b), true
		}
		return "", false
	}
	return "", false
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
