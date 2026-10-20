package rules

import "github.com/z6il/skillguard/internal/finding"

// Meta describes a check that is implemented in code rather than as a pattern.
type Meta struct {
	ID       string
	Title    string
	Severity finding.Severity
	Reason   string
}

// Built-in check IDs.
const (
	HiddenComment   = "SG002"
	TagChars        = "SG003"
	Bidi            = "SG004"
	ZeroWidth       = "SG005"
	EncodedPayload  = "SG008"
	EncodedText     = "SG009"
	MCPUnpinned     = "SG040"
	MCPSecret       = "SG041"
	MCPPlainHTTP    = "SG042"
	MCPInlineShell  = "SG043"
	MCPRemote       = "SG044"
	HookEveryTool   = "SG050"
	HookEveryPrompt = "SG051"
	HookNetwork     = "SG052"
	HookSession     = "SG053"
)

// Builtins lists every code-based check.
var Builtins = []Meta{
	{HiddenComment, "Instructions hidden in an HTML comment", finding.High,
		"Markdown renderers hide HTML comments from people, but the agent still reads them."},
	{TagChars, "Hidden Unicode tag text", finding.Critical,
		"Unicode tag characters are invisible on screen but read as text by the model. This is a known way to smuggle instructions."},
	{Bidi, "Bidirectional control characters", finding.High,
		"These reorder text on screen, so what you review is not what runs (Trojan Source)."},
	{ZeroWidth, "Zero-width characters", finding.Medium,
		"Invisible characters can hide or split words to slip past review."},
	{EncodedPayload, "Encoded payload", finding.High,
		"A base64 block decodes to commands, URLs or instructions that are hidden from a reader."},
	{EncodedText, "Large encoded text block", finding.Low,
		"A base64 block decodes to readable text. Check why it is encoded."},
	{MCPUnpinned, "Unpinned MCP package", finding.Medium,
		"The server runs whatever version is published next. A hijacked or sold package updates silently."},
	{MCPSecret, "Secret stored in MCP config", finding.High,
		"A token is written in plain text. Use an environment variable reference instead."},
	{MCPPlainHTTP, "Unencrypted remote MCP server", finding.Medium,
		"Traffic to this server, including tokens, is sent without TLS."},
	{MCPInlineShell, "MCP server runs an inline shell command", finding.Medium,
		"The server is started through a shell string, which is hard to review and easy to extend."},
	{MCPRemote, "Remote MCP server", finding.Info,
		"This server runs on someone else's machine and sees what the agent sends it."},
	{HookEveryTool, "Hook runs on every tool call", finding.Low,
		"This hook runs before or after every action the agent takes. Make sure you trust the script."},
	{HookEveryPrompt, "Hook sees every prompt", finding.Low,
		"This hook receives everything you type to the agent."},
	{HookNetwork, "Hook makes network calls", finding.High,
		"A hook that talks to the network can send your prompts, code or tool output somewhere."},
	{HookSession, "Hook runs at session start", finding.Info,
		"Runs automatically every time you open the agent."},
}

// Lookup returns the metadata for a built-in check.
func Lookup(id string) Meta {
	for _, m := range Builtins {
		if m.ID == id {
			return m
		}
	}
	return Meta{ID: id, Title: id}
}

// New builds a finding for a built-in check.
func New(id, file string, line int, snippet string) finding.Finding {
	m := Lookup(id)
	return finding.Finding{
		RuleID: m.ID, Title: m.Title, Severity: m.Severity,
		File: file, Line: line, Snippet: snippet, Reason: m.Reason,
	}
}
