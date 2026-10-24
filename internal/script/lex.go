package script

import "github.com/Idris1980/lookfirst/internal/source"

// stripComments blanks out comments but keeps strings and every newline, so
// rules do not fire on commented-out code and line numbers stay right. It
// is a small lexer, not a parser: good enough for finding patterns.
func stripComments(src []byte, kind source.Kind) []byte {
	out := make([]byte, len(src))
	copy(out, src)

	hash := kind == source.Python || kind == source.Shell || kind == source.PowerShell || kind == source.Dockerfile || kind == source.PipRequirements
	slash := kind == source.JavaScript
	var quote byte    // the open string's quote, or 0
	triple := false   // Python """ or '''
	block := ""       // the end marker of an open block comment
	lineStart := true // only whitespace so far on this line

	blank := func(i int) {
		if out[i] != '\n' && out[i] != '\r' {
			out[i] = ' '
		}
	}

	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '\n' {
			lineStart = true
			if quote != 0 && !triple && quote != '`' && kind != source.Shell && kind != source.PowerShell {
				quote = 0 // unterminated string: recover at end of line
			}
			continue
		}

		if block != "" {
			if hasAt(src, i, block) {
				for j := 0; j < len(block); j++ {
					blank(i + j)
				}
				i += len(block) - 1
				block = ""
				continue
			}
			blank(i)
			continue
		}

		if quote != 0 {
			switch {
			case c == '\\' && kind != source.PowerShell && !(kind == source.Shell && quote == '\''):
				i++
			case kind == source.PowerShell && c == '`':
				i++
			case triple && hasAt(src, i, string([]byte{quote, quote, quote})):
				i += 2
				quote, triple = 0, false
			case !triple && c == quote:
				quote = 0
			}
			continue
		}

		switch {
		case kind == source.Python && (hasAt(src, i, `"""`) || hasAt(src, i, `'''`)):
			quote, triple = c, true
			i += 2
		case c == '"' || c == '\'' || (slash && c == '`'):
			// In shell, a ' inside a word like don't is still a quote; that
			// is rare in scripts and only shifts what counts as a comment.
			quote = c
		case kind == source.PowerShell && hasAt(src, i, "<#"):
			block = "#>"
			blank(i)
		case hash && c == '#' && (lineStart || kind != source.Shell || isSpace(prev(src, i))):
			if kind == source.Shell && i == 0 && hasAt(src, i, "#!") {
				break // keep the shebang
			}
			for i < len(src) && src[i] != '\n' {
				blank(i)
				i++
			}
			i--
		case slash && hasAt(src, i, "//") && prev(src, i) != ':':
			for i < len(src) && src[i] != '\n' {
				blank(i)
				i++
			}
			i--
		case slash && hasAt(src, i, "/*"):
			block = "*/"
			blank(i)
		}
		if !isSpace(c) {
			lineStart = false
		}
	}
	return out
}

func hasAt(b []byte, i int, s string) bool {
	return i+len(s) <= len(b) && string(b[i:i+len(s)]) == s
}

func prev(b []byte, i int) byte {
	if i == 0 {
		return ' '
	}
	return b[i-1]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }
