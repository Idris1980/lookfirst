package risk

import (
	"regexp"
	"strings"
)

// leftover finds stand-ins that someone was meant to replace, such as
// "YOUR_IP_ADDRESS" or "<your-subscription-id>". AI assistants write them
// often, and code that still has them fails, or worse, half works. Names
// like "my-vnet" are left alone: they are real names that work as they are.
var leftover = regexp.MustCompile(`(?i)["'` + "`" + `](your[_-][a-z0-9_.-]+|<[^<>"'` + "`" + `\n]*\byour\b[^<>"'` + "`" + `\n]*>|replace[_-]?(?:me|this|with[_-][a-z0-9_-]+)|change[_-]?me|insert[_-][a-z0-9_-]+|xxx\.xxx\.xxx\.xxx|0{8}-0{4}-0{4}-0{4}-0{12})["'` + "`" + `]`)

// Leftovers returns the placeholders in one line of code, without quotes.
func Leftovers(line string) []string {
	var out []string
	for _, m := range leftover.FindAllStringSubmatch(line, -1) {
		out = append(out, m[1])
	}
	return out
}

// LeftoverAdvice explains a placeholder finding.
func LeftoverAdvice(value string) string {
	return "The code still contains " + quote(value) + ", which someone was meant to replace with a real value. " +
		"Until it is replaced, the code fails, or works in a way nobody chose. Fill in the real value, preferably from a variable or parameter."
}

func quote(s string) string { return "\"" + strings.TrimSpace(s) + "\"" }
