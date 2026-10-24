package risk

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

var (
	// name = "value", name: 'value', "name": "value", NAME := `value`
	quotedAssign = regexp.MustCompile(`([A-Za-z_][\w.-]*)["']?\s*(?::=|=>|\?\?=|=|:)\s*[rbfu]?(["'` + "`" + `])([^"'` + "`" + `\n]+)["'` + "`" + `]`)
	// NAME=value, key: value, ENV KEY value
	bareAssign = regexp.MustCompile(`(?m)(?:^|[\s,{(;])(?:export\s+|ENV\s+|ARG\s+|\$)?([A-Za-z_][\w.-]*)\s*(?::|=)\s*([^\s"'` + "`" + `#,;=:][^\s"'` + "`" + `#,;]*)`)
	// --password value, --admin-password=value
	secretFlag = regexp.MustCompile(`--((?:admin-)?password|client-secret|secret|token|access-key|secret-key|sas-token|account-key|api-key)(?:\s+|=)["']?([^\s"']+)`)
	// var.x, os.environ["X"], process.env.X, getenv("X"): references, not values
	reference = regexp.MustCompile(`^(?:[A-Za-z_][\w]*(?:\.[\w]+|\[[^\]]*\]|\([^)]*\))+|[A-Za-z_][\w]*\(.*\)?|\d+)$`)
)

// Mask replaces passwords, keys and tokens in text with «SECRET_1»,
// «SECRET_2» and so on, so that the text can be shown to an AI model. It
// returns the masked text and the original behind each token; the
// originals never leave this machine. The same value always gets the same
// token, so the model can still see that two places use one secret.
func Mask(text string) (string, map[string]string) {
	m := &masker{originals: map[string]string{}, tokens: map[string]string{}}

	for _, p := range secretValue {
		text = p.re.ReplaceAllStringFunc(text, m.token)
	}
	// The body of a PEM key spans many lines of base64.
	text = pemBody.ReplaceAllStringFunc(text, m.token)
	// Keys of kinds we do not know by name still look random.
	text = replaceGroup(text, quotedLong, 1, func(sub []string) bool {
		return !masked(sub[1]) && looksRandom(sub[1])
	}, m.token)
	text = replaceGroup(text, quotedAssign, 3, func(sub []string) bool {
		return SecretName(sub[1]) && !Placeholder(sub[3]) && !masked(sub[3])
	}, m.token)
	text = replaceGroup(text, secretFlag, 2, func(sub []string) bool {
		return !Placeholder(sub[2]) && !strings.HasPrefix(sub[2], "$") && !masked(sub[2])
	}, m.token)
	text = replaceGroup(text, bareAssign, 2, func(sub []string) bool {
		v := sub[2]
		return SecretName(sub[1]) && !Placeholder(v) && !masked(v) && !reference.MatchString(v) &&
			!strings.HasPrefix(v, "$") && !strings.ContainsAny(v, "[({")
	}, m.token)
	return maskNamedValues(text, m), m.originals
}

var (
	// A secret's name on one line ...
	secretLabel = regexp.MustCompile(`(?i)(?:variable\s+"([^"]+)"|\bparam\s+(\w+)|["']?name["']?\s*[:=]\s*["']?([A-Za-z_][\w.-]*))`)
	// ... and its value on one of the next lines: Terraform "default",
	// Kubernetes and ARM "value", ARM "defaultValue".
	namedValue = regexp.MustCompile(`(?i)\b["']?(default|value|defaultValue)["']?\s*[:=]\s*["']?([^"'\s,}]+)`)
)

// maskNamedValues masks values whose secret name is on an earlier line,
// such as "- name: DB_PASSWORD" followed by "value: hunter2".
func maskNamedValues(text string, m *masker) string {
	lines := strings.Split(text, "\n")
	pending := 0
	for i, l := range lines {
		// Each new name starts over: only a secret's own value is masked.
		if sub := secretLabel.FindStringSubmatch(l); sub != nil {
			pending = 0
			if SecretName(sub[1] + sub[2] + sub[3]) {
				pending = 4
			}
		}
		if pending == 0 {
			continue
		}
		pending--
		before := lines[i]
		lines[i] = replaceGroup(l, namedValue, 2, func(sub []string) bool {
			v := sub[2]
			return !Placeholder(v) && !masked(v) && !reference.MatchString(v) && !strings.HasPrefix(v, "[")
		}, m.token)
		if lines[i] != before {
			pending = 0
		}
	}
	return strings.Join(lines, "\n")
}

var (
	pemBody    = regexp.MustCompile(`(?m)^[ \t]*[A-Za-z0-9+/]{40,}={0,2}[ \t]*$`)
	quotedLong = regexp.MustCompile(`["'` + "`" + `]([A-Za-z0-9+/=_\-.~]{24,})["'` + "`" + `]`)
)

// looksRandom reports whether s is a long string that mixes letters and
// digits the way generated keys do, unlike words, paths or version numbers.
func looksRandom(s string) bool {
	var lower, upper, digit int
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			lower++
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= '0' && r <= '9':
			digit++
		}
	}
	if lower == 0 || digit == 0 || (upper == 0 && digit < 4) {
		return false
	}
	return entropy(s) >= 3.8
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	e := 0.0
	for _, c := range counts {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

type masker struct {
	originals map[string]string // token -> value
	tokens    map[string]string // value -> token
}

func (m *masker) token(value string) string {
	if t, ok := m.tokens[value]; ok {
		return t
	}
	t := fmt.Sprintf("«SECRET_%d»", len(m.tokens)+1)
	m.tokens[value] = t
	m.originals[t] = value
	return t
}

func masked(v string) bool { return strings.Contains(v, "«SECRET_") }

// replaceGroup replaces one capture group of every match of re for which
// keep returns true.
func replaceGroup(text string, re *regexp.Regexp, group int, keep func([]string) bool, replace func(string) string) string {
	var b strings.Builder
	last := 0
	for _, idx := range re.FindAllStringSubmatchIndex(text, -1) {
		sub := make([]string, len(idx)/2)
		for i := range sub {
			if idx[2*i] >= 0 {
				sub[i] = text[idx[2*i]:idx[2*i+1]]
			}
		}
		start, end := idx[2*group], idx[2*group+1]
		if start < 0 || !keep(sub) {
			continue
		}
		b.WriteString(text[last:start])
		b.WriteString(replace(text[start:end]))
		last = end
	}
	b.WriteString(text[last:])
	return b.String()
}
