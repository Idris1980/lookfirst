package risk

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

var (
	secretName  = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api_?key|apikey|access_?key|private_?key|connection_?string|client_?secret|(^|_)sas(_|$))`)
	notSecret   = regexp.MustCompile(`(?i)(public|[_-]?(id|ids|name|names|type|version|length|enabled|count|uri|url|path|file|header|limit|ttl|env|setting|settings|ref|reference|location|hint|label|prompt|message|msg|text|description|desc|placeholder|pattern|regex|format|field|column|param|input|mode|strength|policy|required|hash|algorithm|algo)$|[_-]?policy|[_-]?expir|[_-]?rotation|_min|_max|^next_?token)`)
	secretValue = []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "an AWS access key"},
		{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "a private key"},
		{regexp.MustCompile(`(?i)AccountKey=[A-Za-z0-9+/=]{20,}`), "an Azure storage key"},
		{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`), "a GitHub token"},
		{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{50,}`), "a GitHub token"},
		{regexp.MustCompile(`sk-(proj-|ant-)?[A-Za-z0-9_-]{20,}`), "an AI service API key"},
		{regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`), "a Slack token"},
		{regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), "a Google API key"},
		{regexp.MustCompile(`sk_live_[0-9A-Za-z]{20,}`), "a Stripe live key"},
		{regexp.MustCompile(`(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^:/\s]+:[^@/\s]+@`), "a connection string with a password"},
	}
	// placeholders are values that are obviously not real secrets.
	placeholder = regexp.MustCompile(`(?i)^(\$\{.*\}|\$[A-Z_][A-Z0-9_]*|<.*>|x+|\*+|changeme_later|your[_-].*|todo|none|null|true|false|\{\{.*\}\}|«SECRET_\d+»)$`)
)

// SecretName reports whether a setting or variable name usually holds a
// secret, such as admin_password or API_KEY.
func SecretName(name string) bool {
	return secretName.MatchString(name) && !notSecret.MatchString(name)
}

// SecretValue reports whether the value itself looks like a known kind of
// key, whatever it is called.
func SecretValue(value string) (what string, ok bool) {
	for _, p := range secretValue {
		if p.re.MatchString(value) {
			return p.what, true
		}
	}
	return "", false
}

// Placeholder reports whether a value is a reference or a stand-in rather
// than a real secret.
func Placeholder(value string) bool {
	v := strings.TrimSpace(value)
	return v == "" || placeholder.MatchString(v)
}

// CheckSecret reports a finding if name = value looks like a secret written
// into the code. The value is never repeated. fix tells how to do it right
// in this kind of file.
func CheckSecret(g *model.Graph, nodeID, name, value, file string, line int, fix string) bool {
	if Placeholder(value) {
		return false
	}
	if what, ok := SecretValue(value); ok {
		g.Add(model.High, nodeID, "Secret written in the code",
			fmt.Sprintf("%s looks like %s. Anyone who can see this code can use it. Remove it, revoke it, and %s.", name, what, fix), file, line)
		return true
	}
	if SecretName(name) {
		g.Add(model.High, nodeID, "Password or key written in the code",
			fmt.Sprintf("%s has its value written directly in the file. Anyone who can see this code, or the Git history, can read it. Instead, %s.", name, fix), file, line)
		return true
	}
	return false
}
