package script

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/source"
)

// manifest reads a package list (package.json or requirements.txt): which
// packages it would install, and, for npm, what runs during installation.
func (s *scan) manifest() {
	if s.f.Kind == source.NpmManifest {
		s.npmManifest()
		return
	}
	s.pipRequirements()
}

// installHooks run automatically when a package is installed, before
// anyone has looked at what the package does.
var installHooks = []string{"preinstall", "install", "postinstall", "prepare"}

var hookDanger = regexp.MustCompile(`\b(curl|wget|bash|sh|powershell|pwsh|iex|eval|nc|base64)\b|node\s+-e|https?://`)

func (s *scan) npmManifest() {
	var m struct {
		Scripts              map[string]string `json:"scripts"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(s.f.Data, &m); err != nil {
		s.add(model.High, "Syntax error", "package.json is not valid JSON: "+err.Error()+".", 0)
		return
	}

	for _, hook := range installHooks {
		cmd, ok := m.Scripts[hook]
		if !ok {
			continue
		}
		ln := s.lineOf(`"` + hook + `"`)
		if hookDanger.MatchString(cmd) {
			s.add(model.High, "Runs a download or shell command when installed",
				fmt.Sprintf("The %q script runs automatically on npm install and calls %q. This is a common way for malicious packages to run code on your machine. Read what it does before installing, or install with --ignore-scripts.", hook, clipText(cmd, 80)), ln)
		} else {
			s.add(model.Low, "Runs a script when installed",
				fmt.Sprintf("The %q script runs automatically on npm install. Check what %q does.", hook, clipText(cmd, 80)), ln)
		}
	}

	for _, deps := range []map[string]string{m.Dependencies, m.DevDependencies, m.OptionalDependencies} {
		for _, name := range sortedKeys(deps) {
			version := deps[name]
			ln := s.lineOf(`"` + name + `"`)
			s.pkg(name, "npm", "installs", ln)
			// A dependency fetched from an address bypasses the registry and
			// its checks; "latest" and "*" accept whatever is published next.
			switch {
			case strings.Contains(version, "://") || strings.HasPrefix(version, "git+") || strings.HasPrefix(version, "github:"):
				s.add(model.Medium, "Package installed straight from an address",
					fmt.Sprintf("%q comes from %q instead of the npm registry, so it is not checked there and can change at any time. Prefer a published version.", name, version), ln)
			case version == "*" || version == "latest" || version == "":
				s.add(model.Low, "Package version is not pinned",
					fmt.Sprintf("%q accepts any version, including a bad one published tomorrow. Give a version range such as ^1.2.3.", name), ln)
			}
		}
	}
}

var reqName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

func (s *scan) pipRequirements() {
	for _, l := range s.lines {
		text := strings.TrimSpace(l.code) // comments are already blank
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "-") {
			fields := strings.Fields(strings.Replace(text, "=", " ", 1))
			if len(fields) > 1 && (fields[0] == "--extra-index-url" || fields[0] == "--index-url" || fields[0] == "-i") {
				host := fields[1]
				if u, err := url.Parse(fields[1]); err == nil && u.Host != "" {
					host = u.Host
				}
				if !strings.HasSuffix(host, "pypi.org") {
					s.add(model.Medium, "Packages may come from another server",
						fmt.Sprintf("%s makes pip look for packages on %s as well. A package there with the same name as a public one can win (dependency confusion). Make sure you trust that server.", fields[0], host), l.n)
				}
			}
			continue
		}
		if strings.Contains(text, "://") || strings.HasPrefix(text, "git+") {
			s.add(model.Medium, "Package installed straight from an address",
				"This line installs from an address instead of PyPI, so it is not checked there and can change at any time. Prefer a released version.", l.n)
			continue
		}
		if m := reqName.FindStringSubmatch(text); m != nil {
			s.pkg(m[1], "pip", "installs", l.n)
		}
	}
}

func (s *scan) lineOf(needle string) int {
	if i := bytes.Index(s.f.Data, []byte(needle)); i >= 0 {
		return bytes.Count(s.f.Data[:i], []byte("\n")) + 1
	}
	return 0
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
