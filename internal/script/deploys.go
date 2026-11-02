package script

import (
	"path"
	"regexp"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/source"
)

// A script often builds nothing itself: it hands a template to the cloud,
// as in az deployment group create --template-file templates/main.json.
// Without a box for that, the picture of such a script looks empty, so the
// template it deploys is drawn too, with a line from the script and a note
// that the template has a picture of its own.

var (
	deployCmds = []struct {
		re    *regexp.Regexp
		cloud string
		flags []string
	}{
		{regexp.MustCompile(`(?i)\baz\s+deployment\s+(group|sub|mg|tenant)\s+(create|what-if|validate)\b`), "azure", []string{"--template-file", "-f"}},
		{regexp.MustCompile(`(?i)\bNew-Az(ResourceGroup|Subscription|ManagementGroup|Tenant)?Deployment\b|\bTest-AzResourceGroupDeployment\b`), "azure", []string{"-TemplateFile"}},
		{regexp.MustCompile(`(?i)\baws\s+cloudformation\s+(deploy|create-stack|update-stack|create-change-set)\b`), "aws", []string{"--template-file", "--template-body"}},
		{regexp.MustCompile(`(?i)\bsam\s+deploy\b`), "aws", []string{"--template-file", "-t"}},
	}
	// $mall = Join-Path $PSScriptRoot "templates" "azuredeploy.json"
	psJoinPath = regexp.MustCompile(`(?i)^\s*\$(\w+)\s*=\s*Join-Path\s+(.+)$`)
	quotedPart = regexp.MustCompile(`["']([^"']+)["']`)
	// $file = "templates/main.json", TEMPLATE=templates/main.json
	psStringVar = regexp.MustCompile(`^\s*\$(\w+)\s*=\s*["']([^"']+)["']\s*$`)
	shStringVar = regexp.MustCompile(`^\s*(?:export\s+)?(\w+)=["']?([^"'\s;]+)["']?\s*$`)
	scriptRoot  = regexp.MustCompile(`(?i)^(\$PSScriptRoot|\$\{PSScriptRoot\}|\$\(dirname\s+"?\$0"?\)|\$SCRIPT_DIR|\$\{SCRIPT_DIR\}|\.)[\\/]`)
	// $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path,
	// DIR=$(cd "$(dirname "$0")" && pwd) and the like: the script's folder.
	rootDef    = regexp.MustCompile(`(?i)^\s*\$?(\w+)\s*=\s*.*(MyInvocation\.MyCommand|PSCommandPath|\$PSScriptRoot|dirname\s+"?\$(0|\{?BASH_SOURCE))`)
	leadingVar = regexp.MustCompile(`^\$\{?(\w+)\}?[\\/]`)
)

// pathResolver turns a path in a script into one relative to the script:
// "$PSScriptRoot	emplates\main.json", a variable set with Join-Path or
// to a string, or one that starts with a variable holding the script's
// own folder ($scriptDir = Split-Path … $MyInvocation…).
func pathResolver(lines []line) func(string) string {
	vars := map[string]string{}
	roots := map[string]bool{}
	for _, l := range lines {
		if m := rootDef.FindStringSubmatch(l.code); m != nil && !psJoinPath.MatchString(l.code) {
			roots[strings.ToLower(m[1])] = true
			continue
		}
		if m := psJoinPath.FindStringSubmatch(l.code); m != nil {
			var parts []string
			for _, q := range quotedPart.FindAllStringSubmatch(m[2], -1) {
				parts = append(parts, q[1])
			}
			if len(parts) > 0 {
				vars[strings.ToLower(m[1])] = strings.Join(parts, "/")
			}
			continue
		}
		if m := psStringVar.FindStringSubmatch(l.code); m != nil {
			vars[strings.ToLower(m[1])] = m[2]
		} else if m := shStringVar.FindStringSubmatch(l.code); m != nil {
			vars[strings.ToLower(m[1])] = m[2]
		}
	}
	return func(v string) string {
		v = strings.Trim(v, `"'@`)
		v = strings.TrimPrefix(strings.TrimPrefix(v, "fileb://"), "file://")
		if strings.HasPrefix(v, "$") {
			name := strings.ToLower(strings.Trim(strings.TrimPrefix(v, "$"), "{}"))
			if known, ok := vars[name]; ok {
				v = known
			}
		}
		v = scriptRoot.ReplaceAllString(v, "")
		// A variable that holds the script's own folder.
		if m := leadingVar.FindStringSubmatch(v); m != nil && roots[strings.ToLower(m[1])] {
			v = v[len(m[0]):]
		}
		return path.Clean(strings.ReplaceAll(v, `\`, "/"))
	}
}

// templateDeployments draws each template the script hands to the cloud.
func (s *scan) templateDeployments() {
	if s.f.Kind != source.Shell && s.f.Kind != source.PowerShell {
		return
	}
	lines := s.logicalLines()
	resolve := pathResolver(lines)

	for _, l := range lines {
		for _, d := range deployCmds {
			if !d.re.MatchString(l.code) {
				continue
			}
			file := ""
			for _, f := range d.flags {
				v, ok := azFlag(l.code, f)
				if !ok {
					v, ok = psParam(l.code, strings.TrimPrefix(f, "-"))
				}
				if ok && v != "" {
					file = resolve(v)
					break
				}
			}
			if file == "" || file == "." {
				file = "a template"
			}
			id := "deploy." + d.cloud + "." + file
			s.g.AddNode(&model.Node{ID: id, Name: file, Kind: "code", Friendly: "template it deploys, own picture",
				Code: "deploys " + file, Cloud: d.cloud, Type: "template deployment", Category: model.CloudCompute, File: s.f.Path, Line: l.n})
			s.g.Connect(s.me, id, "deploys", false)
			break
		}
	}
}
