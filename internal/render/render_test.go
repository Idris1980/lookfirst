package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/model"
)

// hostile is a graph whose names come from a malicious file.
func hostile() *model.Graph {
	g := &model.Graph{Sources: []string{"evil.tf"}}
	g.AddNode(&model.Node{ID: "a", Name: `<script>alert(1)</script>`, Friendly: `"><img src=x onerror=alert(1)>`,
		Code: `</text><script>x()</script>`, Kind: "vm", Category: model.Compute, File: "evil.tf", Line: 3})
	g.Add(model.High, "a", `<b onmouseover=alert(1)>title</b>`, `javascript:alert(1)`, "evil.tf", 3)
	return g
}

func TestHTMLHasNoScripts(t *testing.T) {
	for _, opt := range []Options{{}, {VSCode: true}} {
		var buf bytes.Buffer
		if err := HTML(&buf, []Section{{Name: "evil", Graph: hostile()}}, opt); err != nil {
			t.Fatal(err)
		}
		out := strings.ToLower(buf.String())
		// The hostile text may appear, but only escaped, so never as a tag
		// or an attribute the browser would act on.
		for _, bad := range []string{"<script", "<img", "<b ", `href="javascript:`} {
			if strings.Contains(out, bad) {
				t.Errorf("VSCode=%v: report contains %q", opt.VSCode, bad)
			}
		}
		if !strings.Contains(out, "default-src 'none'") {
			t.Error("report lost its Content-Security-Policy")
		}
	}
}

func TestLinksOnlyForVSCode(t *testing.T) {
	var plain, vscode bytes.Buffer
	HTML(&plain, []Section{{Name: "x", Graph: hostile()}}, Options{})
	HTML(&vscode, []Section{{Name: "x", Graph: hostile()}}, Options{VSCode: true})
	if strings.Contains(plain.String(), "command:") {
		t.Error("a browser report contains command links")
	}
	if !strings.Contains(vscode.String(), `href="command:lookFirst.reveal?`) {
		t.Error("the VS Code report has no links to the code")
	}
	if strings.Contains(vscode.String(), "command:") && strings.Count(vscode.String(), "command:") != strings.Count(vscode.String(), "command:lookFirst.reveal?") {
		t.Error("the report links to a command other than lookFirst.reveal")
	}
}

func TestOverviewOnlyForSeveralProjects(t *testing.T) {
	var one, two bytes.Buffer
	HTML(&one, []Section{{Name: "a", Graph: hostile()}}, Options{})
	HTML(&two, []Section{{Name: "a", Graph: hostile()}, {Name: "b", Graph: &model.Graph{}}}, Options{})
	if strings.Contains(one.String(), "<h2>Overview</h2>") {
		t.Error("one project got an overview")
	}
	if !strings.Contains(two.String(), "<h2>Overview</h2>") || !strings.Contains(two.String(), `href="#project-2"`) {
		t.Error("two projects got no overview with links")
	}
}

func TestClipCode(t *testing.T) {
	if got := clipCode("azurerm_linux_virtual_machine.main", 25); !strings.HasSuffix(got, ".main") || len([]rune(got)) != 25 {
		t.Errorf("clipCode kept the wrong part: %q", got)
	}
	if got := clipCode("services.web", 25); got != "services.web" {
		t.Errorf("clipCode changed a short name: %q", got)
	}
}
