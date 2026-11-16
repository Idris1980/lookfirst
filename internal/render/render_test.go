package render

import (
	"bytes"
	"fmt"
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
	out := vscode.String()
	if !strings.Contains(out, `href="command:lookFirst.reveal?`) {
		t.Error("the VS Code report has no links to the code")
	}
	if !strings.Contains(out, `href="command:lookFirst.explain?`) {
		t.Error("the VS Code report has no links to the AI explanation")
	}
	// The extension allows exactly these two commands in the picture.
	allowed := strings.Count(out, "command:lookFirst.reveal?") + strings.Count(out, "command:lookFirst.explain?")
	if strings.Count(out, "command:") != allowed {
		t.Error("the report links to a command other than lookFirst.reveal and lookFirst.explain")
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

func TestGitHubCommandsCannotBeInjected(t *testing.T) {
	g := &model.Graph{}
	g.Add(model.High, "", "Bad, title: x", "line one\n::set-env name=X::evil\r\n%0A", "dir/a,b:c.tf", 7)
	var buf bytes.Buffer
	GitHub(&buf, []Section{{Name: "x", Graph: g}})
	out := buf.String()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("one finding became several lines:\n%s", out)
	}
	if !strings.HasPrefix(out, "::error title=LookFirst%3A Bad%2C title%3A x,file=dir/a%2Cb%3Ac.tf,line=7::line one%0A::set-env") {
		t.Errorf("unexpected command:\n%s", out)
	}
	// The literal "%0A" in the text must stay text, not become a new line.
	if !strings.Contains(out, "%250A") {
		t.Errorf("percent signs in the text must be escaped too:\n%s", out)
	}
}

func TestMarkdownEscapesCode(t *testing.T) {
	g := &model.Graph{}
	g.Add(model.Medium, "", "Package name looks like a misspelling", `"![x](https://evil.example/p.png)" <img src=x>`, "package.json", 3)
	var buf bytes.Buffer
	Markdown(&buf, []Section{{Name: "x", Graph: g}}, nil)
	out := buf.String()
	// Escaped, the text is shown as written: \! \[ \( and \< are not syntax.
	if strings.Contains(out, "![x](") || strings.Contains(strings.ReplaceAll(out, `\<`, ""), "<img") {
		t.Errorf("markdown from the code was not escaped:\n%s", out)
	}
	if !strings.Contains(out, "0 high · 1 medium · 0 low") {
		t.Errorf("counts missing:\n%s", out)
	}
}

func TestMarkdownPutsTheChangeFirst(t *testing.T) {
	old := &model.Graph{}
	old.Add(model.High, "", "Old problem", "x", "examples/old.tf", 1)
	mine := &model.Graph{}
	mine.Add(model.High, "", "New problem", "y", "test-pr/main.tf", 14)
	var buf bytes.Buffer
	Markdown(&buf, []Section{{Name: "examples", Graph: old}, {Name: "test-pr", Graph: mine}}, map[string]bool{"test-pr/main.tf": true})
	out := buf.String()
	first, rest, _ := strings.Cut(out, "<details>")
	if !strings.Contains(first, "New problem") || strings.Contains(first, "Old problem") {
		t.Errorf("the pull request's own finding should come first, alone:\n%s", out)
	}
	if !strings.Contains(rest, "2 high") {
		t.Errorf("the folded part should count everything:\n%s", out)
	}
}

// The whole report is made, chain and review cards included, so a mistake
// in the template is found by the tests and not by a user.
func TestReportWithChainAndCards(t *testing.T) {
	g := &model.Graph{Sources: []string{"deploy.sh", "main.json"}}
	g.AddNode(&model.Node{ID: "app", Name: "app-1", Kind: "webapp", Friendly: "web app", Cloud: "azure", Type: "Microsoft.Web/sites", File: "main.json", Line: 3})
	g.AddNode(&model.Node{ID: "kv", Name: "kv-1", Kind: "key", Friendly: "key vault", Cloud: "azure", Type: "Microsoft.KeyVault/vaults", File: "main.json", Line: 9, Existing: true})
	g.ConnectKind("app", "kv", "reads secrets from", model.Flow)
	g.Add(model.Low, "app", "No HTTPS", "x", "main.json", 3)
	g.Steps = []model.Step{
		{File: "deploy.sh", Line: 1, Says: "Creates the resource group rg-1", Made: []string{"group|rg-1"}},
		{File: "deploy.sh", Line: 2, Says: "Hands the template main.json to Azure to build", Template: "main.json"},
		{File: "deploy.sh", Line: 3, Says: "Uploads the code", Changes: []string{"app"}, Needs: []string{"plan|plan-x"}},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, []Section{{Name: "x", Graph: g}}, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"What happens, step by step", "Creates the web app app-1", "Uses the existing key vault kv-1",
		`id="` + cardID("app") + `"`, `href="#` + cardID("app") + `"`, "plan-x", "Review card"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q", want)
		}
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

// A graph that knows what its lines mean is drawn along the flow: the
// internet first, then what it reaches and what that talks to. Lines that
// only give the order of creation, and hidden boxes, are left out.
func TestFlowPicture(t *testing.T) {
	g := &model.Graph{}
	g.AddNode(&model.Node{ID: "web", Name: "web", Category: model.Compute})
	g.AddNode(&model.Node{ID: "db", Name: "db", Category: model.Data})
	g.AddNode(&model.Node{ID: "plan", Name: "plan", Category: model.Compute})
	g.AddNode(&model.Node{ID: "role", Name: "role", Category: model.Security, Hidden: true})
	g.Expose("web", "HTTPS", false)
	g.ConnectKind("web", "db", "reads and writes data in", model.Flow)
	g.ConnectKind("web", "plan", "runs on", model.Hosting)
	g.ConnectKind("db", "plan", "", model.Order)
	g.ConnectKind("role", "db", "", model.Order)

	l := layout(g)
	if !l.flow {
		t.Fatal("want a flow picture")
	}
	col := func(id string) int { return l.pos[id].col }
	if col(model.InternetID) != 0 || col("web") != 1 || col("db") != 2 || col("plan") != 2 {
		t.Errorf("columns: internet %d, web %d, db %d, plan %d", col(model.InternetID), col("web"), col("db"), col("plan"))
	}
	if _, ok := l.pos["role"]; ok {
		t.Error("a hidden box was drawn")
	}
	for _, e := range l.edges {
		if e.Kind == model.Order {
			t.Errorf("an order line was drawn: %+v", e)
		}
	}

}

func TestWrapLabel(t *testing.T) {
	got := wrapLabel("keeps its state in · may use blobs (owner), queues, tables", 24)
	want := []string{"keeps its state in", "may use blobs (owner),", "queues, tables"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A network is drawn as frames: the VPC around its subnets, the servers in
// their subnet, the security groups' rules in the boxes, and arrows only
// for traffic, from the internet through the gateway, from your IP, and
// from one group of servers to another.
func TestNetworkPicture(t *testing.T) {
	g := &model.Graph{}
	add := func(id, kind, friendly, address string) {
		g.AddNode(&model.Node{ID: id, Name: id, Kind: kind, Friendly: friendly, Cloud: "aws", Address: address})
	}
	add("vpc", "network", "VPC in AWS", "10.0.0.0/16")
	add("public", "subnet", "subnet in AWS", "10.0.1.0/24")
	add("private", "subnet", "subnet in AWS", "10.0.2.0/24")
	add("igw", "globe", "internet gateway in AWS", "")
	add("web-sg", "shield", "security group in AWS", "")
	add("bastion-sg", "shield", "security group in AWS", "")
	add("db-sg", "shield", "security group in AWS", "")
	add("web", "vm", "EC2 server in AWS", "")
	add("bastion", "vm", "EC2 server in AWS", "")
	for _, e := range [][2]string{{"public", "vpc"}, {"private", "vpc"}, {"igw", "vpc"}, {"web-sg", "vpc"}, {"bastion-sg", "vpc"}, {"db-sg", "vpc"},
		{"web", "public"}, {"web", "web-sg"}, {"bastion", "public"}, {"bastion", "bastion-sg"}} {
		g.Connect(e[0], e[1], "", false)
	}
	g.Expose("web-sg", "port 80, port 443", false)
	g.ConnectKind(model.You, "bastion-sg", "port 22", model.Flow)
	g.ConnectKind("bastion-sg", "web-sg", "port 22", model.Flow)
	g.ConnectKind("web-sg", "db-sg", "port 3306", model.Flow)

	nv, ok := buildNetwork(g)
	if !ok {
		t.Fatal("want a network picture")
	}
	if nv.parent["public"] != "vpc" || nv.parent["web"] != "public" || nv.parent["bastion"] != "public" {
		t.Errorf("frames: %v", nv.parent)
	}
	for _, sg := range []string{"web-sg", "bastion-sg"} {
		if _, drawn := nv.byID[sg]; drawn {
			t.Errorf("%s protects a server and should be written in its box, not drawn", sg)
		}
	}
	if _, drawn := nv.byID["db-sg"]; !drawn {
		t.Error("a security group that protects nothing yet should be a box of its own")
	}
	want := map[[2]string]string{
		{model.InternetID, "igw"}: "80, 443", {"igw", "web"}: "80, 443",
		{model.You, "igw"}: "22", {"igw", "bastion"}: "22",
		{"bastion", "web"}: "22", {"web", "db-sg"}: "3306",
	}
	got := map[[2]string]string{}
	for _, a := range nv.arrows {
		got[[2]string{a.from, a.to}] = a.label
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("arrow %s -> %s: got %q, want %q (all: %v)", k[0], k[1], got[k], v, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("arrows: %v", got)
	}
	notes := strings.Join(nv.byID["web"].notes, "|")
	if !strings.Contains(notes, "80, 443 from anyone") || !strings.Contains(notes, "22 from bastion-sg") {
		t.Errorf("web's rules: %q", notes)
	}

	var buf bytes.Buffer
	if err := HTML(&buf, []Section{{Name: "v44", Graph: g}}, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `class="frame vnet aws"`) || !strings.Contains(buf.String(), "svg:has(.n0:hover)") {
		t.Error("the report should draw the VPC as a frame and light up on hover")
	}
}
