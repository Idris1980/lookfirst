package script

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/source"
)

func TestPipInstallArgs(t *testing.T) {
	cases := map[string][]string{
		"requests flask==3.0":                       {"requests", "flask"},
		"-r requirements.txt":                       nil,
		"--upgrade pip -r reqs/dev.txt numpy>=1.26": {"pip", "numpy"},
		"-e . pandas[excel]":                        {"pandas"},
		"--index-url https://example.com/simple x":  {"x"},
		"./local.whl":                               nil,
	}
	for in, want := range cases {
		if got := PipInstallArgs(in); !reflect.DeepEqual(got, want) {
			t.Errorf("PipInstallArgs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNpmInstallArgs(t *testing.T) {
	cases := []struct {
		in   string
		npx  bool
		want []string
	}{
		{"express axios@1.7.0 --save", false, []string{"express", "axios"}},
		{"-D @types/node@20", false, []string{"@types/node"}},
		{"--yes @vscode/vsce@3.6.0 package --target win32-x64", true, []string{"@vscode/vsce"}},
		{"create-react-app my-app", true, []string{"create-react-app"}},
		{"./local-folder", false, nil},
	}
	for _, c := range cases {
		if got := NpmInstallArgs(c.in, c.npx); !reflect.DeepEqual(got, c.want) {
			t.Errorf("NpmInstallArgs(%q, %v) = %q, want %q", c.in, c.npx, got, c.want)
		}
	}
}

func TestLookalike(t *testing.T) {
	for name, want := range map[string]string{"reqeusts": "requests", "axois": "axios", "expresss": "express", "beautifulsup4": "beautifulsoup4"} {
		got, ok := lookalike(name, map[string]bool{want: true})
		if !ok || got != want {
			t.Errorf("lookalike(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"requests", "python_dateutil", "flask-cors", "abc"} {
		if like, ok := lookalike(name, pythonPopular); ok {
			t.Errorf("lookalike(%q) = %q, want no match", name, like)
		}
	}
}

// An install script as AI assistants write it: every risk is on its own line.
func TestInstallScript(t *testing.T) {
	sh := `#!/bin/bash
sudo apt-get update && sudo apt-get upgrade -y
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
rm get-docker.sh
sudo usermod -aG docker $USER
`
	g := Read([]source.File{{Path: "setup.sh", Kind: source.Shell, Data: []byte(sh)}})
	got := map[string][]int{}
	for _, f := range g.Findings {
		got[f.Title] = append(got[f.Title], f.Line)
	}
	want := map[string][]int{
		"Downloads code and runs it":                    {3, 5},
		"User can take over the machine through Docker": {7},
		"Runs with admin rights":                        {2},
	}
	for title, lines := range want {
		if !reflect.DeepEqual(got[title], lines) {
			t.Errorf("%q on lines %v, want %v", title, got[title], lines)
		}
	}
	for _, p := range []string{"bash", "sh", "apt-get", "usermod"} {
		if g.Node("program."+p) == nil {
			t.Errorf("the picture is missing the program %q", p)
		}
	}
	if g.Node("program.-E") != nil {
		t.Error(`sudo's option -E was taken for a program`)
	}

	// The shebang alone does not run bash.
	g = Read([]source.File{{Path: "a.sh", Kind: source.Shell, Data: []byte("#!/bin/bash\necho hi\n")}})
	if g.Node("program.bash") != nil {
		t.Error("the shebang was taken for running bash")
	}
}

func TestStripComments(t *testing.T) {
	cases := []struct {
		kind      source.Kind
		in        string
		keep, cut string
	}{
		{source.Python, "x = '#not a comment'  # real comment\n", "#not a comment", "real comment"},
		{source.Python, "s = \"\"\"doc # kept\"\"\"\n# gone\n", "doc # kept", "gone"},
		{source.JavaScript, "const u = 'http://x.com'; // gone\n/* gone too */ y()\n", "http://x.com", "gone"},
		{source.Shell, "echo \"a # b\" # gone\necho $#\n", "a # b", "gone"},
		{source.PowerShell, "<# gone\nstill gone #>\nWrite-Host 'x # kept'\n", "x # kept", "gone"},
	}
	for _, c := range cases {
		out := string(stripComments([]byte(c.in), c.kind))
		if !strings.Contains(out, c.keep) {
			t.Errorf("%s: %q lost %q: %q", c.kind, c.in, c.keep, out)
		}
		if strings.Contains(out, c.cut) {
			t.Errorf("%s: %q kept comment %q: %q", c.kind, c.in, c.cut, out)
		}
		if strings.Count(out, "\n") != strings.Count(c.in, "\n") {
			t.Errorf("%s: line count changed", c.kind)
		}
	}
}
