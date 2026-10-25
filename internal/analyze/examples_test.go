package analyze

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
	"github.com/Idris1980/lookfirst/internal/source"
)

// Each example must keep finding what it was written to show. A change
// that loses one of these has made LookFirst miss a real risk.
var expectations = []struct {
	dir     string
	want    []string // finding titles that must be there
	notWant []string // titles that must not be there
	bicep   bool     // needs the Bicep compiler
}{
	{dir: "azure-vm", want: []string{
		"SSH (port 22) is open to the internet",
		"Password or key written in the code",
		"Password login is allowed",
		"Web traffic (port 80) is allowed from the internet",
	}},
	{dir: "azure-webapp-sql", want: []string{
		"Password has a default value in the code",
		"Database open to the whole internet",
		"Files can be made public",
		"Files are public",
		"Old TLS version allowed",
	}},
	{dir: "aws-ec2", want: []string{
		"Secret written in the code",
		"Every port is open to the internet",
		"Database reachable from the internet",
		"Bucket is public",
		"Private key is saved in the Terraform state",
	}},
	{dir: "bicep", bicep: true, want: []string{
		"Password has a default value in the code",
		"Files can be made public",
		"Database open to the whole internet",
	}},
	{dir: "compose", want: []string{
		"Sensitive host folder is mounted",
		"PostgreSQL is published on every network interface",
		"Container runs privileged",
		"Image version is not pinned",
		"Database admin panel is published on every network interface",
	}, notWant: []string{
		"Redis (port 6379) is published on every network interface", // bound to 127.0.0.1
	}},
	{dir: "kubernetes", want: []string{
		"Container runs privileged",
		"SSH (port 22) is open to the internet",
		"Secret values are stored in the file",
		"No HTTPS",
	}},
	{dir: "python-helper", want: []string{
		"Reads secrets and talks to the internet",
		"Talks to a suspicious service",
		"Makes something start automatically",
		"Debug mode is on",
		"Downloads code and runs it",
		`Package name looks like a misspelling of "requests"`,
		"Certificate checks are turned off",
	}, notWant: []string{
		"Hidden code is decoded and run", // only in a comment
	}},
	{dir: "node-api", want: []string{
		"Password or key written in the code",
		"SQL built from text",
		"Command built from text",
		"Opens port 3000 to the network",
	}, notWant: []string{
		"Runs text as code", // exec() in Node runs a program, not code
	}},
	{dir: "setup-scripts", want: []string{
		"Downloads code and runs it",
		"Turns off security protection",
		"SSH (port 22) is open to the internet",
		"Can delete everything",
		"Makes something start automatically",
		"PowerShell safety check is bypassed",
		"Container runs as root",
		`Package name looks like a misspelling of "express"`,
	}},
	{dir: "packages", want: []string{
		"Runs a download or shell command when installed",
		`Package name looks like a misspelling of "axios"`,
		`Package name looks like a misspelling of "beautifulsoup4"`,
		"Package installed straight from an address",
		"Packages may come from another server",
	}},
}

func TestExamples(t *testing.T) {
	for _, e := range expectations {
		t.Run(e.dir, func(t *testing.T) {
			if e.bicep && !hasBicep() {
				t.Skip("no Bicep compiler on this machine")
			}
			projects, err := Paths([]string{filepath.Join("..", "..", "examples", e.dir)})
			if err != nil {
				t.Fatal(err)
			}
			titles := map[string]bool{}
			for _, f := range Merge(projects).Findings {
				titles[f.Title] = true
			}
			for _, w := range e.want {
				if !titles[w] {
					t.Errorf("missing finding %q", w)
				}
			}
			for _, w := range e.notWant {
				if titles[w] {
					t.Errorf("unexpected finding %q", w)
				}
			}
		})
	}
}

// TestSafeCode checks that code written the right way gives no high or
// medium findings. Each case here was once a false alarm.
func TestSafeCode(t *testing.T) {
	projects, err := Paths([]string{filepath.Join("testdata", "safe")})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Merge(projects).Findings {
		if f.Severity != model.Low {
			t.Errorf("%s:%d: false alarm %q (%s)", filepath.Base(f.File), f.Line, f.Title, f.Detail)
		}
	}
}

func TestProjectsPerFolder(t *testing.T) {
	projects, err := Paths([]string{filepath.Join("..", "..", "examples")})
	if err != nil {
		t.Fatal(err)
	}
	if len(projects) != len(expectations) {
		t.Fatalf("got %d projects, want one per example folder (%d)", len(projects), len(expectations))
	}
	for _, p := range projects {
		if strings.Contains(p.Name, `\`) {
			t.Errorf("project name %q should use forward slashes", p.Name)
		}
	}
}

// TestMaskHidesEverySecret masks every example file, as the extension does
// before code is shown to an AI model, and reads the masked files again.
// None of the secrets LookFirst finds may still be there.
func TestMaskHidesEverySecret(t *testing.T) {
	secretTitles := map[string]bool{
		"Secret written in the code":               true,
		"Password or key written in the code":      true,
		"Password has a default value in the code": true,
	}
	files, _, err := source.Collect([]string{filepath.Join("..", "..", "examples")})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var masked []string
	for i, f := range files {
		if f.Kind == source.Bicep {
			continue // needs a compiler; its secrets are covered by the ARM rules
		}
		out, _ := risk.Mask(string(f.Data))
		sub := filepath.Join(dir, fmt.Sprint(i))
		if err := os.MkdirAll(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(sub, filepath.Base(f.Path))
		if err := os.WriteFile(p, []byte(out), 0o600); err != nil {
			t.Fatal(err)
		}
		masked = append(masked, p)
	}
	projects, err := Paths(masked)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range Merge(projects).Findings {
		if secretTitles[f.Title] {
			t.Errorf("a secret survived masking in %s:%d: %s", filepath.Base(f.File), f.Line, f.Detail)
		}
	}
}

func hasBicep() bool {
	if _, err := exec.LookPath("bicep"); err == nil {
		return true
	}
	_, err := exec.LookPath("az")
	return err == nil
}
