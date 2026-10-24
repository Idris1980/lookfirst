// Command lookfirst shows what code would build or do, and what is risky
// about it, by reading the code without running it.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Idris1980/lookfirst/internal/analyze"
	"github.com/Idris1980/lookfirst/internal/render"
)

const usage = `lookfirst shows what code would build or do, and what is risky about it, without running it.

Usage:
  lookfirst read [--out report.html] [--open] [--format text|json|markdown|github]
                 [--fail-on high|medium|low|none] [--changed paths.txt] <file or folder>...
  lookfirst excerpt --line 42 [--context 15] <file>

read     reads Terraform, Bicep, ARM, docker-compose, Kubernetes, Dockerfile,
         Python, JavaScript/TypeScript, shell, PowerShell, package.json and
         requirements.txt.
excerpt  prints the lines around a line as JSON, with passwords and keys
         replaced by «SECRET_1» and so on. The VS Code extension uses it
         before it shows code to an AI model.

Nothing is sent anywhere.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "read":
		err = read(os.Args[2:])
	case "excerpt":
		err = excerpt(os.Args[2:])
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func read(args []string) error {
	fs := flag.NewFlagSet("read", flag.ExitOnError)
	out := fs.String("out", "", "where to write the HTML report (default lookfirst-report.html for text; other formats write one only when given)")
	open := fs.Bool("open", false, "open the report in the browser")
	format := fs.String("format", "text", "what to print: text, json, markdown or github (annotations for GitHub Actions)")
	failOn := fs.String("fail-on", "none", "exit with code 3 if there is a finding this severe or worse: high, medium, low or none")
	vscodeLinks := fs.Bool("vscode-links", false, "make boxes and findings in the report open the code in VS Code")
	changedList := fs.String("changed", "", "a file listing the paths a pull request changes, one per line: markdown shows their findings first, and --fail-on only counts them")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return fmt.Errorf("give a file or folder to read, for example: lookfirst read main.tf")
	}
	var changed map[string]bool
	if *changedList != "" {
		data, err := os.ReadFile(*changedList)
		if err != nil {
			return err
		}
		changed = map[string]bool{}
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				changed[filepath.ToSlash(l)] = true
			}
		}
	}
	printers := map[string]func([]render.Section) error{
		"text":     func(s []render.Section) error { render.Text(os.Stdout, s); return nil },
		"json":     func(s []render.Section) error { return render.JSON(os.Stdout, s) },
		"markdown": func(s []render.Section) error { render.Markdown(os.Stdout, s, changed); return nil },
		"github":   func(s []render.Section) error { render.GitHub(os.Stdout, s); return nil },
	}
	print, ok := printers[*format]
	if !ok {
		return fmt.Errorf("--format must be text, json, markdown or github")
	}
	threshold, ok := map[string]int{"high": 0, "medium": 1, "low": 2, "none": -1}[*failOn]
	if !ok {
		return fmt.Errorf("--fail-on must be high, medium, low or none")
	}

	projects, err := analyze.Paths(fs.Args())
	if err != nil {
		return err
	}
	sections := make([]render.Section, len(projects))
	for i, p := range projects {
		sections[i] = render.Section{Name: p.Name, Graph: p.Graph}
	}
	if err := print(sections); err != nil {
		return err
	}

	if *out == "" && *format == "text" {
		*out = "lookfirst-report.html"
	}
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		if err := render.HTML(f, sections, render.Options{VSCode: *vscodeLinks}); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		abs, _ := filepath.Abs(*out)
		if *format == "text" {
			fmt.Printf("\nReport: %s\n", abs)
		}
		if *open {
			if err := openFile(abs); err != nil {
				return err
			}
		}
	}

	// The exit code lets a pipeline stop on findings. The reports above are
	// written first, so the reason is always there to read.
	for _, p := range projects {
		for _, f := range p.Graph.Findings {
			// In a pull request, only what the change brings in can stop it.
			if changed != nil && !changed[filepath.ToSlash(f.File)] {
				continue
			}
			if int(f.Severity) <= threshold {
				fmt.Fprintf(os.Stderr, "lookfirst: stopping because of a %s finding (--fail-on %s)\n", f.Severity, *failOn)
				os.Exit(3)
			}
		}
	}
	return nil
}

func openFile(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	return cmd.Start()
}
