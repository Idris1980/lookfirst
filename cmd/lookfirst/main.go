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

	"github.com/Idris1980/lookfirst/internal/analyze"
	"github.com/Idris1980/lookfirst/internal/render"
)

const usage = `lookfirst shows what code would build or do, and what is risky about it, without running it.

Usage:
  lookfirst read [--out report.html] [--open] [--format text|json] <file or folder>...

Reads Terraform, Bicep, ARM, docker-compose, Kubernetes, Dockerfile, Python,
JavaScript/TypeScript, shell and PowerShell. Nothing is sent anywhere.
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
	out := fs.String("out", "", "where to write the HTML report (default lookfirst-report.html; with --format json, no report unless given)")
	open := fs.Bool("open", false, "open the report in the browser")
	format := fs.String("format", "text", "what to print: text or json")
	vscodeLinks := fs.Bool("vscode-links", false, "make boxes and findings in the report open the code in VS Code")
	fs.Parse(args)
	if fs.NArg() == 0 {
		return fmt.Errorf("give a file or folder to read, for example: lookfirst read main.tf")
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("--format must be text or json")
	}

	g, err := analyze.Paths(fs.Args())
	if err != nil {
		return err
	}
	if *format == "json" {
		if err := render.JSON(os.Stdout, g); err != nil {
			return err
		}
	} else {
		render.Text(os.Stdout, g)
	}

	if *out == "" && *format == "json" {
		return nil
	}
	if *out == "" {
		*out = "lookfirst-report.html"
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	if err := render.HTML(f, g, render.Options{VSCode: *vscodeLinks}); err != nil {
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
		return openFile(abs)
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
