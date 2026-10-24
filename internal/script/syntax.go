package script

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/source"
)

// syntax asks the language's own parser, if it is installed, whether the
// file can be read at all. Every command here only parses: none of them
// runs the code. If no parser is found, the check is skipped quietly.
func syntax(g *model.Graph, f source.File) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch f.Kind {
	case source.Python:
		py := firstFound("python3", "python", "py")
		if py == "" {
			return
		}
		cmd = exec.CommandContext(ctx, py, "-I", "-c",
			"import ast,sys\ntry:\n ast.parse(open(sys.argv[1],'rb').read(),sys.argv[1])\nexcept SyntaxError as e:\n print('LINE',e.lineno,e.msg)",
			f.Path)
	case source.JavaScript:
		ext := strings.ToLower(filepath.Ext(f.Path))
		if ext != ".js" && ext != ".mjs" && ext != ".cjs" {
			return // TypeScript and JSX need a compiler, not just node
		}
		node := firstFound("node")
		if node == "" {
			return
		}
		cmd = exec.CommandContext(ctx, node, "--check", f.Path)
	case source.Shell:
		bash := firstFound("bash")
		if bash == "" {
			return
		}
		cmd = exec.CommandContext(ctx, bash, "-n", f.Path)
	case source.PowerShell:
		pwsh := firstFound("pwsh", "powershell")
		if pwsh == "" {
			return
		}
		// The path goes in through the environment, never into the command text.
		cmd = exec.CommandContext(ctx, pwsh, "-NoProfile", "-NonInteractive", "-Command",
			`$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:LOOKFIRST_FILE,[ref]$null,[ref]$e); foreach($x in $e){ 'LINE {0} {1}' -f $x.Extent.StartLineNumber, $x.Message }`)
		cmd.Env = append(os.Environ(), "LOOKFIRST_FILE="+f.Path)
	default:
		return
	}

	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	text := out.String()
	if ctx.Err() != nil {
		return
	}

	add := func(ln int, msg string) {
		g.Add(model.High, "script."+f.Path, "Syntax error",
			"The code cannot run as written: "+strings.TrimSpace(msg)+". AI-generated code often has small mistakes like this; fix it before running.", f.Path, ln)
	}
	switch f.Kind {
	case source.Python, source.PowerShell:
		for _, m := range lineMsg.FindAllStringSubmatch(text, 5) {
			n, _ := strconv.Atoi(m[1])
			add(n, m[2])
		}
	case source.JavaScript:
		if err == nil {
			return
		}
		// node prints "file:LINE", the code, a caret, then "SyntaxError: ...".
		n := 0
		if m := nodeLine.FindStringSubmatch(text); m != nil {
			n, _ = strconv.Atoi(m[1])
		}
		if m := syntaxErr.FindStringSubmatch(text); m != nil {
			add(n, m[1])
		}
	case source.Shell:
		if err == nil {
			return
		}
		for _, m := range bashLine.FindAllStringSubmatch(text, 5) {
			n, _ := strconv.Atoi(m[1])
			add(n, m[2])
		}
	}
}

var (
	lineMsg   = regexp.MustCompile(`(?m)^LINE (\d+) (.+)$`)
	nodeLine  = regexp.MustCompile(`(?m):(\d+)\r?$`)
	syntaxErr = regexp.MustCompile(`(?m)^SyntaxError: (.+)$`)
	bashLine  = regexp.MustCompile(`(?m)line (\d+): (.+)$`)
)

// firstFound returns the first of the programs that is on the PATH. The
// Windows Store "python" stub is skipped, since it only opens the Store.
func firstFound(names ...string) string {
	for _, n := range names {
		p, err := exec.LookPath(n)
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(p), `microsoft\windowsapps`) {
			continue
		}
		return p
	}
	return ""
}
