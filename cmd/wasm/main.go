//go:build js && wasm

// Command wasm is LookFirst for the web page. It runs in the visitor's
// browser and only reads what the page hands it: nothing is fetched and
// nothing is sent anywhere.
//
// The page calls one function:
//
//	lookfirstRead('[{"name": "infra/main.tf", "text": "..."}]')
//
// and gets back JSON: {"html": "<the report>", "error": "..."}.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"syscall/js"

	"github.com/Idris1980/lookfirst/internal/analyze"
	"github.com/Idris1980/lookfirst/internal/render"
	"github.com/Idris1980/lookfirst/internal/source"
)

type input struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

func main() {
	js.Global().Set("lookfirstRead", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 1 {
			return reply("", "lookfirstRead takes one argument")
		}
		html, err := read(args[0].String())
		if err != nil {
			return reply("", err.Error())
		}
		return reply(html, "")
	}))
	js.Global().Set("lookfirstGuessName", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 1 {
			return ""
		}
		return source.GuessName(args[0].String())
	}))
	select {} // keep the functions available to the page
}

func read(raw string) (string, error) {
	var inputs []input
	if err := json.Unmarshal([]byte(raw), &inputs); err != nil {
		return "", fmt.Errorf("could not read the request: %v", err)
	}
	if len(inputs) > source.MaxFiles {
		return "", fmt.Errorf("more than %d files; choose a smaller folder", source.MaxFiles)
	}

	var files []source.File
	var skipped []string
	for _, in := range inputs {
		name := path.Clean("/" + strings.ReplaceAll(in.Name, "\\", "/"))[1:]
		if len(in.Text) > source.MaxFileSize {
			skipped = append(skipped, name)
			continue
		}
		if k := source.Detect(name, []byte(in.Text)); k != "" {
			files = append(files, source.File{Path: name, Kind: k, Data: []byte(in.Text)})
		}
	}
	if len(files) == 0 {
		if len(skipped) > 0 {
			return "", fmt.Errorf("the files are larger than %d MiB", source.MaxFileSize>>20)
		}
		return "", analyze.ErrNothing
	}

	projects := analyze.Group(files)
	sections := make([]render.Section, len(projects))
	for i, p := range projects {
		sections[i] = render.Section{Name: p.Name, Graph: p.Graph}
	}
	var buf bytes.Buffer
	if err := render.HTML(&buf, sections, render.Options{}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func reply(html, errText string) string {
	b, _ := json.Marshal(map[string]string{"html": html, "error": errText})
	return string(b)
}
