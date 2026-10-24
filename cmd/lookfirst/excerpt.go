package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Idris1980/lookfirst/internal/risk"
	"github.com/Idris1980/lookfirst/internal/source"
)

// excerpt prints the lines around one line of a file, masked, as JSON:
//
//	{"start": 27, "end": 57, "line": 42, "text": "...", "secrets": {"«SECRET_1»": "..."}}
//
// The secrets map lets the caller put the real values back into a suggested
// fix on this machine; only "text" is meant to be shown to an AI model.
func excerpt(args []string) error {
	fs := flag.NewFlagSet("excerpt", flag.ExitOnError)
	line := fs.Int("line", 0, "the line the excerpt is about, counting from 1")
	context := fs.Int("context", 15, "how many lines to include before and after it")
	fs.Parse(args)
	if fs.NArg() != 1 || *line < 1 || *context < 0 {
		return fmt.Errorf("usage: lookfirst excerpt --line 42 [--context 15] file")
	}
	path := fs.Arg(0)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Size() > source.MaxFileSize {
		return fmt.Errorf("%s is larger than %d MiB", path, source.MaxFileSize>>20)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	at := min(*line, len(lines))
	start := max(1, at-*context)
	end := min(len(lines), at+*context)
	text, secrets := risk.Mask(strings.Join(lines[start-1:end], "\n"))

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Start   int               `json:"start"`
		End     int               `json:"end"`
		Line    int               `json:"line"`
		Text    string            `json:"text"`
		Secrets map[string]string `json:"secrets"`
	}{start, end, at, text, secrets})
}
