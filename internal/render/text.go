package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Idris1980/lookfirst/internal/explain"
	"github.com/Idris1980/lookfirst/internal/model"
)

// Text writes a short report for the terminal, one block per project.
func Text(w io.Writer, sections []Section) {
	for i, s := range sections {
		if len(sections) > 1 {
			if i > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "== %s ==\n", s.Name)
		}
		text(w, s.Graph)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, explain.Disclaimer)
}

func text(w io.Writer, g *model.Graph) {
	for _, s := range explain.Summary(g) {
		fmt.Fprintln(w, s)
	}
	if len(g.Findings) > 0 {
		fmt.Fprintln(w)
	}
	for _, f := range g.Findings {
		where := f.File
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "  %-6s %s\n         %s\n", strings.ToUpper(f.Severity.String()), f.Title, where)
	}
}
