package render

import (
	"encoding/json"
	"io"

	"github.com/Idris1980/lookfirst/internal/explain"
	"github.com/Idris1980/lookfirst/internal/model"
)

type jsonFinding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Node     string `json:"node,omitempty"`
}

type jsonReport struct {
	Summary    []string       `json:"summary"`
	Disclaimer string         `json:"disclaimer"`
	Counts     map[string]int `json:"counts"`
	Sources    []string       `json:"sources"`
	Findings   []jsonFinding  `json:"findings"`
}

// JSON writes the findings for tools such as the VS Code extension.
func JSON(w io.Writer, g *model.Graph) error {
	r := jsonReport{
		Summary:    explain.Summary(g),
		Disclaimer: explain.Disclaimer,
		Counts:     map[string]int{"high": 0, "medium": 0, "low": 0},
		Sources:    g.Sources,
		Findings:   []jsonFinding{},
	}
	for _, f := range g.Findings {
		r.Counts[f.Severity.String()]++
		r.Findings = append(r.Findings, jsonFinding{f.Severity.String(), f.Title, f.Detail, f.File, f.Line, f.NodeID})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
