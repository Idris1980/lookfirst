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
	Project  string `json:"project,omitempty"`
}

type jsonProject struct {
	Name    string         `json:"name"`
	Summary []string       `json:"summary"`
	Counts  map[string]int `json:"counts"`
}

type jsonReport struct {
	Summary    []string       `json:"summary"`
	Disclaimer string         `json:"disclaimer"`
	Counts     map[string]int `json:"counts"`
	Sources    []string       `json:"sources"`
	Projects   []jsonProject  `json:"projects"`
	Findings   []jsonFinding  `json:"findings"`
}

// JSON writes the findings for tools such as the VS Code extension. The
// top-level summary, counts and findings cover every project together.
func JSON(w io.Writer, sections []Section) error {
	all := &model.Graph{}
	r := jsonReport{
		Disclaimer: explain.Disclaimer,
		Counts:     counts(nil),
		Findings:   []jsonFinding{},
	}
	for _, s := range sections {
		all.Merge(s.Graph)
		r.Projects = append(r.Projects, jsonProject{s.Name, explain.Summary(s.Graph), counts(s.Graph.Findings)})
		for _, f := range s.Graph.Findings {
			r.Counts[f.Severity.String()]++
			r.Findings = append(r.Findings, jsonFinding{f.Severity.String(), f.Title, f.Detail, f.File, f.Line, f.NodeID, s.Name})
		}
	}
	r.Summary = explain.Summary(all)
	r.Sources = all.Sources
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func counts(findings []model.Finding) map[string]int {
	c := map[string]int{"high": 0, "medium": 0, "low": 0}
	for _, f := range findings {
		c[f.Severity.String()]++
	}
	return c
}
