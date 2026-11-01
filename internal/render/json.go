package render

import (
	"encoding/json"
	"io"

	"github.com/Idris1980/lookfirst/internal/advice"
	"github.com/Idris1980/lookfirst/internal/explain"
	"github.com/Idris1980/lookfirst/internal/model"
)

type jsonFinding struct {
	Severity string      `json:"severity"`
	Title    string      `json:"title"`
	Detail   string      `json:"detail"`
	File     string      `json:"file"`
	Line     int         `json:"line"`
	Node     string      `json:"node,omitempty"`
	Project  string      `json:"project,omitempty"`
	Cloud    string      `json:"cloud,omitempty"`
	Advice   *jsonAdvice `json:"advice,omitempty"`
}

// jsonAdvice is what could happen, how to fix it, and official guidance
// for the cloud the finding is about.
type jsonAdvice struct {
	Story string       `json:"story"`
	Fix   []string     `json:"fix"`
	Refs  []advice.Ref `json:"refs"`
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
			jf := jsonFinding{Severity: f.Severity.String(), Title: f.Title, Detail: f.Detail, File: f.File, Line: f.Line,
				Node: f.NodeID, Project: s.Name, Cloud: s.Graph.CloudOf(f)}
			if a, ok := advice.For(f.Title); ok {
				jf.Advice = &jsonAdvice{a.Story, a.Fix, a.Refs(jf.Cloud)}
			}
			r.Findings = append(r.Findings, jf)
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
