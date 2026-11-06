// Package render shows a graph to a person: as a self-contained HTML report,
// as text in the terminal, or as JSON for the VS Code extension.
package render

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"path/filepath"
	"sort"

	"github.com/Idris1980/lookfirst/internal/advice"
	"github.com/Idris1980/lookfirst/internal/chain"
	"github.com/Idris1980/lookfirst/internal/explain"
	"github.com/Idris1980/lookfirst/internal/model"
)

// The report contains no JavaScript and loads nothing from the network. Its
// Content-Security-Policy makes the browser enforce that, so a malicious
// resource name in the input cannot turn into a script either.
//
//go:embed report.html
var reportHTML string

var report = template.Must(template.New("report").Parse(reportHTML))

type finding struct {
	Sev, Title, Detail, Where, Node string
	Href                            template.URL
	Explain                         template.URL // asks the AI model, in VS Code only
	// From the advice package: what could happen, how to fix it, and
	// official guidance for the cloud the finding is about.
	Story string
	Fix   []string
	Refs  []advice.Ref
}

// item is one thing in the full list of what the code creates.
type item struct {
	Name, What, Type, Where, Sev string
	Href                         template.URL
	Count                        int
	Card                         string // the anchor of its review card
}

type itemGroup struct {
	Title string
	Items []item
}

// Options change how the report is made.
type Options struct {
	// VSCode makes boxes and findings links that open the code in VS Code.
	// The links are command: URIs that only VS Code acts on, so the page
	// still needs no JavaScript.
	VSCode bool
	// Overview replaces the overview's opening text, and keeps the sections
	// in the order given instead of putting the riskiest first. lookfirst try
	// uses it for its fixed order: the difference, the code, Azure.
	Overview []string
}

// reveal returns a link that opens file at line in VS Code.
func reveal(opt Options, file string, line int) template.URL {
	return command(opt, "lookFirst.reveal", file, line)
}

// explainLink returns a link that asks the AI model in VS Code to explain a
// finding and suggest a fix. The extension shows what would be sent first.
func explainLink(opt Options, f model.Finding) template.URL {
	return command(opt, "lookFirst.explain", f.File, f.Line, f.Title, f.Detail)
}

func command(opt Options, name, file string, rest ...any) template.URL {
	if !opt.VSCode || file == "" {
		return ""
	}
	if abs, err := filepath.Abs(file); err == nil {
		file = abs
	}
	args, _ := json.Marshal(append([]any{file}, rest...))
	// The command names and arguments are ours, and the arguments are
	// percent-encoded, so nothing from the input can change the link.
	return template.URL("command:" + name + "?" + url.PathEscape(string(args)))
}

// Section is one project in a report: a name and what was found there.
type Section struct {
	Name  string
	Graph *model.Graph
}

type project struct {
	Name, Anchor string
	Summary      []string
	Findings     []finding
	Counts       map[string]int
	Inventory    []itemGroup // everything the code creates or uses
	Total        int
	NotRead      []string // files in the folders that LookFirst did not read
}

type page struct {
	Sources    []string
	Overall    []string // a summary across projects, when there are several
	Disclaimer string
	Counts     map[string]int
	Projects   []project
	Multi      bool
	// Chains are what happens, step by step, when the code is run.
	Chains []chainView
	// Cards are the review cards that a click on something the code
	// creates opens, in the chain or in the list of everything.
	Cards []reviewCard
	// Knowledge says how current LookFirst's lists of Azure and AWS
	// resource types are.
	Knowledge string
}

// HTML writes the report. With several sections, the riskiest project
// comes first and an overview at the top links to each one.
func HTML(w io.Writer, sections []Section, opt Options) error {
	p := page{Disclaimer: explain.Disclaimer, Counts: map[string]int{}, Multi: len(sections) > 1}
	all := &model.Graph{}
	for _, s := range sections {
		all.Merge(s.Graph)
		p.Projects = append(p.Projects, buildProject(s, opt))
	}
	p.Sources = all.Sources
	all.Sort()
	p.Chains = chainViews(all, opt)
	p.Cards = reviewCards(all, chain.Build(all), opt)
	p.Knowledge = knowledgeLine()
	for _, f := range all.Findings {
		p.Counts[f.Severity.String()]++
	}
	if p.Multi && opt.Overview != nil {
		p.Overall = opt.Overview
	} else if p.Multi {
		p.Overall = []string{fmt.Sprintf("%d folders with code were read. What happens step by step is above; each folder's findings and everything it creates follow below, the riskiest first.", len(sections))}
		sort.SliceStable(p.Projects, func(i, j int) bool {
			a, b := p.Projects[i].Counts, p.Projects[j].Counts
			if a["high"] != b["high"] {
				return a["high"] > b["high"]
			}
			if a["medium"] != b["medium"] {
				return a["medium"] > b["medium"]
			}
			return a["low"] > b["low"]
		})
	}
	for i := range p.Projects {
		p.Projects[i].Anchor = fmt.Sprintf("project-%d", i+1)
	}
	return report.Execute(w, p)
}

func buildProject(s Section, opt Options) project {
	g := s.Graph
	p := project{Name: s.Name, Summary: explain.Summary(g), Counts: map[string]int{}}

	for _, f := range g.Findings {
		where := f.File
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		// Name the box the finding belongs to, unless it is just the file itself.
		box := ""
		if n := g.Node(f.NodeID); n != nil && n.Name != filepath.Base(f.File) {
			box = n.Name
		}
		fd := finding{Sev: f.Severity.String(), Title: f.Title, Detail: f.Detail, Where: where, Node: box,
			Href: reveal(opt, f.File, f.Line), Explain: explainLink(opt, f)}
		if a, ok := advice.For(f.Title); ok {
			fd.Story, fd.Fix, fd.Refs = a.Story, a.Fix, a.Refs(g.CloudOf(f))
		}
		p.Findings = append(p.Findings, fd)
		p.Counts[f.Severity.String()]++
	}
	p.Inventory, p.Total = inventory(g, opt)
	p.NotRead = g.NotRead
	return p
}

// inventory lists everything the code creates or uses, by kind, each with
// a link to its review card.
func inventory(g *model.Graph, opt Options) ([]itemGroup, int) {
	var groups []itemGroup
	total := 0
	for _, c := range g.Columns() {
		var items []item
		for _, n := range g.Nodes {
			if n.Category != c || n.ID == model.InternetID || n.Type == "principal" || n.Type == "resource group" {
				continue
			}
			it := item{Name: n.Name, What: n.Friendly, Type: n.Type, Href: reveal(opt, n.File, n.Line)}
			if hasCard(n.ID) {
				it.Card = cardID(n.ID)
			}
			if n.Existing {
				it.What += " (already there; only used)"
			}
			if it.Type == "" {
				it.Type = n.Code
			}
			if n.File != "" {
				it.Where = fmt.Sprintf("%s:%d", n.File, n.Line)
			}
			if sev, ok := g.Worst(n.ID); ok {
				it.Sev = sev.String()
				for _, f := range g.Findings {
					if f.NodeID == n.ID {
						it.Count++
					}
				}
			}
			items = append(items, it)
		}
		if len(items) > 0 {
			groups = append(groups, itemGroup{Title: g.Title(c), Items: items})
			total += len(items)
		}
	}
	return groups, total
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
