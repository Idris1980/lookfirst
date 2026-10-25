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
	"strings"

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

const (
	nodeW, nodeH = 184, 60
	colGap       = 68
	rowGap       = 26
	padX, padY   = 24, 80
	maxRows      = 12 // more than this in one column is folded into "+N more"
)

// quietLabel are line labels too common to be worth drawing.
var quietLabel = map[string]bool{"uses": true, "connects": true, "installs": true}

type svgNode struct {
	X, Y, W, H     int
	Name, Friendly string
	Tooltip        string
	Icon           template.HTML
	Code           string
	Cat, Sev       string
	Count          int
	Href           template.URL // where a click goes, or "" outside VS Code
}

type svgEdge struct {
	D      string
	Risky  bool
	Label  string
	Lines  []string // the label, one item per line so it fits between columns
	LX, LY int
}

type svgCol struct {
	X     int
	Title string
}

type finding struct {
	Sev, Title, Detail, Where, Node string
	Href                            template.URL
	Explain                         template.URL // asks the AI model, in VS Code only
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
	W, H         int
	Cols         []svgCol
	Nodes        []svgNode
	Edges        []svgEdge
	Findings     []finding
	Counts       map[string]int
}

type page struct {
	Sources    []string
	Overall    []string // a summary across projects, when there are several
	Disclaimer string
	Counts     map[string]int
	Projects   []project
	Multi      bool
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
	for _, f := range all.Findings {
		p.Counts[f.Severity.String()]++
	}
	if p.Multi && opt.Overview != nil {
		p.Overall = opt.Overview
	} else if p.Multi {
		p.Overall = []string{fmt.Sprintf("%d folders with code were read. Each has its own picture below, the riskiest first.", len(sections))}
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
	l := layout(g)
	p.Cols, p.W, p.H = l.cols, l.w, l.h

	for _, n := range l.order {
		pos := l.pos[n.ID]
		sn := svgNode{
			X: pos.x, Y: pos.y, W: nodeW, H: nodeH,
			Name: clip(n.Name, 21), Friendly: clip(n.Friendly, 25), Code: clipCode(n.Code, 23),
			Tooltip: n.Name + "\n" + n.Friendly, Icon: icon(n.Kind), Cat: strings.ToLower(n.Category.String()),
		}
		if n.File != "" {
			sn.Tooltip += fmt.Sprintf("\n%s:%d", n.File, n.Line)
		}
		if sev, ok := g.Worst(n.ID); ok {
			sn.Sev = sev.String()
			for _, f := range g.Findings {
				if f.NodeID == n.ID {
					sn.Count++
				}
			}
		}
		if n.Code != "" {
			sn.Tooltip += "\n" + n.Code
		}
		// A click goes to the worst problem in the box, so the user lands
		// where there is something to fix; without problems, to where the
		// box is defined. Findings are sorted, so the first one is worst.
		file, line := n.File, n.Line
		for _, f := range g.Findings {
			if f.NodeID == n.ID && f.File != "" {
				file, line = f.File, f.Line
				break
			}
		}
		if sn.Href = reveal(opt, file, line); sn.Href != "" {
			sn.Tooltip += "\nClick to open in the code"
		}
		p.Nodes = append(p.Nodes, sn)
	}

	lanes := map[int]int{}
	for _, e := range l.edges {
		a, b := l.pos[e.From], l.pos[e.To]
		se := edgePath(a, b, e, lanes)
		if se.Label != "" {
			se.Lines = strings.Split(se.Label, ", ")
			se.LY -= 12 * (len(se.Lines) - 1)
		}
		p.Edges = append(p.Edges, se)
	}

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
		p.Findings = append(p.Findings, finding{f.Severity.String(), f.Title, f.Detail, where, box, reveal(opt, f.File, f.Line), explainLink(opt, f)})
		p.Counts[f.Severity.String()]++
	}
	return p
}

type place struct{ x, y, col, row int }

type laidOut struct {
	order []*model.Node
	pos   map[string]place
	edges []model.Edge
	cols  []svgCol
	w, h  int
}

// layout puts each category in a column, folds long columns, and orders
// each column so lines cross as little as possible.
func layout(g *model.Graph) laidOut {
	columns := map[model.Category][]*model.Node{}
	for _, n := range g.Nodes {
		columns[n.Category] = append(columns[n.Category], n)
	}

	// Fold long columns, keeping the boxes with findings.
	redirect := map[string]string{}
	for c, nodes := range columns {
		if len(nodes) <= maxRows {
			continue
		}
		sort.SliceStable(nodes, func(i, j int) bool {
			_, fi := g.Worst(nodes[i].ID)
			_, fj := g.Worst(nodes[j].ID)
			return fi && !fj
		})
		keep, rest := nodes[:maxRows-1], nodes[maxRows-1:]
		more := &model.Node{
			ID: "more." + c.String(), Name: fmt.Sprintf("+%d more", len(rest)), Kind: "generic",
			Friendly: "listed in the findings", Category: c,
		}
		for _, n := range rest {
			redirect[n.ID] = more.ID
		}
		columns[c] = append(append([]*model.Node{}, keep...), more)
	}
	target := func(id string) string {
		if r, ok := redirect[id]; ok {
			return r
		}
		return id
	}
	var edges []model.Edge
	seen := map[[2]string]int{}
	for _, e := range g.Edges {
		e.From, e.To = target(e.From), target(e.To)
		if e.From == e.To {
			continue
		}
		key := [2]string{e.From, e.To}
		if i, ok := seen[key]; ok {
			edges[i].Risky = edges[i].Risky || e.Risky
			continue
		}
		if _, ok := redirect[e.To]; ok || strings.HasPrefix(e.To, "more.") || quietLabel[e.Label] {
			e.Label = "" // generic or piled-up labels add only noise
		}
		seen[key] = len(edges)
		edges = append(edges, e)
	}

	var used []model.Category
	for _, c := range g.Columns() {
		if len(columns[c]) > 0 {
			used = append(used, c)
		}
	}
	colOf := map[string]int{}
	for i, c := range used {
		for _, n := range columns[c] {
			colOf[n.ID] = i
		}
	}

	// Barycenter ordering: move each box toward the average row of the
	// boxes it is connected to in other columns. A few sweeps are plenty.
	rowOf := map[string]float64{}
	for _, c := range used {
		for i, n := range columns[c] {
			rowOf[n.ID] = float64(i)
		}
	}
	neighbours := map[string][]string{}
	for _, e := range edges {
		if colOf[e.From] != colOf[e.To] {
			neighbours[e.From] = append(neighbours[e.From], e.To)
			neighbours[e.To] = append(neighbours[e.To], e.From)
		}
	}
	for sweep := 0; sweep < 4; sweep++ {
		for _, c := range used {
			nodes := columns[c]
			score := map[string]float64{}
			for _, n := range nodes {
				nb := neighbours[n.ID]
				if len(nb) == 0 {
					score[n.ID] = rowOf[n.ID]
					continue
				}
				sum := 0.0
				for _, m := range nb {
					sum += rowOf[m]
				}
				score[n.ID] = sum / float64(len(nb))
			}
			sort.SliceStable(nodes, func(i, j int) bool {
				if nodes[i].ID == model.InternetID {
					return true
				}
				if nodes[j].ID == model.InternetID {
					return false
				}
				return score[nodes[i].ID] < score[nodes[j].ID]
			})
			for i, n := range nodes {
				rowOf[n.ID] = float64(i)
			}
		}
	}

	out := laidOut{pos: map[string]place{}, edges: edges}
	rows := 0
	for i, c := range used {
		x := padX + i*(nodeW+colGap)
		out.cols = append(out.cols, svgCol{X: x, Title: g.Title(c)})
		for r, n := range columns[c] {
			out.pos[n.ID] = place{x, padY + r*(nodeH+rowGap), i, r}
			out.order = append(out.order, n)
		}
		rows = max(rows, len(columns[c]))
	}
	out.w = padX + len(used)*(nodeW+colGap) - colGap/2 + padX
	out.h = padY + rows*(nodeH+rowGap) + padX
	return out
}

// edgePath draws a soft curve between two boxes, from the side that faces
// the other box. A line that skips a column travels in the gap above the
// target's row, each in its own lane, so it never looks like it passes
// through another box.
func edgePath(a, b place, e model.Edge, lanes map[int]int) svgEdge {
	ay, by := a.y+nodeH/2, b.y+nodeH/2
	out := svgEdge{Risky: e.Risky, Label: e.Label}

	if a.col == b.col {
		x := a.x + nodeW
		bend := colGap/2 - 6
		out.D = fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x, ay, x+bend, ay, x+bend, by, x, by)
		out.LX, out.LY = x+bend/2, (ay+by)/2
		return out
	}

	dir := 1
	x1, x2 := a.x+nodeW, b.x
	if a.col > b.col {
		dir = -1
		x1, x2 = a.x, b.x+nodeW
	}
	if a.col-b.col == 1 || b.col-a.col == 1 {
		c := dir * colGap / 2
		out.D = fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, ay, x1+c, ay, x2-c, by, x2, by)
		out.LX, out.LY = (x1+x2)/2, (ay+by)/2-6
		if ay == by {
			out.LY = ay - 6
		}
		return out
	}

	gap := b.row // the gap above the target's row
	k := lanes[gap]
	lanes[gap]++
	lane := b.y - rowGap/2 + (k%5-2)*5
	q := dir * colGap / 3
	out.D = fmt.Sprintf("M%d %d C%d %d %d %d %d %d L%d %d C%d %d %d %d %d %d",
		x1, ay, x1+q, ay, x1+q, lane, x1+2*q, lane,
		x2-2*q, lane, x2-q, lane, x2-q, by, x2, by)
	out.LX, out.LY = x1+2*q+dir*60, lane-5
	return out
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// clipCode shortens a code name so the name part stays readable:
// "azurerm_linux_virtual_machine.main" keeps ".main", "sql: Microsoft.Sql/servers"
// keeps "sql:".
func clipCode(s string, n int) string {
	if len([]rune(s)) <= n || strings.Contains(s, ": ") {
		return clip(s, n)
	}
	i := strings.LastIndex(s, ".")
	if i <= 0 || len(s)-i >= n-4 {
		return clip(s, n)
	}
	suffix := s[i:]
	return string([]rune(s)[:n-len([]rune(suffix))-1]) + "…" + suffix
}
