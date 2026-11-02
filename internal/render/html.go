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

	"github.com/Idris1980/lookfirst/internal/advice"
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
	flowGap      = 140 // a flow picture names every line, so its columns are further apart
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
	Official       string // the official Azure or AWS icon, by name, if there is one
	Code           string
	Cat, Sev       string
	Count          int
	Href           template.URL // where a click goes, or "" outside VS Code
	Notes          []svgText    // rules under the name, in a network picture
	HL             string       // classes for lighting up what it is joined to
	id             string
}

type svgText struct {
	X, Y int
	Text string
}

// svgFrame is a network or subnet drawn around the boxes in it.
type svgFrame struct {
	X, Y, W, H int
	Title, Sub string
	Class      string
	Empty      string // shown in a subnet with nothing in it
	Lines      []svgText
}

type svgEdge struct {
	D      string
	Risky  bool
	Kind   string // model.Flow, Access, Hosting, Order or ""
	below  bool   // the label hangs under the line and grows downwards
	HL     string // classes for lighting up what it is joined to
	from   string
	to     string
	Anchor string // "end" or "start" when the label lines up with LX that way; centred when empty
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
	W, H         int
	Cols         []svgCol
	Nodes        []svgNode
	Edges        []svgEdge
	Findings     []finding
	Counts       map[string]int
	Inventory    []itemGroup // every box, also those folded into "+N more"
	Total        int
	NotRead      []string      // files in the folders that LookFirst did not read
	Symbols      template.HTML // the official icons the picture uses, once each
	Flow         bool          // the picture follows the flow; show what the lines mean
	Network      bool          // networks and subnets are frames around the boxes
	Frames       []svgFrame
	HoverCSS     template.CSS // lights up a box's lines and neighbours on hover
}

type page struct {
	Sources    []string
	Overall    []string // a summary across projects, when there are several
	Disclaimer string
	Counts     map[string]int
	Projects   []project
	Multi      bool
	// Combined is every folder in one picture, scripts joined to the
	// templates they deploy, shown at the top when there are several.
	Combined *project
	// Chains are what happens, step by step, when the code is run.
	Chains   []chainView
	ChainCSS template.CSS
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
	p.ChainCSS = chainCSS(p.Chains)
	for _, f := range all.Findings {
		p.Counts[f.Severity.String()]++
	}
	if p.Multi && opt.Overview != nil {
		p.Overall = opt.Overview
	} else if p.Multi {
		p.Overall = []string{fmt.Sprintf("%d folders with code were read. The picture shows all of them together; each also has its own picture below, the riskiest first.", len(sections))}
		cp := buildProject(Section{Name: "All folders", Graph: combined(sections)}, opt)
		p.Combined = &cp
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
	if nv, ok := buildNetwork(g); ok {
		networkPicture(&p, g, nv, opt)
	} else {
		drawPicture(&p, g, opt)
	}
	highlight(&p)

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

// drawPicture fills a project's picture with boxes in columns.
func drawPicture(p *project, g *model.Graph, opt Options) {
	l := layout(g)
	p.Cols, p.W, p.H, p.Flow = l.cols, l.w, l.h, l.flow
	var used []string // official icons, for the symbols at the top of the picture

	for _, n := range l.order {
		pos := l.pos[n.ID]
		sn := boxFor(g, n, pos.x, pos.y, nodeH, opt)
		sn.id = n.ID
		used = append(used, sn.Official)
		p.Nodes = append(p.Nodes, sn)
	}

	lanes := map[int]int{}
	// How many lines leave and reach each box, to place the labels.
	outs, ins := map[string]int{}, map[string]int{}
	for _, e := range l.edges {
		outs[e.From]++
		ins[e.To]++
	}
	for _, e := range l.edges {
		a, b := l.pos[e.From], l.pos[e.To]
		se := edgePath(a, b, e, lanes, l.gap, l.flow, map[string]int{e.From: outs[e.From], e.To: ins[e.To]})
		se.from, se.to = e.From, e.To
		if se.Label != "" {
			se.Lines = wrapLabel(se.Label, 24)
			if !se.below {
				se.LY -= 12 * (len(se.Lines) - 1) // grow upwards, away from the line
			}
		}
		p.Edges = append(p.Edges, se)
	}

	p.Symbols = iconSymbols(used)
}

// highlight lets a box light up, when the mouse is over it, its own lines
// and the boxes at their other ends, and fade the rest. It is CSS only
// (:has), so the report still runs no script: box i has class ni, and
// everything joined to it class ci.
func highlight(p *project) {
	index := map[string]int{}
	for i, n := range p.Nodes {
		if n.id != "" {
			index[n.id] = i
		}
	}
	joined := make([][]int, len(p.Nodes))
	for i := range p.Nodes {
		joined[i] = []int{i}
	}
	for k, e := range p.Edges {
		a, okA := index[e.from]
		b, okB := index[e.to]
		var cls []string
		if okA {
			cls = append(cls, fmt.Sprintf("c%d", a))
		}
		if okB {
			cls = append(cls, fmt.Sprintf("c%d", b))
		}
		if okA && okB {
			joined[a] = append(joined[a], b)
			joined[b] = append(joined[b], a)
		}
		p.Edges[k].HL = strings.Join(cls, " ")
	}
	var css strings.Builder
	for i := range p.Nodes {
		cls := []string{fmt.Sprintf("n%d", i)}
		for _, j := range joined[i] {
			cls = append(cls, fmt.Sprintf("c%d", j))
		}
		if p.Nodes[i].id != "" {
			cls = append(cls, boxKey(p.Nodes[i].id))
		}
		p.Nodes[i].HL = strings.Join(cls, " ")
		fmt.Fprintf(&css, "svg:has(.n%d:hover) .hl:not(.c%d){opacity:.1}", i, i)
	}
	p.HoverCSS = template.CSS(css.String())
}

// boxFor is the box for a node in the picture: its names, icon, how many
// problems it has, and where a click goes.
func boxFor(g *model.Graph, n *model.Node, x, y, h int, opt Options) svgNode {
	sn := svgNode{
		X: x, Y: y, W: nodeW, H: h,
		Name: clip(n.Name, 21), Friendly: clip(n.Friendly, 25), Code: clipCode(n.Code, 23),
		Tooltip: n.Name + "\n" + n.Friendly, Icon: icon(n.Kind), Cat: strings.ToLower(n.Category.String()),
		Official: cloudIconFor(n),
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
	return sn
}

// inventory lists every box in the picture by column, so nothing is hidden
// when a long column is folded into "+N more".
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

type place struct{ x, y, col, row int }

type laidOut struct {
	order []*model.Node
	pos   map[string]place
	edges []model.Edge
	cols  []svgCol
	w, h  int
	gap   int  // room between columns
	flow  bool // columns follow the flow, not the kind of thing
}

// layout puts the boxes in columns, folds long columns, and orders each
// column so lines cross as little as possible.
func layout(g *model.Graph) laidOut { return layoutRows(g, maxRows) }

// layoutRows is layout with another limit before a column is folded; 0
// never folds, for exports that must hold every box.
//
// When the graph knows what its lines mean, the columns follow the flow:
// the internet on the left, then what it reaches, then what that talks
// to, and so on, so the picture reads from left to right like the traffic
// does. Lines that only say what must be created first are left out then.
// Otherwise each kind of thing gets a column of its own.
func layoutRows(g *model.Graph, rowsMax int) laidOut {
	flow := g.HasMeaning()
	var shown []*model.Node
	isShown := map[string]bool{}
	for _, n := range g.Nodes {
		if !n.Hidden {
			shown = append(shown, n)
			isShown[n.ID] = true
		}
	}
	var drawn []model.Edge
	for _, e := range g.Edges {
		if isShown[e.From] && isShown[e.To] && !(flow && e.Kind == model.Order) {
			drawn = append(drawn, e)
		}
	}

	columns := map[int][]*model.Node{}
	titles := map[int]string{}
	var keys []int
	if flow {
		layer := flowLayers(shown, drawn)
		for _, n := range shown {
			columns[layer[n.ID]] = append(columns[layer[n.ID]], n)
		}
		for k := range columns {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		if alone := len(keys) > 0 && keys[len(keys)-1] == loneLayer; alone {
			titles[loneLayer] = "Not connected"
		}
	} else {
		for _, n := range shown {
			columns[int(n.Category)] = append(columns[int(n.Category)], n)
		}
		for _, c := range g.Columns() {
			if len(columns[int(c)]) > 0 {
				keys = append(keys, int(c))
				titles[int(c)] = g.Title(c)
			}
		}
	}

	// Fold long columns, keeping the boxes with findings.
	redirect := map[string]string{}
	for _, c := range keys {
		nodes := columns[c]
		if rowsMax == 0 || len(nodes) <= rowsMax {
			continue
		}
		sort.SliceStable(nodes, func(i, j int) bool {
			_, fi := g.Worst(nodes[i].ID)
			_, fj := g.Worst(nodes[j].ID)
			return fi && !fj
		})
		keep, rest := nodes[:rowsMax-1], nodes[rowsMax-1:]
		more := &model.Node{
			ID: fmt.Sprintf("more.%d", c), Name: fmt.Sprintf("+%d more", len(rest)), Kind: "generic",
			Friendly: "listed in the findings", Category: rest[0].Category,
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
	for _, e := range drawn {
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

	colOf := map[string]int{}
	for i, c := range keys {
		for _, n := range columns[c] {
			colOf[n.ID] = i
		}
	}

	// Barycenter ordering: move each box toward the average row of the
	// boxes it is connected to in other columns. A few sweeps are plenty.
	rowOf := map[string]float64{}
	for _, c := range keys {
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
		for _, c := range keys {
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

	gap := colGap
	if flow {
		gap = flowGap // room for what each line means
	}
	out := laidOut{pos: map[string]place{}, edges: edges, gap: gap, flow: flow}
	rows := 0
	for i, c := range keys {
		x := padX + i*(nodeW+gap)
		out.cols = append(out.cols, svgCol{X: x, Title: titles[c]})
		for r, n := range columns[c] {
			out.pos[n.ID] = place{x, padY + r*(nodeH+rowGap), i, r}
			out.order = append(out.order, n)
		}
		rows = max(rows, len(columns[c]))
	}
	out.w = padX + len(keys)*(nodeW+gap) - gap/2 + padX
	out.h = padY + rows*(nodeH+rowGap) + padX
	return out
}

// loneLayer is the column for boxes no line reaches, last in the picture.
const loneLayer = 1 << 20

// flowLayers gives each box its column in a flow picture: the internet
// first, and every box one column right of the furthest box that talks to
// it. Boxes that only host, give rights or sign in (a plan, an identity)
// are then placed one column right of what uses them, without pushing
// anything further right. Loops are cut by never going further right than
// there are boxes.
func flowLayers(nodes []*model.Node, edges []model.Edge) map[string]int {
	layer := map[string]int{}
	linked, inFlow := map[string]bool{}, map[string]bool{}
	var flows, others []model.Edge
	for _, e := range edges {
		linked[e.From], linked[e.To] = true, true
		if e.Kind == model.Flow || e.Kind == "" {
			flows = append(flows, e)
			inFlow[e.From], inFlow[e.To] = true, true
		} else {
			others = append(others, e)
		}
	}
	hasInternet := linked[model.InternetID]
	for _, n := range nodes {
		switch {
		case !linked[n.ID]:
			layer[n.ID] = loneLayer
		case n.ID == model.InternetID || !hasInternet:
			layer[n.ID] = 0
		default:
			layer[n.ID] = 1
		}
	}
	push := func(es []model.Edge, movable func(id string) bool) {
		for round := 0; round < len(nodes); round++ {
			changed := false
			for _, e := range es {
				if e.To == model.InternetID || !movable(e.To) {
					continue
				}
				if next := layer[e.From] + 1; next > layer[e.To] && next <= len(nodes) {
					layer[e.To] = next
					changed = true
				}
			}
			if !changed {
				return
			}
		}
	}
	push(flows, func(string) bool { return true })
	// An identity that is given rights stands just left of what it may use,
	// so that line is short; a plan or a network just right of what uses it.
	first := 0
	if hasInternet {
		first = 1
	}
	placed := map[string]bool{}
	for _, e := range others {
		if inFlow[e.From] || !inFlow[e.To] || e.From == model.InternetID {
			continue
		}
		at := max(first, layer[e.To]-1)
		if !placed[e.From] || at < layer[e.From] {
			layer[e.From], placed[e.From] = at, true
		}
	}
	push(others, func(id string) bool { return !inFlow[id] && !placed[id] })
	// The internet stands just left of what it reaches, not across the
	// whole picture from it.
	if hasInternet {
		nearest := 0
		for _, e := range edges {
			if e.From == model.InternetID && (nearest == 0 || layer[e.To] < nearest) {
				nearest = layer[e.To]
			}
		}
		layer[model.InternetID] = max(0, nearest-1)
	}
	return layer
}

// edgePath draws a soft curve between two boxes, from the side that faces
// the other box. A line that skips a column travels in the gap above the
// target's row, each in its own lane, so it never looks like it passes
// through another box.
func edgePath(a, b place, e model.Edge, lanes map[int]int, colGap int, flow bool, fan map[string]int) svgEdge {
	ay, by := a.y+nodeH/2, b.y+nodeH/2
	out := svgEdge{Risky: e.Risky, Label: e.Label, Kind: e.Kind}

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
		if flow {
			// Where the line is level, at the end with fewer lines: just
			// before the arrow head when one box talks to many, just after
			// the start when many talk to one box.
			out.LX, out.LY, out.Anchor = x2-dir*12, by-6, "end"
			if dir < 0 {
				out.Anchor = "start"
			}
			if fan[e.To] > fan[e.From] {
				// Below the line, so it does not meet a label that sits
				// above another line into the same box.
				out.LX, out.LY, out.Anchor, out.below = x1+dir*12, ay+14, "start", true
				if dir < 0 {
					out.Anchor = "end"
				}
			}
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
	out.LX, out.LY = (x1+x2)/2, lane+11 // under the lane, clear of the box above
	return out
}

// wrapLabel splits a line's label into lines of about n letters: each
// part after " · " on a line of its own, and the items in a part, split at
// commas, packed onto as few lines as fit.
func wrapLabel(label string, n int) []string {
	var lines []string
	for _, part := range strings.Split(label, " · ") {
		cur := ""
		for _, item := range strings.Split(part, ", ") {
			item = strings.TrimSpace(item)
			switch {
			case cur == "":
				cur = item
			case len([]rune(cur))+2+len([]rune(item)) <= n:
				cur += ", " + item
			default:
				lines = append(lines, cur+",")
				cur = item
			}
		}
		if cur != "" {
			lines = append(lines, cur)
		}
	}
	return lines
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
