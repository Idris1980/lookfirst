// Package model holds what the engine found: the things code would build,
// how they connect, and the risks in them. Every reader (Terraform today,
// scripts and other formats later) produces a Graph, and every output
// (terminal, HTML, VS Code) consumes one.
package model

import (
	"sort"
	"strings"
)

// Category decides which column a node is drawn in.
type Category int

const (
	Internet Category = iota
	Network
	Security
	Compute
	Data
	Other

	// What a script builds in the cloud (with az or aws), drawn in columns
	// of their own next to the script's own Compute, Security and Data. They
	// share those names, and so their colors.
	CloudNetwork
	CloudSecurity
	CloudCompute
	CloudData
)

var categoryNames = [...]string{"Internet", "Network", "Security", "Compute", "Data", "Other", "Network", "Security", "Compute", "Data"}

func (c Category) String() string { return categoryNames[c] }

// Categories lists every category in drawing order, left to right.
func Categories() []Category {
	return []Category{Internet, Network, Security, Compute, Data, Other}
}

// Node is one thing the code would build, such as a VM or a firewall.
type Node struct {
	ID       string // unique, e.g. "azurerm_linux_virtual_machine.web"
	Name     string // the name in the code, e.g. "web"
	Kind     string // icon to draw, e.g. "vm"
	Friendly string // plain English, e.g. "virtual machine"
	Code     string // how it is written in the code, e.g. "azurerm_linux_virtual_machine.main"
	Category Category
	File     string
	Line     int
}

// Edge says that From uses or depends on To.
type Edge struct {
	From, To string
	Label    string
	Risky    bool
}

type Severity int

const (
	High Severity = iota
	Medium
	Low
)

var severityNames = [...]string{"high", "medium", "low"}

func (s Severity) String() string { return severityNames[s] }

// Finding is one risk. Detail is plain English and never contains the
// secret value itself.
type Finding struct {
	Severity Severity
	NodeID   string // empty when the finding is not tied to a node
	Title    string
	Detail   string
	File     string
	Line     int
}

type Graph struct {
	Sources  []string // the files that were read
	Nodes    []*Node
	Edges    []Edge
	Findings []Finding
	// Titles renames columns, e.g. "Files" instead of "Data" for scripts.
	Titles map[Category]string
	// Order changes the column order; nil means Categories().
	Order []Category
}

func (g *Graph) Columns() []Category {
	if g.Order != nil {
		return g.Order
	}
	return Categories()
}

func (g *Graph) Title(c Category) string {
	if t, ok := g.Titles[c]; ok {
		return t
	}
	return c.String()
}

// Merge adds everything in other to g. Nodes with the same ID, such as the
// shared Internet node, are kept once.
func (g *Graph) Merge(other *Graph) {
	g.Sources = append(g.Sources, other.Sources...)
	for _, n := range other.Nodes {
		if g.Node(n.ID) == nil {
			g.Nodes = append(g.Nodes, n)
		}
	}
	g.Edges = append(g.Edges, other.Edges...)
	g.Findings = append(g.Findings, other.Findings...)
}

// AddNode adds n unless a node with its ID exists, and returns the node
// that is in the graph.
func (g *Graph) AddNode(n *Node) *Node {
	if old := g.Node(n.ID); old != nil {
		return old
	}
	g.Nodes = append(g.Nodes, n)
	return n
}

// Connect adds an edge unless the same one exists. A label is appended to
// an existing edge's label, and Risky sticks once set.
func (g *Graph) Connect(from, to, label string, risky bool) {
	for i, e := range g.Edges {
		if e.From == from && e.To == to {
			if label != "" && !strings.Contains(e.Label, label) {
				if e.Label != "" {
					g.Edges[i].Label += ", "
				}
				g.Edges[i].Label += label
			}
			g.Edges[i].Risky = e.Risky || risky
			return
		}
	}
	g.Edges = append(g.Edges, Edge{From: from, To: to, Label: label, Risky: risky})
}

// InternetID is the one node that stands for everyone outside.
const InternetID = "internet"

// Expose draws the internet and a line from it to the node.
func (g *Graph) Expose(nodeID, label string, risky bool) {
	if g.Node(InternetID) == nil {
		g.Nodes = append([]*Node{{
			ID: InternetID, Name: "Internet", Kind: "internet", Friendly: "anyone, anywhere",
			Category: Internet,
		}}, g.Nodes...)
	}
	g.Connect(InternetID, nodeID, label, risky)
}

// Add records a finding. A node ID that is not in the graph is dropped so
// the finding still shows, just not on a box.
func (g *Graph) Add(sev Severity, nodeID, title, detail, file string, line int) {
	if g.Node(nodeID) == nil {
		nodeID = ""
	}
	g.Findings = append(g.Findings, Finding{
		Severity: sev, NodeID: nodeID, Title: title, Detail: detail, File: file, Line: line,
	})
}

// Sort orders findings by severity, then by place in the code.
func (g *Graph) Sort() {
	sort.SliceStable(g.Findings, func(i, j int) bool {
		a, b := g.Findings[i], g.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity < b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

func (g *Graph) Node(id string) *Node {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

// Worst returns the most severe finding for a node, or false if it has none.
func (g *Graph) Worst(id string) (Severity, bool) {
	worst, found := Low, false
	for _, f := range g.Findings {
		if f.NodeID == id && (!found || f.Severity < worst) {
			worst, found = f.Severity, true
		}
	}
	return worst, found
}
