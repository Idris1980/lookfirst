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
	Cloud    string // "aws", "azure" or "" when it is not in a cloud
	Type     string // the cloud's own type, e.g. "AWS::EC2::Instance", "Microsoft.Compute/virtualMachines"
	Category Category
	File     string
	Line     int
	// Condition is set when the thing is only built in some deployments:
	// the name of the parameter that decides it, such as "deployContainer",
	// or "!name" when it is built when the parameter is false.
	Condition string
	// Existing is set for something the code only uses and does not
	// create, such as a Terraform data source or a Bicep "existing"
	// resource: it must be there before the code is run.
	Existing bool
	// Note says in words what it does, when its name and kind do not, such
	// as "gives funcName: may read and write blobs on dataStorageName".
	Note string
	// Address is the address range of a network or subnet, e.g.
	// "10.0.1.0/24", when the code spells it out.
	Address string
	// Hidden boxes are part of something else, such as a role assignment
	// (drawn as a line with the right it gives) or a blob container (shown
	// inside its storage account). They are left out of the picture but
	// kept in the full list, so nothing is missed.
	Hidden bool
}

// Edge kinds say what a line means.
const (
	// Flow: From talks to To at run time (calls it, reads from it, sends
	// logs to it). This is what the picture is about.
	Flow = "flow"
	// Access: From is allowed to use To, through a role or permission.
	Access = "access"
	// Hosting: From runs on, sits in or signs in as To.
	Hosting = "hosting"
	// Order: To must exist before From is created, nothing more. Not drawn
	// when the picture has lines of the other kinds.
	Order = "order"
)

// Edge says that From uses or depends on To.
type Edge struct {
	From, To string
	Label    string
	Risky    bool
	Kind     string // Flow, Access, Hosting, Order, or "" when not known
}

// HasMeaning reports whether the graph knows what its lines mean (any
// Flow, Access or Hosting line); then the picture is drawn as a flow.
func (g *Graph) HasMeaning() bool {
	for _, e := range g.Edges {
		// Lines from the internet are flows in every graph; they say
		// nothing about whether the reader knew the other lines' meaning.
		if e.From != InternetID && !IsAddress(e.From) && (e.Kind == Flow || e.Kind == Access || e.Kind == Hosting) {
			return true
		}
	}
	return false
}

// ConnectKind adds a line of a kind, or gives an existing line between the
// two a stronger meaning (a flow beats an access line, which beats hosting,
// which beats order) and adds the label.
func (g *Graph) ConnectKind(from, to, label, kind string) {
	rank := map[string]int{"": 0, Order: 1, Hosting: 2, Access: 3, Flow: 4}
	for i, e := range g.Edges {
		if e.From == from && e.To == to {
			if rank[kind] > rank[e.Kind] {
				g.Edges[i].Kind = kind
				if e.Kind == Order || e.Kind == "" {
					g.Edges[i].Label = "" // an order line's label meant nothing
				}
			}
			if label != "" && !strings.Contains(g.Edges[i].Label, label) {
				if g.Edges[i].Label != "" {
					g.Edges[i].Label += ", "
				}
				g.Edges[i].Label += label
			}
			return
		}
	}
	g.Edges = append(g.Edges, Edge{From: from, To: to, Label: label, Kind: kind})
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

// Step is one thing that happens when the code is run, in the order it
// happens: a command in a script, or a resource a template builds.
type Step struct {
	File    string
	Line    int
	Code    string // the command, shortened
	Says    string // what it does, in plain English
	Creates []string
	Changes []string // what it changes, uploads to or starts
	Deletes bool
	// From is what it takes from your computer, such as a folder of code
	// or a Dockerfile's folder, relative to the script.
	From string
	// Template is a template it hands to the cloud to build, relative to
	// the script, with the parameters given on the command line.
	Template string
	Params   map[string]string
	// Output is a template output it uses ("funcName"), for what it
	// changes, when the name is only known once the template has run.
	Output string
	// Runs is another script it runs, relative to this one.
	Runs string
	// Made and Needs are what it creates and what it expects to be there,
	// as "kind|name" ("network|vnet-a", "group|rg-web"), so the chain can
	// tell what must exist before the code is run.
	Made  []string
	Needs []string
}

type Graph struct {
	// Steps are what happens, in order, when the code is run.
	Steps []Step
	// Outputs are a template's outputs, by "file|name", and the box each
	// names. Defaults are its parameters' default values, by "file|name".
	Outputs  map[string]string
	Defaults map[string]string
	// After are, for a script, the other scripts it says must run first.
	After   map[string][]string
	Sources []string // the files that were read
	// NotRead are files in the folders that LookFirst did not read, because
	// it does not know their kind. They are listed so nothing is missed in
	// silence.
	NotRead  []string
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
	g.NotRead = append(g.NotRead, other.NotRead...)
	for _, n := range other.Nodes {
		if g.Node(n.ID) == nil {
			g.Nodes = append(g.Nodes, n)
		}
	}
	g.Edges = append(g.Edges, other.Edges...)
	g.Findings = append(g.Findings, other.Findings...)
	g.Steps = append(g.Steps, other.Steps...)
	for k, v := range other.Outputs {
		if g.Outputs == nil {
			g.Outputs = map[string]string{}
		}
		g.Outputs[k] = v
	}
	for k, v := range other.After {
		if g.After == nil {
			g.After = map[string][]string{}
		}
		g.After[k] = append(g.After[k], v...)
	}
	for k, v := range other.Defaults {
		if g.Defaults == nil {
			g.Defaults = map[string]string{}
		}
		g.Defaults[k] = v
	}
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

// You is the line source for a rule that lets in only one address, such as
// the one of the person running the script ($MyIp/32, $(curl ifconfig.me)).
const You = "addr:you"

// AddressSource is the line source for a firewall rule's source address:
// You for a single address or one that is looked up when the script runs,
// otherwise "addr:" and the range, such as "addr:10.0.3.0/24". No box is
// drawn for it; a network picture turns it into "your IP", or into the
// subnet with that range.
func AddressSource(source string) string {
	s := strings.Trim(strings.TrimSpace(source), `"'`)
	lower := strings.ToLower(s)
	switch {
	case s == "":
		return You
	case strings.HasSuffix(s, "/32") || strings.ContainsAny(s, "$(") || strings.Contains(lower, "myip") || strings.Contains(lower, "ifconfig") || strings.Contains(lower, "checkip"):
		return You
	case !strings.Contains(s, "/") && strings.Count(s, ".") == 3:
		return You // a single address written out
	}
	return "addr:" + s
}

// IsAddress reports whether a line source is an address rule rather than a
// box.
func IsAddress(id string) bool { return strings.HasPrefix(id, "addr:") }

// Expose draws the internet and a line from it to the node.
func (g *Graph) Expose(nodeID, label string, risky bool) {
	if g.Node(InternetID) == nil {
		g.Nodes = append([]*Node{{
			ID: InternetID, Name: "Internet", Kind: "internet", Friendly: "anyone, anywhere",
			Category: Internet,
		}}, g.Nodes...)
	}
	g.Connect(InternetID, nodeID, label, risky)
	// Traffic from the internet is a flow, whatever else the graph knows.
	for i, e := range g.Edges {
		if e.From == InternetID && e.To == nodeID && e.Kind == "" {
			g.Edges[i].Kind = Flow
		}
	}
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
// CloudOf says which cloud a finding is about: that of its box, or else that
// of the other boxes from the same file, or "" when it is not about a cloud.
func (g *Graph) CloudOf(f Finding) string {
	if n := g.Node(f.NodeID); n != nil && n.Cloud != "" {
		return n.Cloud
	}
	for _, n := range g.Nodes {
		if n.File == f.File && n.Cloud != "" {
			return n.Cloud
		}
	}
	return ""
}

func (g *Graph) Worst(id string) (Severity, bool) {
	worst, found := Low, false
	for _, f := range g.Findings {
		if f.NodeID == id && (!found || f.Severity < worst) {
			worst, found = f.Severity, true
		}
	}
	return worst, found
}
