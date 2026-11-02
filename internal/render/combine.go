package render

import (
	"path/filepath"
	"strings"

	"github.com/Idris1980/lookfirst/internal/chain"
	"github.com/Idris1980/lookfirst/internal/model"
)

// combined puts the pictures of several folders into one, and joins a
// script that deploys a template to what that template builds: a line from
// the "deploys" box to each of the template's top-level things, so the
// whole chain is in one picture, script → template → resources.
func combined(sections []Section) *model.Graph {
	// Scripts and infrastructure together use the script columns, which
	// have room for both your code and what it builds in the cloud.
	var scripts *model.Graph
	for _, s := range sections {
		if s.Graph.Order != nil {
			scripts = s.Graph
		}
	}
	cloudColumn := map[model.Category]model.Category{
		model.Network: model.CloudNetwork, model.Security: model.CloudSecurity,
		model.Compute: model.CloudCompute, model.Data: model.CloudData,
		model.Other: model.CloudData, // monitoring and the like, not packages
	}
	all := &model.Graph{}
	for _, s := range sections {
		// Copies, so the folder's own picture keeps its columns.
		g := &model.Graph{Sources: s.Graph.Sources, Edges: s.Graph.Edges, Findings: s.Graph.Findings}
		for _, n := range s.Graph.Nodes {
			c := *n
			if scripts != nil && s.Graph.Order == nil && c.Cloud != "" {
				if to, ok := cloudColumn[c.Category]; ok {
					c.Category = to
				}
			}
			g.Nodes = append(g.Nodes, &c)
		}
		all.Merge(g)
	}
	if scripts != nil {
		all.Titles, all.Order = scripts.Titles, scripts.Order
	} else if len(sections) > 0 {
		all.Titles, all.Order = sections[0].Graph.Titles, sections[0].Graph.Order
	}
	for _, e := range deployLinks(all) {
		all.Connect(e.From, e.To, "", false)
	}
	chainLinks(all)
	quiet(all)
	return all
}

// quiet leaves out of the joined picture what each folder's own picture
// already shows: the programs a script runs, the packages it installs, and
// then the files with nothing left to connect to and nothing to warn about.
func quiet(g *model.Graph) {
	gone := map[string]bool{}
	for _, n := range g.Nodes {
		if strings.HasPrefix(n.ID, "program.") || strings.HasPrefix(n.ID, "pkg.") {
			n.Hidden, gone[n.ID] = true, true
		}
	}
	linked := map[string]bool{}
	for _, e := range g.Edges {
		if !gone[e.From] && !gone[e.To] {
			linked[e.From], linked[e.To] = true, true
		}
	}
	for _, n := range g.Nodes {
		if _, risky := g.Worst(n.ID); !linked[n.ID] && !risky && n.ID != model.InternetID {
			n.Hidden = true
		}
	}
}

// deployLinks finds, for each "deploys" box, the things built by the
// template it names, and returns a line to where the template begins.
func deployLinks(g *model.Graph) []model.Edge {
	var out []model.Edge
	for _, d := range g.Nodes {
		if !strings.HasPrefix(d.ID, "deploy.") || d.File == "" {
			continue
		}
		template := samePath(filepath.Join(filepath.Dir(d.File), filepath.FromSlash(d.Name)))
		inTemplate := map[string]bool{}
		for _, n := range g.Nodes {
			if n.File != "" && samePath(n.File) == template {
				inTemplate[n.ID] = true
			}
		}
		if len(inTemplate) == 0 {
			continue
		}
		// Where the template's traffic comes in from the internet, or, when
		// nothing does, its top level: what nothing else in it points at.
		pointedAt, entry := map[string]bool{}, map[string]bool{}
		for _, e := range g.Edges {
			if inTemplate[e.From] && inTemplate[e.To] && e.Kind != model.Order {
				pointedAt[e.To] = true
			}
			if e.From == model.InternetID && inTemplate[e.To] {
				entry[e.To] = true
			}
		}
		for _, n := range g.Nodes {
			if !inTemplate[n.ID] || n.Hidden || n.Category == model.Internet {
				continue
			}
			if entry[n.ID] || (len(entry) == 0 && !pointedAt[n.ID]) {
				out = append(out, model.Edge{From: d.ID, To: n.ID})
			}
		}
	}
	return out
}

func samePath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	return strings.ToLower(filepath.Clean(abs))
}

// chainLinks draws what the chain hands over from your computer: a folder
// of code uploaded to an app, a folder with a Dockerfile built into a
// registry, a file run on a server when it starts.
func chainLinks(g *model.Graph) {
	var walk func(items []chain.Item)
	walk = func(items []chain.Item) {
		for _, it := range items {
			if it.From != "" && len(it.Changes)+len(it.Creates) > 0 {
				dir := filepath.Join(filepath.Dir(it.File), filepath.FromSlash(it.From))
				id := "folder." + strings.ToLower(filepath.Clean(dir))
				name := filepath.ToSlash(it.From)
				g.AddNode(&model.Node{ID: id, Name: name, Kind: "folder", Friendly: "on your computer",
					Code: "taken by step " + it.Num, Category: model.Compute, File: it.File, Line: it.Line})
				label := "uploaded to"
				switch {
				case strings.HasPrefix(it.Says, "Builds"):
					label = "built into"
				case strings.HasPrefix(it.Says, "Creates"):
					label = "runs on it at start"
				}
				for _, to := range append(append([]string{}, it.Changes...), it.Creates...) {
					if n := g.Node(to); n != nil && !n.Hidden {
						g.ConnectKind(id, to, label, model.Flow)
					}
				}
			}
			walk(it.Sub)
		}
	}
	for _, c := range chain.Build(g) {
		walk(c.Items)
	}
}
