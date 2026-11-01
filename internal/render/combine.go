package render

import (
	"path/filepath"
	"strings"

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
	return all
}

// deployLinks finds, for each "deploys" box, the things built by the
// template it names, and returns a line to each one that nothing else in
// the template points at (its top level).
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
		pointedAt := map[string]bool{}
		for _, e := range g.Edges {
			if inTemplate[e.From] && inTemplate[e.To] {
				pointedAt[e.To] = true
			}
		}
		for _, n := range g.Nodes {
			if inTemplate[n.ID] && !pointedAt[n.ID] && n.Category != model.Internet {
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
