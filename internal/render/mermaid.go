package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// Mermaid writes the picture as a Mermaid flowchart, which GitHub, GitLab,
// VS Code, Obsidian and many wikis draw on their own. Each column becomes a
// group, risky lines are red and dashed, and boxes with findings are framed
// in the colour of the worst one.
//
// Everything from the code is written inside quoted labels with quotes,
// angle brackets and backticks replaced, so a resource name cannot add
// Mermaid directives, HTML or links of its own.
func Mermaid(w io.Writer, sections []Section) error {
	// Several folders become one picture, with scripts joined to the
	// templates they deploy.
	if len(sections) > 1 {
		sections = []Section{{Name: "All folders", Graph: combined(sections)}}
	}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	n := 0
	ids := map[string]string{}
	var risky []int
	edge := 0
	for si, s := range sections {
		g := s.Graph
		prefix := ""
		if len(sections) > 1 {
			prefix = fmt.Sprintf("p%d_", si+1)
			fmt.Fprintf(&b, "  subgraph %sproject[\"%s\"]\n", prefix, label(s.Name))
		}
		for _, c := range g.Columns() {
			var nodes []*model.Node
			for _, nd := range g.Nodes {
				if nd.Category == c {
					nodes = append(nodes, nd)
				}
			}
			if len(nodes) == 0 {
				continue
			}
			fmt.Fprintf(&b, "  subgraph %scol%d[\"%s\"]\n", prefix, int(c), label(g.Title(c)))
			for _, nd := range nodes {
				n++
				id := fmt.Sprintf("n%d", n)
				ids[prefix+nd.ID] = id
				text := label(nd.Name)
				if nd.Friendly != "" {
					text += "<br/><small>" + label(nd.Friendly) + "</small>"
				}
				fmt.Fprintf(&b, "    %s[\"%s\"]\n", id, text)
				if sev, ok := g.Worst(nd.ID); ok {
					fmt.Fprintf(&b, "    class %s %s\n", id, sev)
				}
			}
			b.WriteString("  end\n")
		}
		for _, e := range g.Edges {
			from, to := ids[prefix+e.From], ids[prefix+e.To]
			if from == "" || to == "" {
				continue
			}
			arrow := "-->"
			if e.Risky {
				arrow = "-.->"
				risky = append(risky, edge)
			}
			if e.Label != "" {
				fmt.Fprintf(&b, "  %s %s|\"%s\"| %s\n", from, arrow, label(e.Label), to)
			} else {
				fmt.Fprintf(&b, "  %s %s %s\n", from, arrow, to)
			}
			edge++
		}
		if len(sections) > 1 {
			b.WriteString("  end\n")
		}
	}
	b.WriteString("  classDef high stroke:#d1242f,stroke-width:3px\n")
	b.WriteString("  classDef medium stroke:#b35900,stroke-width:2px\n")
	b.WriteString("  classDef low stroke:#2f6fb3\n")
	for _, i := range risky {
		fmt.Fprintf(&b, "  linkStyle %d stroke:#d1242f,stroke-width:2px\n", i)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// label makes text from the code safe inside a quoted Mermaid label.
func label(s string) string {
	r := strings.NewReplacer(
		`"`, "#quot;", "<", "#lt;", ">", "#gt;", "`", "#96;", "&", "#amp;",
		"\n", " ", "\r", " ", "|", "#124;", "[", "#91;", "]", "#93;", "{", "#123;", "}", "#125;",
	)
	return r.Replace(clip(s, 60))
}
