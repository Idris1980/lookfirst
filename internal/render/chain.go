package render

import (
	"fmt"
	"hash/fnv"
	"html/template"
	"io"
	"path/filepath"
	"strings"

	"github.com/Idris1980/lookfirst/internal/chain"
	"github.com/Idris1980/lookfirst/internal/model"
)

// The chain is shown first in the report: what happens, in order, when
// the code is run, with each step's risks right where they arise.

type chainView struct {
	Title string
	Items []stepView
}

type stepView struct {
	Num, Says, Note, Where, Code, From string
	Href                               template.URL
	Deletes, Skipped                   bool
	Worst                              string
	Risks                              []riskView
	Sub                                []stepView
	Count                              int       // steps inside, counted all the way down
	Boxes                              []boxLink // what it builds or changes, each a link to its review card
	Needs, Uses                        []string
	Existing                           bool
}

type riskView struct {
	Sev, Title string
	Href       template.URL
}

func chainViews(g *model.Graph, opt Options) []chainView {
	root := commonRoot(g.Sources)
	var out []chainView
	for _, c := range chain.Build(g) {
		out = append(out, chainView{Title: c.Title, Items: stepViews(g, c.Items, root, opt)})
	}
	return out
}

// boxLink is a thing a step builds or changes, linked to its review card.
type boxLink struct{ Name, Card string }

func stepViews(g *model.Graph, items []chain.Item, root string, opt Options) []stepView {
	var out []stepView
	for _, it := range items {
		v := stepView{Num: it.Num, Says: it.Says, Note: it.Note, Code: it.Code, From: it.From,
			Deletes: it.Deletes, Skipped: it.Skipped, Href: reveal(opt, it.File, it.Line),
			Needs: it.Needs, Uses: it.Uses, Existing: it.Existing}
		if it.File != "" {
			v.Where = relTo(root, it.File)
			if it.Line > 0 {
				v.Where += fmt.Sprintf(":%d", it.Line)
			}
		}
		worst := model.Low + 1
		for _, r := range it.Risks {
			v.Risks = append(v.Risks, riskView{Sev: r.Severity.String(), Title: r.Title, Href: reveal(opt, r.File, r.Line)})
			if r.Severity < worst {
				worst = r.Severity
			}
		}
		if worst <= model.Low {
			v.Worst = worst.String()
		}
		for _, id := range append(append([]string{}, it.Creates...), it.Changes...) {
			if n := g.Node(id); n != nil && hasCard(id) {
				v.Boxes = append(v.Boxes, boxLink{Name: n.Name, Card: cardID(id)})
			}
		}
		v.Sub = stepViews(g, it.Sub, root, opt)
		v.Count = len(v.Sub)
		for _, s := range v.Sub {
			v.Count += s.Count
		}
		out = append(out, v)
	}
	return out
}

// boxKey is a class name for a box, the same in the chain and in every
// picture, so hovering one lights up the other.
func boxKey(id string) string {
	h := fnv.New32a()
	h.Write([]byte(id))
	return fmt.Sprintf("x%x", h.Sum32())
}

// Chain writes the chain as text, for the terminal.
func Chain(w io.Writer, g *model.Graph) {
	chains := chain.Build(g)
	if len(chains) == 0 {
		return
	}
	root := commonRoot(g.Sources)
	for _, c := range chains {
		fmt.Fprintf(w, "\n%s:\n", c.Title)
		var write func(items []chain.Item, depth int)
		write = func(items []chain.Item, depth int) {
			for _, it := range items {
				pad := strings.Repeat("   ", depth)
				num := it.Num
				if it.Skipped || it.Existing {
					num = "-"
				}
				fmt.Fprintf(w, "%s  %-5s %s", pad, num, it.Says)
				if it.Note != "" {
					fmt.Fprintf(w, " (%s)", it.Note)
				}
				if it.File != "" && depth == 0 {
					fmt.Fprintf(w, "  [%s:%d]", filepath.ToSlash(relTo(root, it.File)), it.Line)
				}
				fmt.Fprintln(w)
				for _, n := range it.Needs {
					fmt.Fprintf(w, "%s        ? Needs %s, which this code does not create\n", pad, n)
				}
				for _, u := range it.Uses {
					fmt.Fprintf(w, "%s        < Uses %s\n", pad, u)
				}
				for _, r := range it.Risks {
					fmt.Fprintf(w, "%s        ! %s: %s\n", pad, strings.ToUpper(r.Severity.String()), r.Title)
				}
				write(it.Sub, depth+1)
			}
		}
		write(c.Items, 0)
	}
}
