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
	Count                              int    // steps inside, counted all the way down
	Keys                               string // classes of the boxes it builds or changes
}

type riskView struct {
	Sev, Title string
	Href       template.URL
}

func chainViews(g *model.Graph, opt Options) []chainView {
	root := commonRoot(g.Sources)
	var out []chainView
	for _, c := range chain.Build(g) {
		out = append(out, chainView{Title: c.Title, Items: stepViews(c.Items, root, opt)})
	}
	return out
}

func stepViews(items []chain.Item, root string, opt Options) []stepView {
	var out []stepView
	for _, it := range items {
		v := stepView{Num: it.Num, Says: it.Says, Note: it.Note, Code: it.Code, From: it.From,
			Deletes: it.Deletes, Skipped: it.Skipped, Href: reveal(opt, it.File, it.Line)}
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
		var keys []string
		for _, id := range append(append([]string{}, it.Creates...), it.Changes...) {
			keys = append(keys, boxKey(id))
		}
		v.Keys = strings.Join(keys, " ")
		v.Sub = stepViews(it.Sub, root, opt)
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

// chainCSS lights up, when the mouse is over a step, the boxes it builds
// or changes in the pictures, and when it is over a box, the steps that
// build or change it. Only CSS (:has), so the report runs no script.
func chainCSS(chains []chainView) template.CSS {
	seen := map[string]bool{}
	var b strings.Builder
	var walk func(items []stepView)
	walk = func(items []stepView) {
		for _, it := range items {
			for _, k := range strings.Fields(it.Keys) {
				if seen[k] {
					continue
				}
				seen[k] = true
				fmt.Fprintf(&b, "body:has(li.%[1]s>.body:hover) g.%[1]s .box{stroke:var(--accent);stroke-width:3.5}", k)
				fmt.Fprintf(&b, "body:has(g.%[1]s:hover) li.%[1]s>.body{background:var(--accent-bg)}", k)
			}
			walk(it.Sub)
		}
	}
	for _, c := range chains {
		walk(c.Items)
	}
	return template.CSS(b.String())
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
				if it.Skipped {
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
				for _, r := range it.Risks {
					fmt.Fprintf(w, "%s        ! %s: %s\n", pad, strings.ToUpper(r.Severity.String()), r.Title)
				}
				write(it.Sub, depth+1)
			}
		}
		write(c.Items, 0)
	}
}
