package render

import (
	"fmt"
	"html/template"
	"os"
	"strings"

	"github.com/Idris1980/lookfirst/internal/advice"
	"github.com/Idris1980/lookfirst/internal/chain"
	"github.com/Idris1980/lookfirst/internal/knowledge"
	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
)

// A review card for every box: click a box in a picture and it opens with
// the evidence for it. The line of code it comes from, the step of the
// chain that makes or changes it, whether it must exist already, its
// risks with what to do about them, and every line to and from it said in
// words. It is plain HTML that :target shows, so the report still runs no
// script.

type reviewCard struct {
	ID                     string
	Name, Kind, Type       string
	Where                  string
	Open                   template.URL // to the line in VS Code
	Evidence               string       // the line of code, secrets masked
	Steps                  []string
	Existing               bool
	Risks                  []cardRisk
	Talks, Heard           []string     // its lines out and in, in words
	Needs                  []string     // what it needs that the code does not create
	Reference              template.URL // Microsoft's or Amazon's own page for its type
	Condition, Hidden, Box string
}

type cardRisk struct {
	Sev, Title, Detail, Fix string
	Href                    template.URL
}

// cardID is the anchor of a box's review card.
func cardID(nodeID string) string { return "card-" + boxKey(nodeID) }

// hasCard reports whether a box gets a review card: everything the code
// builds or uses, not the stand-ins for the internet or your computer.
func hasCard(id string) bool {
	return id != "" && id != model.InternetID && !model.IsAddress(id) &&
		!strings.HasPrefix(id, "folder.") && !strings.HasPrefix(id, "more.")
}

func reviewCards(g *model.Graph, chains []chain.Chain, opt Options) []reviewCard {
	root := commonRoot(g.Sources)
	steps := map[string][]string{}
	needs := map[string][]string{}
	var walk func(title string, items []chain.Item)
	walk = func(title string, items []chain.Item) {
		for _, it := range items {
			for _, id := range it.Creates {
				steps[id] = append(steps[id], fmt.Sprintf("%s, step %s: %s", title, it.Num, it.Says))
				needs[id] = append(needs[id], it.Needs...)
			}
			for _, id := range it.Changes {
				steps[id] = append(steps[id], fmt.Sprintf("%s, step %s: %s", title, it.Num, it.Says))
			}
			walk(title, it.Sub)
		}
	}
	for _, c := range chains {
		walk(c.Title, c.Items)
	}

	lines := map[string][]string{} // file -> its lines, read once
	evidence := func(file string, line int) string {
		if file == "" || line <= 0 {
			return ""
		}
		if _, ok := lines[file]; !ok {
			data, err := os.ReadFile(file)
			if err != nil || len(data) > 2<<20 {
				lines[file] = nil
			} else {
				lines[file] = strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
			}
		}
		ls := lines[file]
		if line > len(ls) {
			return ""
		}
		from, to := line-1, min(len(ls), line+3)
		masked, _ := risk.Mask(strings.Join(ls[from:to], "\n"))
		return masked
	}
	name := func(id string) string {
		switch {
		case id == model.InternetID:
			return "anyone on the internet"
		case id == model.You:
			return "your own IP address"
		case model.IsAddress(id):
			return "the addresses " + strings.TrimPrefix(id, "addr:")
		}
		if n := g.Node(id); n != nil {
			return n.Name + " (" + strings.Split(n.Friendly, " · ")[0] + ")"
		}
		return id
	}

	var out []reviewCard
	for _, n := range g.Nodes {
		if !hasCard(n.ID) {
			continue
		}
		c := reviewCard{ID: cardID(n.ID), Name: n.Name, Kind: n.Friendly, Type: n.Type, Existing: n.Existing,
			Steps: steps[n.ID], Needs: needs[n.ID], Open: reveal(opt, n.File, n.Line), Evidence: evidence(n.File, n.Line)}
		if n.File != "" {
			c.Where = relTo(root, n.File)
			if n.Line > 0 {
				c.Where += fmt.Sprintf(":%d", n.Line)
			}
		}
		switch {
		case strings.HasPrefix(n.Type, "Microsoft."):
			if _, ok := knowledge.AzureType(n.Type); ok {
				c.Reference = template.URL(knowledge.AzureDocs(n.Type))
			}
		case strings.HasPrefix(n.Type, "AWS::"):
			if docs, ok := knowledge.AWSType(n.Type); ok && strings.HasPrefix(docs, "https://docs.aws.amazon.com/") {
				c.Reference = template.URL(docs)
			}
		}
		if n.Condition != "" {
			c.Condition = "Only built when " + condText(n.Condition) + "."
		}
		if n.Hidden {
			c.Hidden = "Not drawn as a box of its own: it is shown as part of what it belongs to."
		}
		for _, f := range g.Findings {
			if f.NodeID != n.ID {
				continue
			}
			r := cardRisk{Sev: f.Severity.String(), Title: f.Title, Detail: f.Detail, Href: reveal(opt, f.File, f.Line)}
			if a, ok := advice.For(f.Title); ok && len(a.Fix) > 0 {
				r.Fix = a.Fix[0]
			}
			c.Risks = append(c.Risks, r)
		}
		for _, e := range g.Edges {
			if e.Kind == model.Order {
				continue
			}
			switch n.ID {
			case e.From:
				// "keeps its state in · may use queues" reads as
				// "keeps its state in st1 (and may use queues)".
				words, rights, _ := strings.Cut(lineWords(e, g.Node(e.To), true), " · ")
				line := words + " " + name(e.To)
				if rights != "" {
					line += ", and " + rights
				}
				c.Talks = append(c.Talks, line)
			case e.To:
				c.Heard = append(c.Heard, strings.ToUpper(name(e.From)[:1])+name(e.From)[1:]+" — "+lineWords(e, g.Node(e.From), false))
			}
		}
		out = append(out, c)
	}
	return out
}

func condText(c string) string {
	if strings.HasPrefix(c, "!") {
		return "the parameter " + strings.TrimPrefix(c, "!") + " is false"
	}
	return "the parameter " + c + " is true"
}

// lineWords says what a line means, also when the code that made it did
// not say: by what is at its other end.
func lineWords(e model.Edge, other *model.Node, out bool) string {
	if e.Label != "" {
		if e.From == model.InternetID || model.IsAddress(e.From) {
			return "may reach it on " + e.Label
		}
		return e.Label
	}
	if e.From == model.InternetID {
		return "can reach it"
	}
	if !out && other != nil {
		if other.Kind == "subnet" || isVNet(other) {
			return "holds it"
		}
		return "is joined to it"
	}
	if other != nil && out {
		switch {
		case other.Kind == "subnet":
			return "stands in"
		case other.Kind == "shield":
			return "is protected by"
		case isVNet(other):
			return "is in"
		case other.Kind == "key" || other.Kind == "identity":
			return "uses"
		}
	}
	if other != nil && !out {
		switch {
		case other.Kind == "subnet" || isVNet(other):
			return "holds"
		}
	}
	if out {
		return "is joined to"
	}
	return "is joined to"
}

// knowledgeLine says where LookFirst's knowledge of resource types comes
// from and how old it is.
func knowledgeLine() string {
	azDay, awsDay := knowledge.Updated()
	az, aws := knowledge.Counts()
	if az == 0 && aws == 0 {
		return ""
	}
	day := azDay
	if awsDay < day {
		day = awsDay
	}
	return fmt.Sprintf("Resource types checked against Microsoft's and Amazon's own lists (%d Azure and %d AWS types), taken %s.", az, aws, day)
}
