package azuretry

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// Compare finds what Azure adds to the picture the code gives: resources
// the code does not name, and risks that only show once Azure fills in its
// defaults. It also notes risks in the code that Azure did not end up with,
// for example because a policy or a default changed them. The result is a
// graph of its own, so it can be shown next to the other two.
func Compare(code, azure *model.Graph, label string) *model.Graph {
	diff := &model.Graph{Sources: []string{label}}

	codeTypes := map[string]int{}
	for _, n := range code.Nodes {
		if n.Category != model.Internet {
			codeTypes[typeOf(n)]++
		}
	}
	codeIDs := map[string]bool{}
	for _, n := range code.Nodes {
		codeIDs[strings.ToLower(n.ID)] = true
	}
	seenType := map[string]int{}
	for _, n := range azure.Nodes {
		if n.Category == model.Internet {
			continue
		}
		t := typeOf(n)
		seenType[t]++
		// Names the code computes, such as stdemo${uniqueString(...)}, only
		// become real in Azure, so a resource counts as known when the code
		// has one of the same type, even under another name.
		if codeIDs[strings.ToLower(n.ID)] || seenType[t] <= codeTypes[t] {
			continue
		}
		added := *n
		diff.AddNode(&added)
		diff.Add(model.Medium, n.ID, "Azure adds a resource the code does not name",
			fmt.Sprintf("%s %q comes from Azure or from a module, not from a resource written in this file. Check whether you want it.", n.Friendly, n.Name), label, 0)
	}

	inCode := map[string]bool{}
	for _, f := range code.Findings {
		inCode[findingKey(code, f)] = true
	}
	inAzure := map[string]bool{}
	for _, f := range azure.Findings {
		k := findingKey(azure, f)
		inAzure[k] = true
		if inCode[k] {
			continue
		}
		if n := azure.Node(f.NodeID); n != nil && diff.Node(n.ID) == nil {
			c := *n
			diff.AddNode(&c)
		}
		diff.Add(f.Severity, f.NodeID, f.Title+" (only in Azure)",
			f.Detail+" The code does not say this; it is what Azure would build.", label, 0)
	}
	var gone []string
	for _, f := range code.Findings {
		if f.Severity == model.Low || strings.HasPrefix(f.Title, "Bicep file") || strings.HasPrefix(f.Title, "Syntax") {
			continue
		}
		if !inAzure[findingKey(code, f)] && isResourceRule(f.Title) {
			gone = append(gone, f.Title)
		}
	}
	sort.Strings(gone)
	for _, t := range unique(gone) {
		diff.Add(model.Low, "", "Not seen in Azure: "+t,
			"The code shows this risk, but Azure's answer does not. A policy, a default or a value that is only known at deployment may have changed it. Check before you rely on it.", label, 0)
	}
	diff.Sort()
	return diff
}

// isResourceRule is true for findings about how a resource is set up. Secrets
// written in the template and parameters are about the code itself and do
// not appear in what Azure returns, so their absence there means nothing.
func isResourceRule(title string) bool {
	for _, p := range []string{"Password", "Secret", "Placeholder"} {
		if strings.HasPrefix(title, p) {
			return false
		}
	}
	return true
}

// findingKey matches the same risk on the same kind of resource in both
// graphs, ignoring names that only Azure knows.
func findingKey(g *model.Graph, f model.Finding) string {
	t := ""
	if n := g.Node(f.NodeID); n != nil {
		t = typeOf(n)
	}
	return t + "|" + f.Title
}

func typeOf(n *model.Node) string {
	if n.Code != "" {
		if i := strings.LastIndex(n.Code, ": "); i >= 0 {
			return strings.ToLower(n.Code[i+2:])
		}
		return strings.ToLower(n.Code)
	}
	return strings.ToLower(n.Friendly)
}

func unique(list []string) []string {
	var out []string
	for i, s := range list {
		if i == 0 || s != list[i-1] {
			out = append(out, s)
		}
	}
	return out
}
