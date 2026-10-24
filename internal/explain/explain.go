// Package explain turns a graph into a few sentences of plain English. It
// works without AI so that it can run offline and always says the same
// thing for the same code.
package explain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// Disclaimer is shown wherever results are shown.
const Disclaimer = "This is what we found by reading the code, without running it. It is not a promise that the code is safe."

func Summary(g *model.Graph) []string {
	var out []string

	counts := map[string]int{}
	total := 0
	var hosts, files, programs, packages []string
	for _, n := range g.Nodes {
		switch {
		case n.ID == model.InternetID, strings.HasPrefix(n.ID, "script."):
		case strings.HasPrefix(n.ID, "host."):
			hosts = append(hosts, n.Name)
		case strings.HasPrefix(n.ID, "file."):
			files = append(files, n.Name)
		case strings.HasPrefix(n.ID, "program."):
			programs = append(programs, n.Name)
		case strings.HasPrefix(n.ID, "pkg."):
			packages = append(packages, n.Name)
		default:
			// "container · postgres" counts as a container.
			kind, _, _ := strings.Cut(n.Friendly, " · ")
			counts[kind]++
			total++
		}
	}
	if total > 0 {
		out = append(out, fmt.Sprintf("This code would create %s: %s.", plural(total, "resource"), list(counts)))
	}
	if len(hosts) > 0 {
		out = append(out, fmt.Sprintf("It talks to %s on the internet: %s.", plural(len(hosts), "place"), join(hosts, 5)))
	}
	if len(files) > 0 {
		out = append(out, fmt.Sprintf("It touches %s.", join(files, 5)))
	}
	if len(programs) > 0 {
		out = append(out, fmt.Sprintf("It runs other programs: %s.", join(programs, 6)))
	}
	if len(packages) > 0 {
		out = append(out, fmt.Sprintf("It uses or installs %s.", plural(len(packages), "package")))
	}
	if len(out) == 0 {
		out = append(out, "We did not find anything this code builds, connects to or changes.")
	}

	exposed := 0
	for _, e := range g.Edges {
		if e.From == model.InternetID {
			exposed++
		}
	}
	switch {
	case exposed == 1 && total == 0:
		out = append(out, "Other machines on the network can connect to it.")
	case exposed > 0:
		out = append(out, fmt.Sprintf("%d of them would be reachable from the internet.", exposed))
	}

	bySev := map[model.Severity][]string{}
	for _, f := range g.Findings {
		bySev[f.Severity] = append(bySev[f.Severity], f.Title)
	}
	high, medium, low := len(bySev[model.High]), len(bySev[model.Medium]), len(bySev[model.Low])
	if high+medium+low == 0 {
		out = append(out, "We found no known risks in what we checked.")
		return out
	}
	out = append(out, fmt.Sprintf("We found %d high, %d medium and %d low risks.", high, medium, low))
	if high > 0 {
		out = append(out, "Most important: "+strings.Join(unique(bySev[model.High], 3), "; ")+".")
	}
	return out
}

func list(counts map[string]int) string {
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = plural(counts[n], n)
	}
	return and(parts)
}

func join(items []string, max int) string {
	if len(items) > max {
		return and(append(append([]string{}, items[:max]...), fmt.Sprintf("%d more", len(items)-max)))
	}
	return and(items)
}

func and(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	if first, rest, ok := strings.Cut(word, " on "); ok {
		return plural(n, first) + " on " + rest // "folders on the host"
	}
	switch {
	case strings.HasSuffix(word, "ss"), strings.HasSuffix(word, "sh"), strings.HasSuffix(word, "ch"), strings.HasSuffix(word, "x"):
		return fmt.Sprintf("%d %ses", n, word) // addresses
	case strings.HasSuffix(word, "s"):
		return fmt.Sprintf("%d %s", n, word) // already plural: Application Insights
	case strings.HasSuffix(word, "y") && !strings.ContainsAny(word[len(word)-2:len(word)-1], "aeiou"):
		return fmt.Sprintf("%d %sies", n, word[:len(word)-1]) // policies
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func unique(titles []string, max int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range titles {
		if !seen[t] && len(out) < max {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
