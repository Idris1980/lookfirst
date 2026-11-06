package render

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Idris1980/lookfirst/internal/advice"
	"github.com/Idris1980/lookfirst/internal/chain"
	"github.com/Idris1980/lookfirst/internal/explain"
	"github.com/Idris1980/lookfirst/internal/model"
)

// maxCommentRows keeps a pull request comment well under GitHub's size limit.
const maxCommentRows = 60

// Markdown writes a short report for a pull request comment or the summary
// of a GitHub Actions run. Text that comes from the checked code is escaped,
// so it cannot add links, images or formatting to the comment.
//
// With changed files (from a pull request), the findings in those files come
// first, and everything else that was read is folded away below them: the
// reviewer wants to see what this change brings in.
func Markdown(w io.Writer, sections []Section, changed map[string]bool) {
	all := &model.Graph{}
	for _, s := range sections {
		all.Merge(s.Graph)
	}
	fmt.Fprintf(w, "## LookFirst\n\n")

	if changed != nil {
		var mine []model.Finding
		for _, f := range all.Findings {
			if changed[filepath.ToSlash(f.File)] {
				mine = append(mine, f)
			}
		}
		fmt.Fprintf(w, "### In this pull request\n\n")
		if len(mine) == 0 {
			fmt.Fprintf(w, "No known risks in the files this pull request changes.\n\n")
		} else {
			c := counts(mine)
			fmt.Fprintf(w, "**%d high · %d medium · %d low** in the changed files.\n\n", c["high"], c["medium"], c["low"])
			table(w, all, mine, maxCommentRows)
		}
		chainMarkdown(w, all)
		picture(w, sections)
		c := counts(all.Findings)
		fmt.Fprintf(w, "<details><summary>Everything that was read: %d high · %d medium · %d low</summary>\n\n", c["high"], c["medium"], c["low"])
		for _, s := range sections {
			if len(sections) > 1 {
				fmt.Fprintf(w, "**%s**  \n", md(s.Name))
			}
			for _, line := range explain.Summary(s.Graph) {
				fmt.Fprintf(w, "%s  \n", md(line))
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "The full report with pictures is attached to the run.\n\n</details>\n\n")
		fmt.Fprintf(w, "<sub>%s</sub>\n", md(explain.Disclaimer))
		return
	}

	c := counts(all.Findings)
	if c["high"]+c["medium"]+c["low"] == 0 {
		fmt.Fprintf(w, "No known risks in what we checked.\n\n")
	} else {
		fmt.Fprintf(w, "**%d high · %d medium · %d low**\n\n", c["high"], c["medium"], c["low"])
	}
	chainMarkdown(w, all)
	rows := 0
	for _, s := range sections {
		if len(sections) > 1 {
			fmt.Fprintf(w, "### %s\n\n", md(s.Name))
		}
		for _, line := range explain.Summary(s.Graph) {
			fmt.Fprintf(w, "%s  \n", md(line))
		}
		fmt.Fprintln(w)
		if len(s.Graph.Findings) > 0 && rows < maxCommentRows {
			rows += table(w, s.Graph, s.Graph.Findings, maxCommentRows-rows)
		}
	}
	if total := len(all.Findings); total > rows {
		fmt.Fprintf(w, "…and %d more. The full report is attached to the run.\n\n", total-rows)
	}
	picture(w, sections)
	fmt.Fprintf(w, "<sub>%s</sub>\n", md(explain.Disclaimer))
}

// maxPictureBoxes keeps the Mermaid picture readable and the comment under
// GitHub's size limit; larger pictures are in the attached report.
const maxPictureBoxes = 80

// picture adds the diagram as Mermaid, which GitHub draws, folded away so
// the findings come first.
func picture(w io.Writer, sections []Section) {
	boxes := 0
	for _, s := range sections {
		boxes += len(s.Graph.Nodes)
	}
	if boxes == 0 {
		return
	}
	if boxes > maxPictureBoxes {
		fmt.Fprintf(w, "<details><summary>Picture</summary>\n\n%d things are too many to draw here; the full picture is in the report attached to the run.\n\n</details>\n\n", boxes)
		return
	}
	fmt.Fprintf(w, "<details><summary>Picture of what this code builds</summary>\n\n```mermaid\n")
	Mermaid(w, sections)
	fmt.Fprintf(w, "```\n\n</details>\n\n")
}

// table writes up to max findings as a Markdown table and returns how many
// rows it wrote. Each finding links to official guidance on how to fix it.
func table(w io.Writer, g *model.Graph, findings []model.Finding, max int) int {
	fmt.Fprintf(w, "| | Finding | Where |\n| --- | --- | --- |\n")
	n := 0
	for _, f := range findings {
		if n == max {
			break
		}
		n++
		where := filepath.ToSlash(f.File)
		if f.Line > 0 {
			where = fmt.Sprintf("%s:%d", where, f.Line)
		}
		guide := ""
		if a, ok := advice.For(f.Title); ok {
			if refs := a.Refs(g.CloudOf(f)); len(refs) > 0 {
				// The link is LookFirst's own, never text from the code.
				guide = fmt.Sprintf("<br>[How to fix: %s](%s)", md(refs[0].Label), refs[0].URL)
			}
		}
		fmt.Fprintf(w, "| %s | **%s**<br>%s%s | `%s` |\n", badge[f.Severity], md(f.Title), md(f.Detail), guide, strings.ReplaceAll(where, "`", "'"))
	}
	if len(findings) > n {
		fmt.Fprintf(w, "| | …and %d more | |\n", len(findings)-n)
	}
	fmt.Fprintln(w)
	return n
}

var badge = map[model.Severity]string{model.High: "🔴 high", model.Medium: "🟠 medium", model.Low: "🔵 low"}

// md escapes text so Markdown shows it as written.
func md(s string) string {
	var b strings.Builder
	for _, r := range strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", " ") {
		if strings.ContainsRune("\\`*_{}[]()#+-.!|<>~&", r) {
			b.WriteRune('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// chainMarkdown writes what happens, step by step, folded so a pull
// request comment stays short: every step, its risks under it.
func chainMarkdown(w io.Writer, g *model.Graph) {
	all := *g
	all.Sort()
	chains := chain.Build(&all)
	if len(chains) == 0 {
		return
	}
	fmt.Fprintf(w, "<details><summary>What happens, step by step</summary>\n\n")
	var write func(items []chain.Item, depth int)
	write = func(items []chain.Item, depth int) {
		for _, it := range items {
			num := it.Num
			if it.Skipped {
				num = "–"
			}
			line := md(it.Says)
			if it.Deletes {
				line = "**" + line + "**"
			}
			if it.Note != "" {
				line += " _(" + md(it.Note) + ")_"
			}
			fmt.Fprintf(w, "%s- %s %s\n", strings.Repeat("  ", depth), num, line)
			for _, n := range it.Needs {
				fmt.Fprintf(w, "%s  - :grey_question: needs %s, which this code does not create\n", strings.Repeat("  ", depth), md(n))
			}
			for _, r := range it.Risks {
				fmt.Fprintf(w, "%s  - :warning: %s: %s\n", strings.Repeat("  ", depth), strings.ToUpper(r.Severity.String()), md(r.Title))
			}
			write(it.Sub, depth+1)
		}
	}
	for _, c := range chains {
		fmt.Fprintf(w, "**%s**\n\n", md(c.Title))
		write(c.Items, 0)
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "</details>\n\n")
}
