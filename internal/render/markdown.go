package render

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Idris1980/lookfirst/internal/explain"
	"github.com/Idris1980/lookfirst/internal/model"
)

// maxRows keeps a pull request comment well under GitHub's size limit.
const maxCommentRows = 60

// Markdown writes a short report for a pull request comment or the summary
// of a GitHub Actions run. Text that comes from the checked code is escaped,
// so it cannot add links, images or formatting to the comment.
func Markdown(w io.Writer, sections []Section) {
	all := &model.Graph{}
	for _, s := range sections {
		all.Merge(s.Graph)
	}
	c := counts(all.Findings)
	fmt.Fprintf(w, "## LookFirst\n\n")
	if c["high"]+c["medium"]+c["low"] == 0 {
		fmt.Fprintf(w, "No known risks in what we checked.\n\n")
	} else {
		fmt.Fprintf(w, "**%d high · %d medium · %d low**\n\n", c["high"], c["medium"], c["low"])
	}

	rows := 0
	for _, s := range sections {
		if len(sections) > 1 {
			fmt.Fprintf(w, "### %s\n\n", md(s.Name))
		}
		for _, line := range explain.Summary(s.Graph) {
			fmt.Fprintf(w, "%s  \n", md(line))
		}
		fmt.Fprintln(w)
		if len(s.Graph.Findings) == 0 {
			continue
		}
		fmt.Fprintf(w, "| | Finding | Where |\n| --- | --- | --- |\n")
		for _, f := range s.Graph.Findings {
			if rows == maxCommentRows {
				break
			}
			rows++
			where := filepath.ToSlash(f.File)
			if f.Line > 0 {
				where = fmt.Sprintf("%s:%d", where, f.Line)
			}
			fmt.Fprintf(w, "| %s | **%s**<br>%s | `%s` |\n", badge[f.Severity], md(f.Title), md(f.Detail), strings.ReplaceAll(where, "`", "'"))
		}
		fmt.Fprintln(w)
	}
	if total := len(all.Findings); total > rows {
		fmt.Fprintf(w, "…and %d more. The full report is attached to the run.\n\n", total-rows)
	}
	fmt.Fprintf(w, "<sub>%s</sub>\n", md(explain.Disclaimer))
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
