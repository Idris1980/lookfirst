package render

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// GitHub writes one workflow command per finding, so GitHub Actions shows
// each finding on its line in a pull request.
//
// The text comes partly from the code being checked, which may be hostile:
// a pull request could try to end the command early and start one of its
// own. Everything is escaped the way GitHub specifies, so it cannot.
func GitHub(w io.Writer, sections []Section) {
	level := map[model.Severity]string{model.High: "error", model.Medium: "warning", model.Low: "notice"}
	for _, s := range sections {
		for _, f := range s.Graph.Findings {
			props := []string{"title=" + escapeProperty("LookFirst: "+f.Title)}
			if f.File != "" {
				props = append(props, "file="+escapeProperty(filepath.ToSlash(f.File)))
				if f.Line > 0 {
					props = append(props, fmt.Sprintf("line=%d", f.Line))
				}
			}
			fmt.Fprintf(w, "::%s %s::%s\n", level[f.Severity], strings.Join(props, ","), escapeData(f.Detail))
		}
	}
}

func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}
