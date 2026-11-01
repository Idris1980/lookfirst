package render

import (
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// DrawIO writes the picture as a diagrams.net (draw.io) file. Lucidchart
// imports it directly, and diagrams.net can save it as a Visio file
// (.vsdx), so the picture can be edited in all three. Each project gets a
// page of its own, every box is included (nothing is folded), boxes are
// placed as in the report, and risky lines are red and dashed.
//
// Labels are plain text, not HTML, and every value is XML-escaped, so a
// name from the code is shown as text and nothing else.
func DrawIO(w io.Writer, sections []Section) error {
	var b strings.Builder
	b.WriteString(`<mxfile host="LookFirst" type="device">` + "\n")
	for si, s := range sections {
		g := s.Graph
		l := layoutRows(g, 0)
		root := commonRoot(g.Sources)
		name := s.Name
		if name == "" {
			name = "LookFirst"
		}
		fmt.Fprintf(&b, `  <diagram id="p%d" name="%s">`+"\n", si+1, xmlText(name))
		fmt.Fprintf(&b, `    <mxGraphModel grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="%d" pageHeight="%d" math="0" shadow="0">`+"\n", l.w+40, l.h+40)
		b.WriteString("      <root>\n        <mxCell id=\"0\"/>\n        <mxCell id=\"1\" parent=\"0\"/>\n")

		for i, c := range l.cols {
			fmt.Fprintf(&b, `        <mxCell id="col%d" value="%s" style="text;fontStyle=1;fontColor=#5d6673;align=left;verticalAlign=middle;" vertex="1" parent="1"><mxGeometry x="%d" y="14" width="%d" height="24" as="geometry"/></mxCell>`+"\n",
				i, xmlText(strings.ToUpper(c.Title)), c.X, nodeW)
		}
		ids := map[string]string{}
		for i, n := range l.order {
			pos := l.pos[n.ID]
			id := fmt.Sprintf("n%d", i+1)
			ids[n.ID] = id
			fill, stroke := drawioColors(n.Category)
			width := 1.5
			if sev, ok := g.Worst(n.ID); ok {
				switch sev {
				case model.High:
					stroke, width = "#d1242f", 3
				case model.Medium:
					stroke, width = "#b35900", 2.5
				}
			}
			value := n.Name
			if n.Friendly != "" {
				value += "\n" + n.Friendly
			}
			if n.Code != "" && n.Code != n.Name {
				value += "\n" + n.Code
			}
			// Paths relative to the folder that was read: the file may be
			// shared, and should not show how someone's disk is organised.
			tooltip := ""
			if n.File != "" {
				tooltip = fmt.Sprintf("%s:%d", relTo(root, n.File), n.Line)
			}
			fmt.Fprintf(&b, `        <mxCell id="%s" value="%s" tooltip="%s" style="rounded=1;arcSize=12;whiteSpace=wrap;html=0;fillColor=%s;strokeColor=%s;strokeWidth=%.1f;fontSize=11;align=left;spacingLeft=10;" vertex="1" parent="1"><mxGeometry x="%d" y="%d" width="%d" height="%d" as="geometry"/></mxCell>`+"\n",
				id, xmlText(value), xmlText(tooltip), fill, stroke, width, pos.x, pos.y, nodeW, nodeH)
		}
		for i, e := range l.edges {
			from, to := ids[e.From], ids[e.To]
			if from == "" || to == "" {
				continue
			}
			style := "edgeStyle=orthogonalEdgeStyle;rounded=1;html=0;strokeColor=#8a94a3;endArrow=block;endFill=1;fontSize=10;"
			if e.Risky {
				style = "edgeStyle=orthogonalEdgeStyle;rounded=1;html=0;strokeColor=#d1242f;strokeWidth=2;dashed=1;endArrow=block;endFill=1;fontColor=#d1242f;fontSize=10;"
			}
			fmt.Fprintf(&b, `        <mxCell id="e%d" value="%s" style="%s" edge="1" parent="1" source="%s" target="%s"><mxGeometry relative="1" as="geometry"/></mxCell>`+"\n",
				i+1, xmlText(e.Label), style, from, to)
		}
		b.WriteString("      </root>\n    </mxGraphModel>\n  </diagram>\n")
	}
	b.WriteString("</mxfile>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// commonRoot is the deepest folder holding every file that was read.
func commonRoot(files []string) string {
	root := ""
	for i, f := range files {
		dir := filepath.Dir(filepath.Clean(f))
		if i == 0 {
			root = dir
			continue
		}
		for root != "" && !strings.HasPrefix(strings.ToLower(dir)+string(filepath.Separator), strings.ToLower(root)+string(filepath.Separator)) {
			parent := filepath.Dir(root)
			if parent == root {
				return ""
			}
			root = parent
		}
	}
	// One level up, so the folder's own name is kept: v40/deploy.ps1.
	if root != "" && filepath.Dir(root) != root {
		root = filepath.Dir(root)
	}
	return root
}

func relTo(root, file string) string {
	if root == "" {
		return filepath.ToSlash(filepath.Base(file))
	}
	if rel, err := filepath.Rel(root, file); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(filepath.Base(file))
}

// drawioColors are the report's column colours.
func drawioColors(c model.Category) (fill, stroke string) {
	switch c.String() {
	case "Internet":
		return "#f3f4f6", "#6b7280"
	case "Network":
		return "#dbeafe", "#2563eb"
	case "Security":
		return "#ede9fe", "#7c3aed"
	case "Compute":
		return "#ccfbf1", "#0f8a7e"
	case "Data":
		return "#ffedd5", "#c2410c"
	}
	return "#f1f5f9", "#64748b"
}

func xmlText(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	// EscapeText writes newlines as &#xA;, which draw.io shows as line
	// breaks; quotes must be escaped too inside attributes.
	return strings.ReplaceAll(b.String(), `"`, "&quot;")
}
