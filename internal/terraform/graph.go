package terraform

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/Idris1980/lookfirst/internal/model"
)

func build(c *config) *model.Graph {
	g := &model.Graph{Sources: c.files}

	for _, r := range c.resources {
		if hidden[r.typ] || (isAssociation(r.typ) && len(references(r.body)) == 2) {
			continue
		}
		e := lookup(r.typ)
		// The name the resource gets in the cloud says more than the label
		// in the code, which AI assistants often set to "main".
		name := r.name
		if n, ok := str(r.body, "name"); ok && n != "" {
			name = n
		} else if n, ok := str(r.body, "bucket"); ok && n != "" {
			name = n
		}
		g.Nodes = append(g.Nodes, &model.Node{
			ID: r.id(), Name: name, Kind: e.kind, Friendly: e.friendly, Code: r.id(),
			Category: e.category, File: r.file, Line: r.line,
		})
	}

	seen := map[[2]string]bool{}
	connect := func(from, to string) {
		key := [2]string{from, to}
		if to == from || seen[key] || g.Node(from) == nil || g.Node(to) == nil {
			return
		}
		seen[key] = true
		g.Edges = append(g.Edges, model.Edge{From: from, To: to})
	}
	for _, r := range c.resources {
		if hidden[r.typ] {
			continue
		}
		refs := references(r.body)
		// An association only says that two other things belong together,
		// so it becomes a line between them instead of a box.
		if isAssociation(r.typ) && len(refs) == 2 {
			connect(refs[0], refs[1])
			continue
		}
		for _, to := range refs {
			connect(r.id(), to)
		}
	}

	check(c, g)
	g.Findings = append(g.Findings, c.problems...)
	return g
}

// references returns the resources a block refers to, as "type.name".
func references(body *hclsyntax.Body) []string {
	var out []string
	walk(body, func(a *hclsyntax.Attribute) {
		for _, t := range a.Expr.Variables() {
			if id, ok := resourceRef(t); ok {
				out = append(out, id)
			}
		}
	})
	return out
}

func resourceRef(t hcl.Traversal) (string, bool) {
	if len(t) < 2 {
		return "", false
	}
	root := t.RootName()
	switch root {
	case "var", "local", "data", "module", "each", "count", "path", "terraform", "self":
		return "", false
	}
	attr, ok := t[1].(hcl.TraverseAttr)
	if !ok {
		return "", false
	}
	return root + "." + attr.Name, true
}

// walk calls fn for every attribute in the body and its nested blocks.
func walk(body *hclsyntax.Body, fn func(*hclsyntax.Attribute)) {
	for _, a := range body.Attributes {
		fn(a)
	}
	for _, b := range body.Blocks {
		walk(b.Body, fn)
	}
}

// literal returns the value of an expression that is written out directly
// in the code, such as "abc", 22 or ["0.0.0.0/0"]. Anything that depends on
// variables or functions is unknown to us and returns false.
func literal(expr hclsyntax.Expression) (cty.Value, bool) {
	if len(expr.Variables()) > 0 {
		return cty.NilVal, false
	}
	v, diags := expr.Value(nil)
	if diags.HasErrors() || v.IsNull() || !v.IsWhollyKnown() {
		return cty.NilVal, false
	}
	return v, true
}

func str(body *hclsyntax.Body, name string) (string, bool) {
	a, ok := body.Attributes[name]
	if !ok {
		return "", false
	}
	v, ok := literal(a.Expr)
	if !ok {
		return "", false
	}
	s, err := convert.Convert(v, cty.String)
	if err != nil {
		return "", false
	}
	return s.AsString(), true
}

// strs returns the literal strings of every named attribute, whether each is
// a single string or a list of them.
func strs(body *hclsyntax.Body, names ...string) []string {
	var out []string
	for _, name := range names {
		if s, ok := str(body, name); ok {
			out = append(out, s)
			continue
		}
		a, ok := body.Attributes[name]
		if !ok {
			continue
		}
		v, ok := literal(a.Expr)
		if !ok || !(v.Type().IsListType() || v.Type().IsTupleType() || v.Type().IsSetType()) {
			continue
		}
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			if s, err := convert.Convert(e, cty.String); err == nil && !s.IsNull() {
				out = append(out, s.AsString())
			}
		}
	}
	return out
}

func boolean(body *hclsyntax.Body, name string) (value, set bool) {
	s, ok := str(body, name)
	if !ok {
		return false, false
	}
	return s == "true", true
}

func line(body *hclsyntax.Body, name string, fallback int) int {
	if a, ok := body.Attributes[name]; ok {
		return a.SrcRange.Start.Line
	}
	return fallback
}
