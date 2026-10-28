// Package terraform reads Terraform files as text and works out what they
// would build. It never runs Terraform, never evaluates variables against a
// real environment and never touches the network.
package terraform

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/source"
)

type resource struct {
	typ, name string
	body      *hclsyntax.Body
	file      string
	line      int
}

func (r resource) id() string { return r.typ + "." + r.name }

type variable struct {
	name string
	body *hclsyntax.Body
	file string
	line int
}

type config struct {
	files     []string
	resources []resource
	providers []resource // typ is "provider", name is e.g. "aws"
	locals    []resource
	variables []variable
	problems  []model.Finding
	// policyDocs are data "aws_iam_policy_document" blocks by name, so a
	// policy = data.aws_iam_policy_document.x.json can be read.
	policyDocs map[string]*hclsyntax.Body
}

// Read works out what the given .tf files would build. Each file's content
// has already been read, within size limits, by the caller.
func Read(files []source.File) *model.Graph {
	cfg := &config{}
	for _, f := range files {
		cfg.files = append(cfg.files, f.Path)
		cfg.parse(f.Path, f.Data)
	}
	return build(cfg)
}

func (c *config) parse(path string, src []byte) {
	file, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
	for _, d := range diags {
		if d.Severity != hcl.DiagError {
			continue
		}
		line := 0
		if d.Subject != nil {
			line = d.Subject.Start.Line
		}
		c.problem(path, line, "Syntax error", d.Summary+". "+d.Detail)
	}
	if file == nil {
		return
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return
	}

	for _, b := range body.Blocks {
		switch {
		case b.Type == "resource" && len(b.Labels) == 2:
			c.resources = append(c.resources, resource{b.Labels[0], b.Labels[1], b.Body, path, b.DefRange().Start.Line})
		case b.Type == "provider" && len(b.Labels) == 1:
			c.providers = append(c.providers, resource{"provider", b.Labels[0], b.Body, path, b.DefRange().Start.Line})
		case b.Type == "locals":
			c.locals = append(c.locals, resource{"locals", "", b.Body, path, b.DefRange().Start.Line})
		case b.Type == "variable" && len(b.Labels) == 1:
			c.variables = append(c.variables, variable{b.Labels[0], b.Body, path, b.DefRange().Start.Line})
		case b.Type == "data" && len(b.Labels) == 2 && b.Labels[0] == "aws_iam_policy_document":
			if c.policyDocs == nil {
				c.policyDocs = map[string]*hclsyntax.Body{}
			}
			c.policyDocs[b.Labels[1]] = b.Body
		}
	}
}

func (c *config) problem(file string, line int, title, detail string) {
	c.problems = append(c.problems, model.Finding{
		Severity: model.High, Title: title, Detail: strings.TrimSpace(detail), File: file, Line: line,
	})
}
