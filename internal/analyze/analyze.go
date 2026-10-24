// Package analyze finds the files under the given paths, hands each kind to
// its reader and merges the results into one picture.
package analyze

import (
	"fmt"

	"github.com/Idris1980/lookfirst/internal/arm"
	"github.com/Idris1980/lookfirst/internal/compose"
	"github.com/Idris1980/lookfirst/internal/kubernetes"
	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/script"
	"github.com/Idris1980/lookfirst/internal/source"
	"github.com/Idris1980/lookfirst/internal/terraform"
)

func Paths(paths []string) (*model.Graph, error) {
	files, skipped, err := source.Collect(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("found nothing we can read. Supported: Terraform, Bicep, ARM, docker-compose, Kubernetes, Dockerfile, Python, JavaScript/TypeScript, shell and PowerShell")
	}
	g := Files(files)
	for _, p := range skipped {
		g.Add(model.Low, "", "File skipped", fmt.Sprintf("The file is larger than %d MiB and was not read.", source.MaxFileSize>>20), p, 0)
	}
	g.Sort()
	return g, nil
}

func Files(files []source.File) *model.Graph {
	byKind := map[source.Kind][]source.File{}
	allScripts := true
	for _, f := range files {
		byKind[f.Kind] = append(byKind[f.Kind], f)
		if !f.Kind.Script() {
			allScripts = false
		}
	}

	g := &model.Graph{}
	if fs := byKind[source.Terraform]; len(fs) > 0 {
		g.Merge(terraform.Read(fs))
	}
	if fs := append(byKind[source.ARM], byKind[source.Bicep]...); len(fs) > 0 {
		g.Merge(arm.Read(fs))
	}
	if fs := byKind[source.Compose]; len(fs) > 0 {
		g.Merge(compose.Read(fs))
	}
	if fs := byKind[source.Kubernetes]; len(fs) > 0 {
		g.Merge(kubernetes.Read(fs))
	}
	var scripts []source.File
	for _, k := range []source.Kind{source.Python, source.JavaScript, source.Shell, source.PowerShell, source.Dockerfile} {
		scripts = append(scripts, byKind[k]...)
	}
	if len(scripts) > 0 {
		g.Merge(script.Read(scripts))
	}
	if allScripts {
		g.Titles, g.Order = script.Titles, script.Order
	}
	g.Sort()
	return g
}
