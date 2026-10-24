// Package analyze finds the files under the given paths, hands each kind to
// its reader and builds one picture per project.
package analyze

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Idris1980/lookfirst/internal/arm"
	"github.com/Idris1980/lookfirst/internal/compose"
	"github.com/Idris1980/lookfirst/internal/kubernetes"
	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/script"
	"github.com/Idris1980/lookfirst/internal/source"
	"github.com/Idris1980/lookfirst/internal/terraform"
)

// Project is the code in one folder. A repository often holds several
// unrelated things, such as infrastructure, an app and some scripts; one
// picture of all of them at once is unreadable.
type Project struct {
	Name  string // the folder, relative to what was read, e.g. "infra/network"
	Dir   string // the folder as found on disk
	Graph *model.Graph
}

// Paths reads the given files and folders and returns one project per
// folder that holds code, in folder order.
func Paths(paths []string) ([]Project, error) {
	files, skipped, err := source.Collect(paths)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("found nothing we can read. Supported: Terraform, Bicep, ARM, docker-compose, Kubernetes, Dockerfile, Python, JavaScript/TypeScript, shell, PowerShell, package.json and requirements.txt")
	}

	byDir := map[string][]source.File{}
	for _, f := range files {
		dir := filepath.Dir(f.Path)
		byDir[dir] = append(byDir[dir], f)
	}
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	root := commonDir(dirs)

	var projects []Project
	for _, d := range dirs {
		projects = append(projects, Project{Name: projectName(root, d), Dir: d, Graph: Files(byDir[d])})
	}
	for _, p := range skipped {
		g := projects[0].Graph
		for _, pr := range projects {
			if filepath.Dir(p) == pr.Dir {
				g = pr.Graph
			}
		}
		g.Add(model.Low, "", "File skipped", fmt.Sprintf("The file is larger than %d MiB and was not read.", source.MaxFileSize>>20), p, 0)
		g.Sort()
	}
	return projects, nil
}

// Files reads files that belong together into one picture.
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
	for _, k := range []source.Kind{source.Python, source.JavaScript, source.Shell, source.PowerShell, source.Dockerfile, source.NpmManifest, source.PipRequirements} {
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

// Merge puts every project into one graph, for totals and for tools that
// want a flat list of findings.
func Merge(projects []Project) *model.Graph {
	g := &model.Graph{}
	for _, p := range projects {
		g.Merge(p.Graph)
	}
	if len(projects) == 1 {
		g.Titles, g.Order = projects[0].Graph.Titles, projects[0].Graph.Order
	}
	g.Sort()
	return g
}

// commonDir is the deepest folder that holds all the given folders.
func commonDir(dirs []string) string {
	root := dirs[0]
	for _, d := range dirs[1:] {
		for !within(root, d) {
			parent := filepath.Dir(root)
			if parent == root {
				return root
			}
			root = parent
		}
	}
	return root
}

func within(root, dir string) bool {
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func projectName(root, dir string) string {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		if abs, err := filepath.Abs(dir); err == nil {
			return filepath.Base(abs)
		}
		return dir
	}
	return filepath.ToSlash(rel)
}
