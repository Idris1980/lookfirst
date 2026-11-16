package render

import (
	"path/filepath"
	"strings"
)

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
