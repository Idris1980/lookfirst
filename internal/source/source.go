// Package source finds the files to read, decides what kind of code each one
// is, and reads them within fixed limits. Nothing here runs the code.
package source

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Kind string

const (
	Terraform  Kind = "terraform"
	Bicep      Kind = "bicep"
	ARM        Kind = "arm"
	Compose    Kind = "compose"
	Kubernetes Kind = "kubernetes"
	Python     Kind = "python"
	JavaScript Kind = "javascript"
	Shell      Kind = "shell"
	PowerShell Kind = "powershell"
	Dockerfile Kind = "dockerfile"
)

// Script reports whether the kind is a program rather than infrastructure.
func (k Kind) Script() bool {
	switch k {
	case Python, JavaScript, Shell, PowerShell, Dockerfile:
		return true
	}
	return false
}

type File struct {
	Path string
	Kind Kind
	Data []byte
}

// Limits keep a hostile or accidental input from eating the machine.
const (
	MaxFileSize = 2 << 20 // 2 MiB per file
	MaxFiles    = 500
)

var skipDirs = map[string]bool{
	".git": true, ".terraform": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, "build": true, "vendor": true, ".next": true,
}

// Collect returns every file we know how to read under the given paths, and
// the files inside folders that were skipped as too large. A file named
// directly must be a kind we know; inside folders, other files are ignored.
// Symbolic links are never followed.
func Collect(paths []string) (files []File, skipped []string, err error) {
	var found []string
	for _, p := range paths {
		info, err := os.Lstat(p)
		if err != nil {
			return nil, nil, err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("%s is a symbolic link; give the real path instead", p)
		}
		if !info.IsDir() {
			found = append(found, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != p && skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink == 0 && guessByName(d.Name()) != "" || shebangCandidate(d.Name()) {
				found = append(found, path)
			}
			if len(found) > MaxFiles {
				return fmt.Errorf("more than %d files to read; point at a smaller folder", MaxFiles)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	sort.Strings(found)

	for _, path := range found {
		named := contains(paths, path)
		info, err := os.Stat(path)
		if err != nil {
			return nil, nil, err
		}
		if info.Size() > MaxFileSize {
			if named {
				return nil, nil, fmt.Errorf("%s is larger than %d MiB", path, MaxFileSize>>20)
			}
			skipped = append(skipped, path)
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		f := File{Path: path, Kind: Detect(path, data), Data: data}
		if f.Kind == "" {
			if named {
				return nil, nil, fmt.Errorf("%s: this kind of file is not supported yet", path)
			}
			continue
		}
		files = append(files, f)
	}
	return files, skipped, nil
}

// Detect decides what kind of code a file holds, from its name first and
// its content where the name is not enough. It returns "" for anything else.
func Detect(path string, data []byte) Kind {
	name := filepath.Base(path)
	k := guessByName(name)
	switch k {
	case "yaml":
		switch {
		case composeName.MatchString(strings.ToLower(name)) || topLevelServices.Match(data):
			return Compose
		case apiVersion.Match(data) && kindLine.Match(data):
			return Kubernetes
		}
		return ""
	case "json":
		if bytes.Contains(data, []byte("deploymentTemplate.json")) {
			return ARM
		}
		return ""
	case "":
		if bytes.HasPrefix(data, []byte("#!")) {
			first, _, _ := bytes.Cut(data, []byte("\n"))
			switch {
			case bytes.Contains(first, []byte("python")):
				return Python
			case bytes.Contains(first, []byte("node")):
				return JavaScript
			case bytes.Contains(first, []byte("sh")):
				return Shell
			}
		}
		return ""
	}
	return k
}

var (
	composeName      = regexp.MustCompile(`^(docker-)?compose([.-].*)?\.ya?ml$`)
	topLevelServices = regexp.MustCompile(`(?m)^services:\s*$`)
	apiVersion       = regexp.MustCompile(`(?m)^apiVersion:\s*\S`)
	kindLine         = regexp.MustCompile(`(?m)^kind:\s*\S`)
)

func guessByName(name string) Kind {
	lower := strings.ToLower(name)
	if lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile") {
		return Dockerfile
	}
	switch filepath.Ext(lower) {
	case ".tf":
		return Terraform
	case ".bicep":
		return Bicep
	case ".json":
		return "json"
	case ".yml", ".yaml":
		return "yaml"
	case ".py":
		return Python
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx":
		return JavaScript
	case ".sh", ".bash", ".zsh":
		return Shell
	case ".ps1", ".psm1":
		return PowerShell
	}
	return ""
}

// shebangCandidate lets extensionless files through so Detect can look at
// their first line.
func shebangCandidate(name string) bool {
	return filepath.Ext(name) == "" && !strings.HasPrefix(name, ".")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
