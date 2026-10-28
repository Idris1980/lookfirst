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
	Terraform Kind = "terraform"
	Bicep     Kind = "bicep"
	ARM       Kind = "arm"
	// AWS CloudFormation templates, including SAM, in YAML or JSON.
	CloudFormation Kind = "cloudformation"
	Compose        Kind = "compose"
	Kubernetes     Kind = "kubernetes"
	Python         Kind = "python"
	JavaScript     Kind = "javascript"
	Shell          Kind = "shell"
	PowerShell     Kind = "powershell"
	Dockerfile     Kind = "dockerfile"
	// Package lists: what a program would install.
	NpmManifest     Kind = "package.json"
	PipRequirements Kind = "requirements"
)

// Script reports whether the kind is a program rather than infrastructure.
func (k Kind) Script() bool {
	switch k {
	case Python, JavaScript, Shell, PowerShell, Dockerfile, NpmManifest, PipRequirements:
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

// skipDirs hold downloaded or generated files, not the user's own code.
var skipDirs = map[string]bool{
	".git": true, ".terraform": true, "node_modules": true, ".venv": true, "venv": true,
	"__pycache__": true, "dist": true, "build": true, "vendor": true, ".next": true,
	".vs": true, "obj": true, "coverage": true, ".cache": true, "site-packages": true,
	".pytest_cache": true, ".mypy_cache": true, ".tox": true, "target": true,
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
			if d.Type()&fs.ModeSymlink == 0 && (guessByName(d.Name()) != "" || shebangCandidate(d.Name())) {
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
		byName := guessByName(filepath.Base(path))
		// A file without an extension is only code if it starts with #!.
		// Programs and other data are passed over without a word.
		if byName == "" && !named && !startsWithShebang(path) {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, nil, err
		}
		if info.Size() > MaxFileSize {
			if named {
				return nil, nil, fmt.Errorf("%s is larger than %d MiB", path, MaxFileSize>>20)
			}
			// Large JSON and YAML files are usually data, such as lock
			// files; only mention files that are certainly code.
			if byName != "json" && byName != "yaml" && byName != "" {
				skipped = append(skipped, path)
			}
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
		case cloudFormation(data):
			return CloudFormation
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
		if cloudFormation(data) {
			return CloudFormation
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
	cfnVersion       = regexp.MustCompile(`"?AWSTemplateFormatVersion"?\s*:`)
	cfnResources     = regexp.MustCompile(`(?m)^\s*"?Resources"?\s*:`)
	cfnType          = regexp.MustCompile(`"?Type"?\s*:\s*["']?AWS::\w+::\w+`)
)

// cloudFormation recognises a CloudFormation or SAM template: it says so,
// or it has Resources with AWS:: types.
func cloudFormation(data []byte) bool {
	return cfnVersion.Match(data) || (cfnResources.Match(data) && cfnType.Match(data))
}

func guessByName(name string) Kind {
	lower := strings.ToLower(name)
	switch {
	case lower == "dockerfile" || strings.HasPrefix(lower, "dockerfile.") || strings.HasSuffix(lower, ".dockerfile"):
		return Dockerfile
	case lower == "package.json":
		return NpmManifest
	case strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt"):
		return PipRequirements
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

// GuessName picks a file name for pasted code, which has none, from what
// the code looks like. Detect then decides the kind from that name as usual.
func GuessName(text string) string {
	t := strings.TrimSpace(text)
	has := func(re string) bool { return regexp.MustCompile(re).MatchString(t) }
	switch {
	case strings.Contains(t, "deploymentTemplate.json"):
		return "azuredeploy.json"
	case cloudFormation([]byte(t)):
		if strings.HasPrefix(t, "{") {
			return "template.json"
		}
		return "template.yaml"
	case has(`(?m)^\s*"(dependencies|devDependencies|scripts)"\s*:`) && strings.HasPrefix(t, "{"):
		return "package.json"
	case has(`(?m)^(resource|variable|provider|module|terraform|data|output|locals)\s+("|\{)`):
		return "main.tf"
	case has(`(?m)^(param|resource|module|targetScope|var)\s+\w+.*'[\w.]+/[\w./]+@`) || has(`(?m)^targetScope\s*=`):
		return "main.bicep"
	case has(`(?m)^services:\s*$`):
		return "docker-compose.yml"
	case has(`(?m)^apiVersion:\s*\S`) && has(`(?m)^kind:\s*\S`):
		return "manifest.yaml"
	case has(`(?mi)^FROM\s+\S+`) && has(`(?mi)^(RUN|CMD|ENTRYPOINT|COPY|WORKDIR)\s`):
		return "Dockerfile"
	case has(`^#!.*\b(ba|z)?sh\b`):
		return "script.sh"
	case has(`^#!.*python`):
		return "script.py"
	case has(`^#!.*node`):
		return "script.js"
	case has(`(?mi)\b(Write-Host|Get-ChildItem|Set-ExecutionPolicy|Invoke-WebRequest|New-Item|\$env:[A-Za-z_])`):
		return "script.ps1"
	case has(`(?m)^\s*(def\s+\w+\(|import\s+\w+|from\s+[\w.]+\s+import\s)`) || has(`(?m)^if __name__ == `):
		return "script.py"
	case has(`(?m)\b(require\(['"]|module\.exports|console\.log\(|=>\s*[{(]|^\s*(const|let|var)\s+\w+\s*=|^\s*import\s+.*\s+from\s+['"])`):
		return "script.js"
	case has(`(?m)^[A-Za-z0-9_.-]+\s*(==|>=|~=)\s*\d`) && !strings.Contains(t, "{"):
		return "requirements.txt"
	case has(`(?m)^\s*(sudo|apt(-get)?|curl|wget|export|echo|chmod|cd|mkdir|az|aws|kubectl|docker)\s`):
		return "script.sh"
	}
	return ""
}

func startsWithShebang(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 2)
	n, _ := f.Read(head)
	return n == 2 && string(head) == "#!"
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
