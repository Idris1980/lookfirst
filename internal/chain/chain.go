// Package chain puts what the code would do in the order it happens: the
// scripts that are run, each command in them, the templates they hand to
// the cloud and everything those build, the code and images uploaded, and
// what is deleted at the end. Each step carries the risks it brings, so
// the reader can follow the whole chain before anything is run.
package chain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// Item is one step, with the steps it leads to inside it.
type Item struct {
	Num     string // "2", "2.3"
	Says    string
	File    string
	Line    int
	Code    string
	Creates []string // box ids
	Changes []string
	From    string // a folder or file on your computer it takes
	Deletes bool
	Skipped bool   // a template resource not built this time
	Note    string // such as "only when deployContainer is true"
	Risks   []model.Finding
	Sub     []Item
	// Needs are what it expects to be there and nothing before it in the
	// code creates; Uses are what an earlier script creates for it.
	Needs    []string
	Uses     []string
	Existing bool // a template part that is only used, not created
}

// Chain is everything that happens when one thing is run: a script, or a
// template that no script deploys.
type Chain struct {
	Title string
	File  string
	Items []Item
}

// Build finds the chains in everything that was read.
func Build(g *model.Graph) []Chain {
	b := &builder{g: g, byFile: map[string][]model.Step{}, built: map[string]bool{}, deployed: map[string]bool{}, madeBy: map[string]made{}}
	for _, s := range g.Steps {
		b.byFile[key(s.File)] = append(b.byFile[key(s.File)], s)
	}
	// The scripts no other script runs are where it starts.
	runBy := map[string]bool{}
	for _, s := range g.Steps {
		if s.Runs != "" {
			runBy[key(join(s.File, s.Runs))] = true
		}
	}
	var entries []string
	seen := map[string]bool{}
	for _, s := range g.Steps {
		k := key(s.File)
		if !runBy[k] && !seen[k] {
			seen[k] = true
			entries = append(entries, s.File)
		}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		ri, rj := rank(entries[i]), rank(entries[j])
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(entries[i]) < strings.ToLower(entries[j])
	})
	entries = afterOrder(entries, g.After)

	// Two scripts with the same name are told apart by their folder.
	title := func(f string) string {
		base := filepath.Base(f)
		for _, other := range append(append([]string{}, entries...), b.templateFiles()...) {
			if key(other) != key(f) && strings.EqualFold(filepath.Base(other), base) {
				return filepath.Base(filepath.Dir(f)) + "/" + base
			}
		}
		return base
	}
	var out []Chain
	for _, f := range entries {
		b.built = map[string]bool{}
		b.title = "When " + title(f) + " is run"
		b.told = map[string]bool{}
		items := b.script(f, "", map[string]bool{})
		if len(items) > 0 {
			out = append(out, Chain{Title: "When " + title(f) + " is run", File: f, Items: items})
		}
	}
	// Templates and other infrastructure code no script deploys.
	for _, f := range b.templateFiles() {
		if b.deployed[key(f)] {
			continue
		}
		b.built = map[string]bool{}
		b.title = "When " + title(f) + " " + deployWord(f, b.g)
		b.told = map[string]bool{}
		items := b.template(f, nil, "")
		if len(items) > 0 {
			out = append(out, Chain{Title: "When " + title(f) + " " + deployWord(f, b.g), File: f, Items: items})
		}
	}
	return out
}

type builder struct {
	g        *model.Graph
	byFile   map[string][]model.Step
	built    map[string]bool // what this chain has built so far
	deployed map[string]bool // templates some script deploys
	// madeBy says, by lower-case name, which step of which script makes
	// something, across the scripts in the order they run.
	madeBy map[string]made
	title  string          // the chain being built
	file   string          // its file, to name it in what other scripts use
	told   map[string]bool // what this chain has already said it uses
}

// made is where something is made: the step and the script it is in.
type made struct{ chain, step, file string }

// rank puts scripts that build first and scripts that tear down last.
func rank(file string) int {
	n := strings.ToLower(filepath.Base(file))
	switch {
	case regexp.MustCompile(`destroy|delete|cleanup|clean-up|teardown|tear-down|remove|uninstall|riv|ta-bort`).MatchString(n):
		return 3
	case regexp.MustCompile(`^0*\d`).MatchString(n):
		return 1
	case regexp.MustCompile(`deploy|setup|install|bootstrap|create|init|main|start|build|provision`).MatchString(n):
		return 0
	}
	return 2
}

func key(p string) string { return strings.ToLower(filepath.Clean(p)) }

func join(script, rel string) string {
	if filepath.IsAbs(rel) {
		return rel
	}
	return filepath.Join(filepath.Dir(script), filepath.FromSlash(rel))
}

// script is the steps of one script, with what each leads to.
func (b *builder) script(file, prefix string, running map[string]bool) []Item {
	if running[key(file)] {
		return nil
	}
	running[key(file)] = true
	defer delete(running, key(file))

	var items []Item
	lastTemplate := ""
	for i, s := range b.byFile[key(file)] {
		it := Item{Num: num(prefix, i+1), Says: s.Says, File: s.File, Line: s.Line, Code: s.Code,
			Creates: s.Creates, Changes: s.Changes, Deletes: s.Deletes}
		for _, id := range s.Creates {
			b.built[id] = true
		}
		// What it needs: there already, made by an earlier script, or
		// made by nothing in the code at all.
		for _, need := range s.Needs {
			kind, name, _ := strings.Cut(need, "|")
			what := kindWords(kind) + " " + name
			switch by, ok := b.madeBy[strings.ToLower(name)]; {
			case !ok:
				it.Needs = append(it.Needs, what)
			case by.chain != b.title && !b.told[strings.ToLower(name)]:
				// Said once per script: the first step that relies on it.
				b.told[strings.ToLower(name)] = true
				it.Uses = append(it.Uses, fmt.Sprintf("%s, made in step %s of %s, which must run first", what, by.step, filepath.Base(by.file)))
			}
		}
		for _, m := range s.Made {
			_, name, _ := strings.Cut(m, "|")
			if _, ok := b.madeBy[strings.ToLower(name)]; !ok {
				b.madeBy[strings.ToLower(name)] = made{b.title, it.Num, file}
			}
		}
		if s.From != "" {
			it.From = s.From
			it.Risks = append(it.Risks, b.risksIn(join(file, s.From))...)
		}
		// What it changes, named by a template's output.
		if s.Output != "" && lastTemplate != "" {
			if id, ok := b.g.Outputs[lastTemplate+"|"+s.Output]; ok || b.outputOf(lastTemplate, s.Output) != "" {
				if !ok {
					id = b.outputOf(lastTemplate, s.Output)
				}
				it.Changes = append(it.Changes, id)
				if n := b.g.Node(id); n != nil {
					it.Says = strings.ReplaceAll(it.Says, "«"+s.Output+"»", n.Name)
				}
			}
		}
		switch {
		case s.Runs != "":
			it.Sub = b.script(join(file, s.Runs), it.Num, running)
			if len(b.byFile[key(join(file, s.Runs))]) == 0 {
				it.Note = "LookFirst has not read this script (it is not among the files), so what it does is not shown. Read it before running this."
			}
		case s.Template != "":
			t := b.templatePath(join(file, s.Template))
			lastTemplate = t
			if b.deployed == nil {
				b.deployed = map[string]bool{}
			}
			b.deployed[key(t)] = true
			it.Sub = b.template(t, b.params(file, t, s.Params), it.Num)
			if len(it.Sub) == 0 {
				it.Note = "LookFirst did not find this template among the files it read, so what it builds is not shown."
			}
		}
		// An output no template named stays as its name.
		it.Says = strings.NewReplacer("«", "", "»", "").Replace(it.Says)
		it.Risks = dedupe(append(it.Risks, b.risksAt(s.File, s.Line, it.Creates)...))
		items = append(items, it)
	}
	return items
}

// outputOf finds an output by name case-insensitively, as scripts often
// write it differently.
func (b *builder) outputOf(template, name string) string {
	for k, v := range b.g.Outputs {
		if strings.EqualFold(k, template+"|"+name) {
			return v
		}
	}
	return ""
}

// templatePath matches a path a script names to a file that was read,
// also when the script names a folder (Terraform, Kubernetes).
func (b *builder) templatePath(p string) string {
	want := key(p)
	for _, n := range b.g.Nodes {
		if n.File != "" && key(n.File) == want {
			return n.File
		}
	}
	for _, f := range b.templateFiles() {
		if strings.HasPrefix(key(f), want+string(filepath.Separator)) {
			return filepath.Dir(f) // a folder of templates
		}
	}
	return p
}

// templateFiles are the files with infrastructure that is not a script's.
func (b *builder) templateFiles() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range b.g.Nodes {
		if n.File == "" || n.ID == model.InternetID || len(b.byFile[key(n.File)]) > 0 || seen[key(n.File)] {
			continue
		}
		if n.Cloud == "" && n.Type == "" {
			continue // code that runs inside something, not something built
		}
		seen[key(n.File)] = true
		out = append(out, n.File)
	}
	return out
}

// params are the values a deployment gets: from the command line, then a
// parameters file, then the template's defaults.
func (b *builder) params(script, template string, given map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range b.g.Defaults {
		if f, name, ok := strings.Cut(k, "|"); ok && key(f) == key(template) {
			out[name] = v
		}
	}
	if f, ok := given["@"]; ok {
		if data, err := os.ReadFile(join(script, f)); err == nil {
			var pf struct {
				Parameters map[string]struct {
					Value any `json:"value"`
				} `json:"parameters"`
			}
			if json.Unmarshal(data, &pf) == nil {
				for k, v := range pf.Parameters {
					out[k] = fmt.Sprint(v.Value)
				}
			}
		}
	}
	for k, v := range given {
		if k != "@" {
			out[k] = v
		}
	}
	return out
}

// template is what a template builds, in the order the cloud must build
// it: what something needs comes before it.
func (b *builder) template(file string, params map[string]string, prefix string) []Item {
	inFile := func(n *model.Node) bool {
		if n.File == "" || n.ID == model.InternetID {
			return false
		}
		k, f := key(n.File), key(file)
		return k == f || strings.HasPrefix(k, f+string(filepath.Separator))
	}
	var nodes []*model.Node
	in := map[string]bool{}
	for _, n := range b.g.Nodes {
		if inFile(n) && n.Type != "principal" && n.Type != "resource group" {
			nodes = append(nodes, n)
			in[n.ID] = true
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].File != nodes[j].File {
			return nodes[i].File < nodes[j].File
		}
		return nodes[i].Line < nodes[j].Line
	})
	nodes = dependencyOrder(nodes, b.g.Edges, in)

	var items []Item
	again := 0
	for _, n := range nodes {
		it := Item{Says: says(n), File: n.File, Line: n.Line, Creates: []string{n.ID}}
		if n.Existing {
			// Only read or used: it must be there before the code runs.
			kind, _, _ := strings.Cut(n.Friendly, " · ")
			it.Says = "Uses the existing " + strings.TrimSuffix(strings.TrimSuffix(kind, " in AWS"), " in Azure") + " " + n.Name
			it.Note = "this code does not create it, so it must already be there"
			it.Existing, it.Creates = true, nil
			items = append(items, it)
			continue
		}
		if c := n.Condition; c != "" {
			on, known := decide(c, params)
			switch {
			case !known:
				it.Note = "only when " + condWords(c) + "; LookFirst could not tell whether it is"
			case !on:
				it.Skipped = true
				it.Note = "not built this time: only when " + condWords(c)
			default:
				it.Note = "built this time, because " + condWords(c)
			}
		}
		if !it.Skipped && b.built[n.ID] {
			again++
			continue // already there from an earlier step
		}
		if !it.Skipped {
			if _, ok := b.madeBy[strings.ToLower(n.Name)]; !ok {
				b.madeBy[strings.ToLower(n.Name)] = made{b.title, prefix, n.File}
			}
			b.built[n.ID] = true
			it.Risks = dedupe(b.risksAt(n.File, -1, it.Creates, nil))
		}
		items = append(items, it)
	}
	// Number what is built; what is skipped keeps its place unnumbered.
	k := 0
	for i := range items {
		if !items[i].Skipped && !items[i].Existing {
			k++
			items[i].Num = num(prefix, k)
		}
	}
	if again > 0 {
		k++
		items = append(items, Item{Num: num(prefix, k), Says: fmt.Sprintf("Updates the %d things an earlier step built from this template, with the new parameters", again)})
	}
	return items
}

func num(prefix string, i int) string {
	if prefix == "" {
		return fmt.Sprint(i)
	}
	return fmt.Sprintf("%s.%d", prefix, i)
}

// decide works out a condition such as "deployContainer" or "!x".
func decide(cond string, params map[string]string) (on, known bool) {
	neg := strings.HasPrefix(cond, "!")
	name := strings.TrimPrefix(cond, "!")
	if cond == "false" {
		return false, true
	}
	v, ok := params[name]
	if !ok {
		return false, false
	}
	b := strings.EqualFold(v, "true")
	if !b && !strings.EqualFold(v, "false") {
		return false, false
	}
	return b != neg, true
}

func condWords(c string) string {
	if strings.HasPrefix(c, "!") {
		return strings.TrimPrefix(c, "!") + " is false"
	}
	if c == "false" {
		return "never (the condition is false)"
	}
	return c + " is true"
}

// says is a resource's step in words.
func says(n *model.Node) string {
	if n.Note != "" {
		return strings.ToUpper(n.Note[:1]) + n.Note[1:]
	}
	kind, inside, _ := strings.Cut(n.Friendly, " · ")
	if n.Type == "compose service" {
		switch {
		case inside == "built here":
			return "Builds the container " + n.Name + " from its Dockerfile and starts it"
		case inside != "":
			return "Starts the container " + n.Name + " from the image " + inside
		}
		return "Starts the container " + n.Name
	}
	kind = strings.TrimSuffix(strings.TrimSuffix(kind, " in AWS"), " in Azure")
	s := "Creates the " + kind + " " + n.Name
	if n.Address != "" && strings.Contains(n.Address, "/") {
		s += " (" + n.Address + ")"
	}
	if inside != "" {
		s += ", with " + inside + " in it"
	}
	return s
}

// dependencyOrder puts what a thing points at before it, keeping the
// order of the code where nothing decides.
func dependencyOrder(nodes []*model.Node, edges []model.Edge, in map[string]bool) []*model.Node {
	needs := map[string][]string{}
	for _, e := range edges {
		if in[e.From] && in[e.To] && e.From != e.To && e.Kind != model.Access {
			needs[e.From] = append(needs[e.From], e.To)
		}
	}
	var out []*model.Node
	done, visiting := map[string]bool{}, map[string]bool{}
	byID := map[string]*model.Node{}
	for _, n := range nodes {
		byID[n.ID] = n
	}
	var visit func(n *model.Node)
	visit = func(n *model.Node) {
		if done[n.ID] || visiting[n.ID] {
			return
		}
		visiting[n.ID] = true
		for _, m := range needs[n.ID] {
			if dep := byID[m]; dep != nil {
				visit(dep)
			}
		}
		visiting[n.ID] = false
		done[n.ID] = true
		out = append(out, n)
	}
	for _, n := range nodes {
		visit(n)
	}
	return out
}

// risksAt are the findings on a line of a script, or on the boxes a step
// builds or changes.
func (b *builder) risksAt(file string, line int, ids ...[]string) []model.Finding {
	want := map[string]bool{}
	for _, list := range ids {
		for _, id := range list {
			want[id] = true
		}
	}
	var out []model.Finding
	for _, f := range b.g.Findings {
		onLine := line > 0 && f.Line == line && key(f.File) == key(file) && f.NodeID == ""
		if want[f.NodeID] || onLine || (line > 0 && f.Line == line && key(f.File) == key(file)) {
			out = append(out, f)
		}
	}
	return out
}

// risksIn are the findings in the files of a folder the step takes from
// your computer, such as the code it uploads or the Dockerfile it builds.
func (b *builder) risksIn(dir string) []model.Finding {
	d := key(dir)
	var out []model.Finding
	for _, f := range b.g.Findings {
		k := key(f.File)
		if k == d || strings.HasPrefix(k, d+string(filepath.Separator)) {
			out = append(out, f)
		}
	}
	return out
}

// afterOrder moves a script after the scripts it says it comes after, such
// as "Körs EFTER natverk-novatrix.sh" or "Run setup.sh first".
func afterOrder(files []string, after map[string][]string) []string {
	var out []string
	placed := map[string]bool{}
	var place func(f string, depth int)
	place = func(f string, depth int) {
		if placed[key(f)] || depth > len(files) {
			return
		}
		for _, name := range after[f] {
			for _, g := range files {
				if strings.EqualFold(filepath.Base(g), name) && key(g) != key(f) {
					place(g, depth+1)
				}
			}
		}
		if !placed[key(f)] {
			placed[key(f)] = true
			out = append(out, f)
		}
	}
	for _, f := range files {
		place(f, 0)
	}
	return out
}

// deployWord says how a file of infrastructure is put to use.
func deployWord(f string, g *model.Graph) string {
	for _, n := range g.Nodes {
		if key(n.File) != key(f) {
			continue
		}
		switch {
		case strings.HasPrefix(n.Type, "compose"):
			return "is started (docker compose up)"
		case strings.HasPrefix(n.Type, "Kubernetes"):
			return "is applied to a Kubernetes cluster"
		case strings.HasSuffix(strings.ToLower(f), ".tf"):
			return "is applied (terraform apply)"
		}
	}
	return "is deployed"
}

// dedupe keeps one of each kind of risk on a step: the worst first, and
// the same title only once.
func dedupe(risks []model.Finding) []model.Finding {
	sort.SliceStable(risks, func(i, j int) bool { return risks[i].Severity < risks[j].Severity })
	seen := map[string]bool{}
	var out []model.Finding
	for _, r := range risks {
		if !seen[r.Title] {
			seen[r.Title] = true
			out = append(out, r)
		}
	}
	return out
}

// kindWords names a kind of thing a command needs.
func kindWords(kind string) string {
	switch kind {
	case "group":
		return "the resource group"
	case "network":
		return "the virtual network"
	case "subnet":
		return "the subnet"
	case "shield":
		return "the security group"
	case "plan":
		return "the App Service plan"
	case "registry":
		return "the container registry"
	case "key":
		return "the key vault"
	case "storage":
		return "the storage account"
	case "database":
		return "the database server"
	case "image":
		return "the machine image"
	}
	return "the " + kind
}
