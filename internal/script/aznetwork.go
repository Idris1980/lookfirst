package script

import (
	"regexp"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
)

// What az commands say about the network: which network and subnet
// something is placed in, which security group protects it, and the parts
// az vm create makes on its own when the command does not name them. The
// network picture draws from these lines; the parts made on their own are
// listed with everything else that is created.

// azID is the id of what an az command creates, by kind and name, also
// when another script in the folder creates it.
func azID(kind, name string) string { return "azure." + kind + "." + name }

func (s *scan) azNetworkLinks(args, id, kind, cmd string, ln int) {
	flag := func(names ...string) string {
		v, _ := azFlag(args, names...)
		return v
	}
	vnet, subnet := flag("--vnet-name"), flag("--subnet")
	// --subnet may also be a full id: .../virtualNetworks/v/subnets/s.
	if i := strings.LastIndex(subnet, "/subnets/"); i >= 0 {
		subnet = subnet[i+len("/subnets/"):]
	}
	switch {
	case kind == "subnet":
		if vnet != "" {
			s.g.ConnectKind(id, azID("network", vnet), "in network", model.Hosting)
		}
	case subnet != "":
		s.g.ConnectKind(id, azID("subnet", subnet), "in subnet", model.Hosting)
	case vnet != "":
		s.g.ConnectKind(id, azID("network", vnet), "in network", model.Hosting)
	}
	if nsg := flag("--nsg", "--network-security-group"); nsg != "" {
		s.g.ConnectKind(id, azID("shield", nsg), "protected by", model.Hosting)
	}

	add := func(n *model.Node) {
		n.Cloud, n.File, n.Line = "azure", s.f.Path, ln
		n.Category = cloudColumn(n.Kind)
		s.g.AddNode(n)
	}
	switch cmd {
	case "network vnet create":
		// --subnet-name makes the first subnet in the same command.
		if name := flag("--subnet-name"); name != "" {
			sid := azID("subnet", name)
			add(&model.Node{ID: sid, Name: name, Kind: "subnet", Friendly: "subnet in Azure", Code: "az network vnet create --subnet-name",
				Type: "az network vnet create", Address: flag("--subnet-prefixes", "--subnet-prefix")})
			s.g.ConnectKind(sid, id, "in network", model.Hosting)
		}
	case "vm create":
		s.azVMParts(args, id, vnet, subnet, ln, add)
	}
}

// azVMParts adds what az vm create makes when the command does not name
// it: a virtual network and subnet, a network security group, a public IP
// address, a network card and the OS disk, as Microsoft's documentation
// for az vm create describes.
func (s *scan) azVMParts(args, id, vnet, subnet string, ln int, add func(*model.Node)) {
	name := strings.TrimPrefix(id, "azure.vm.")
	made := func(what string) string { return what + " in Azure" }
	const code = "made by az vm create"
	if vnet == "" && subnet == "" {
		vid, sid := azID("network", name+"VNET"), azID("subnet", name+"Subnet")
		add(&model.Node{ID: vid, Name: name + "VNET", Kind: "network", Friendly: made("virtual network"), Code: code, Type: "az vm create", Address: "10.0.0.0/16"})
		add(&model.Node{ID: sid, Name: name + "Subnet", Kind: "subnet", Friendly: made("subnet"), Code: code, Type: "az vm create", Address: "10.0.0.0/24"})
		s.g.ConnectKind(sid, vid, "in network", model.Hosting)
		s.g.ConnectKind(id, sid, "in subnet", model.Hosting)
	}
	if _, named := azFlag(args, "--nsg"); !named {
		nid := azID("shield", name+"NSG")
		add(&model.Node{ID: nid, Name: name + "NSG", Kind: "shield", Friendly: made("network security group"), Code: code, Type: "az vm create"})
		s.g.ConnectKind(id, nid, "protected by", model.Hosting)
	}
	if v, named := azFlag(args, "--public-ip-address"); !named || v != "" {
		add(&model.Node{ID: azID("publicip", name+"PublicIP"), Name: name + "PublicIP", Kind: "publicip", Friendly: made("public IP address"),
			Code: code, Type: "az vm create", Hidden: true})
		s.g.Expose(id, "", false)
	}
	if _, named := azFlag(args, "--nics"); !named {
		add(&model.Node{ID: azID("nic", name+"VMNic"), Name: name + "VMNic", Kind: "nic", Friendly: made("network card"),
			Code: code, Type: "az vm create", Hidden: true})
	}
	disk, _ := azFlag(args, "--os-disk-name")
	if disk == "" {
		disk = name + "_OsDisk"
	}
	add(&model.Node{ID: azID("disk", disk), Name: disk, Kind: "storage", Friendly: made("OS disk"), Code: code, Type: "az vm create", Hidden: true})
}

var (
	shVar = regexp.MustCompile(`^\s*(?:export\s+|local\s+|readonly\s+|declare\s+)?(\w+)=(?:"([^"]*)"|'([^']*)'|([^\s;"'` + "`" + `]*))\s*$`)
	psVar = regexp.MustCompile(`(?i)^\s*\$(\w+)\s*=\s*(?:"([^"]*)"|'([^']*)')\s*$`)
	// ${RG:-rg-novatrix-v34}: the default when the variable is not set.
	withDefault = regexp.MustCompile(`^\$\{\w+:-([^}]*)\}$`)
	useVar      = regexp.MustCompile(`\$\{(\w+)\}|\$(\w+)`)
)

// stringVars collects variables set to plain text, such as VNET="vnet-a"
// or $vmName = "vm-web", so names given through them can be read.
func stringVars(lines []line) map[string]string {
	vars := map[string]string{}
	for _, l := range lines {
		var name, value string
		if m := psVar.FindStringSubmatch(l.code); m != nil {
			name, value = m[1], m[2]+m[3]
		} else if m := shVar.FindStringSubmatch(l.code); m != nil {
			name, value = m[1], m[2]+m[3]+m[4]
		} else {
			continue
		}
		if d := withDefault.FindStringSubmatch(value); d != nil {
			value = d[1]
		}
		if strings.Contains(value, "$(") {
			continue // set by running something
		}
		vars[strings.ToLower(name)] = expandVars(value, vars)
	}
	return vars
}

// expandVars puts the values of known text variables into a command.
func expandVars(s string, vars map[string]string) string {
	if len(vars) == 0 {
		return s
	}
	return useVar.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.ToLower(strings.Trim(m, "${}"))
		if v, ok := vars[name]; ok && !strings.Contains(v, " ") {
			return v
		}
		return m
	})
}

// ruleBook keeps the NSG rules that let in only some addresses, by NSG
// and rule name, so that az network nsg rule update in any script of the
// folder can change where a rule lets traffic in from.
type ruleBook struct {
	rules   map[string]*nsgRule
	updates []nsgUpdate
}

type nsgRule struct {
	node  string
	from  []string
	label string
}

type nsgUpdate struct {
	key     string
	sources []string
}

func ruleKey(args string) string {
	nsg, _ := azFlag(args, "--nsg-name")
	name, _ := azFlag(args, "--name", "-n")
	return strings.ToLower(nsg + "/" + name)
}

func (b *ruleBook) created(args, node string, sources, ports []string) {
	if b.rules == nil {
		b.rules = map[string]*nsgRule{}
	}
	r := &nsgRule{node: node, label: risk.PortLabel(ports)}
	for _, src := range sources {
		r.from = append(r.from, model.AddressSource(src))
	}
	b.rules[ruleKey(args)] = r
}

func (b *ruleBook) updated(args string, sources []string) {
	b.updates = append(b.updates, nsgUpdate{ruleKey(args), sources})
}

// apply moves the lines of each updated rule to its new sources.
func (b *ruleBook) apply(g *model.Graph) {
	for _, u := range b.updates {
		r, ok := b.rules[u.key]
		if !ok || risk.FromAnywhere(u.sources) {
			continue
		}
		gone := map[string]bool{}
		for _, f := range r.from {
			gone[f] = true
		}
		kept := g.Edges[:0]
		for _, e := range g.Edges {
			if !(gone[e.From] && e.To == r.node && e.Label == r.label) {
				kept = append(kept, e)
			}
		}
		g.Edges = kept
		r.from = nil
		for _, src := range u.sources {
			r.from = append(r.from, model.AddressSource(src))
			g.ConnectKind(model.AddressSource(src), r.node, r.label, model.Flow)
		}
	}
}
