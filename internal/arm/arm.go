// Package arm reads Azure Resource Manager templates, and Bicep files by
// compiling them to ARM locally first, and works out what they would build.
package arm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
	"github.com/Idris1980/lookfirst/internal/source"
)

const secretFix = "use a parameter of type securestring, filled from a key vault"

type entry struct {
	kind, friendly string
	category       model.Category
}

var catalog = map[string]entry{
	"microsoft.network/virtualnetworks":                         {"network", "virtual network", model.Network},
	"microsoft.network/virtualnetworks/subnets":                 {"subnet", "subnet", model.Network},
	"microsoft.network/networkinterfaces":                       {"nic", "network interface", model.Network},
	"microsoft.network/publicipaddresses":                       {"publicip", "public IP address", model.Network},
	"microsoft.network/loadbalancers":                           {"loadbalancer", "load balancer", model.Network},
	"microsoft.network/applicationgateways":                     {"loadbalancer", "application gateway", model.Network},
	"microsoft.network/privateendpoints":                        {"nic", "private endpoint", model.Network},
	"microsoft.network/networksecuritygroups":                   {"shield", "network security group", model.Security},
	"microsoft.network/networksecuritygroups/securityrules":     {"shield", "security rule", model.Security},
	"microsoft.network/azurefirewalls":                          {"firewall", "firewall", model.Security},
	"microsoft.keyvault/vaults":                                 {"key", "key vault", model.Security},
	"microsoft.keyvault/vaults/secrets":                         {"key", "key vault secret", model.Security},
	"microsoft.managedidentity/userassignedidentities":          {"identity", "managed identity", model.Security},
	"microsoft.authorization/roleassignments":                   {"identity", "role assignment", model.Security},
	"microsoft.compute/virtualmachines":                         {"vm", "virtual machine", model.Compute},
	"microsoft.containerservice/managedclusters":                {"kubernetes", "Kubernetes cluster", model.Compute},
	"microsoft.containerinstance/containergroups":               {"container", "container group", model.Compute},
	"microsoft.app/containerapps":                               {"container", "container app", model.Compute},
	"microsoft.app/managedenvironments":                         {"plan", "container apps environment", model.Compute},
	"microsoft.web/serverfarms":                                 {"plan", "App Service plan", model.Compute},
	"microsoft.web/sites":                                       {"webapp", "web app", model.Compute},
	"microsoft.storage/storageaccounts":                         {"storage", "storage account", model.Data},
	"microsoft.storage/storageaccounts/blobservices/containers": {"storage", "storage container", model.Data},
	"microsoft.sql/servers":                                     {"database", "SQL server", model.Data},
	"microsoft.sql/servers/databases":                           {"database", "SQL database", model.Data},
	"microsoft.sql/servers/firewallrules":                       {"firewall", "SQL firewall rule", model.Data},
	"microsoft.dbforpostgresql/flexibleservers":                 {"database", "PostgreSQL server", model.Data},
	"microsoft.dbforpostgresql/flexibleservers/firewallrules":   {"firewall", "PostgreSQL firewall rule", model.Data},
	"microsoft.dbformysql/flexibleservers":                      {"database", "MySQL server", model.Data},
	"microsoft.documentdb/databaseaccounts":                     {"database", "Cosmos DB account", model.Data},
	"microsoft.insights/components":                             {"monitor", "Application Insights", model.Other},
	"microsoft.operationalinsights/workspaces":                  {"monitor", "Log Analytics workspace", model.Other},
	"microsoft.web/sites/networkconfig":                         {"subnet", "VNet integration", model.Network},
	"microsoft.web/sites/config":                                {"generic", "app settings", model.Compute},
	"microsoft.storage/storageaccounts/managementpolicies":      {"storage", "storage lifecycle rules", model.Data},
	"microsoft.network/privatednszones":                         {"dns", "private DNS zone", model.Network},
	"microsoft.network/privatednszones/virtualnetworklinks":     {"dns", "DNS zone link to VNet", model.Network},
	"microsoft.network/privateendpoints/privatednszonegroups":   {"dns", "private endpoint DNS", model.Network},
	"microsoft.network/dnszones":                                {"dns", "DNS zone", model.Network},
	"microsoft.relay/namespaces":                                {"relay", "Azure Relay", model.Network},
	"microsoft.relay/namespaces/hybridconnections":              {"relay", "Relay connection", model.Network},
	"microsoft.sql/servers/connectionpolicies":                  {"database", "SQL connection policy", model.Data},
	"microsoft.network/natgateways":                             {"loadbalancer", "NAT gateway", model.Network},
	"microsoft.network/bastionhosts":                            {"shield", "Azure Bastion", model.Security},
	"microsoft.containerregistry/registries":                    {"container", "container registry", model.Compute},
	"microsoft.servicebus/namespaces":                           {"relay", "Service Bus", model.Data},
	"microsoft.eventhub/namespaces":                             {"relay", "Event Hubs", model.Data},
	"microsoft.cache/redis":                                     {"database", "Redis cache", model.Data},
}

var hidden = map[string]bool{
	"microsoft.resources/deployments":                      true,
	"microsoft.storage/storageaccounts/blobservices":       true,
	"microsoft.resources/resourcegroups":                   true,
	"microsoft.insights/diagnosticsettings":                true,
	"microsoft.network/networkinterfaces/ipconfigurations": true,
}

func lookup(t string) entry {
	if e, ok := catalog[strings.ToLower(t)]; ok {
		return e
	}
	parts := strings.Split(t, "/")
	return entry{"generic", strings.ToLower(parts[len(parts)-1]), model.Other}
}

type template struct {
	Parameters map[string]struct {
		Type         string `json:"type"`
		DefaultValue any    `json:"defaultValue"`
	} `json:"parameters"`
	Variables map[string]any  `json:"variables"`
	Resources json.RawMessage `json:"resources"`
}

type resource struct {
	Type       string            `json:"type"`
	Name       string            `json:"name"`
	DependsOn  []string          `json:"dependsOn"`
	Properties map[string]any    `json:"properties"`
	Resources  []json.RawMessage `json:"resources"`
	Kind       string            `json:"kind"`
}

type item struct {
	typ, rawName, name string
	symbol             string // the Bicep symbolic name, e.g. "sql"
	res                resource
	line               int
}

type reader struct {
	g     *model.Graph
	file  string
	src   []byte // what line numbers point into
	tmpl  template
	items []*item
	seen  map[string]int // how many of each type have been placed, for line lookup
}

func Read(files []source.File) *model.Graph {
	g := &model.Graph{}
	for _, f := range files {
		g.Sources = append(g.Sources, f.Path)
		data := f.Data
		bicep := f.Kind == source.Bicep
		if bicep {
			var err error
			if data, err = compileBicep(f.Path); err != nil {
				g.Add(model.Medium, "", "Bicep file could not be read", err.Error(), f.Path, 0)
				continue
			}
		}
		r := &reader{g: g, file: f.Path, src: f.Data, seen: map[string]int{}}
		if err := json.Unmarshal(data, &r.tmpl); err != nil {
			g.Add(model.High, "", "Syntax error", err.Error(), f.Path, 0)
			continue
		}
		r.read(bicep)
	}
	return g
}

// compileBicep turns Bicep into ARM JSON with the Bicep compiler on this
// machine. --no-restore keeps it from downloading modules.
func compileBicep(path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var cmd *exec.Cmd
	if p, err := exec.LookPath("bicep"); err == nil {
		cmd = exec.CommandContext(ctx, p, "build", path, "--stdout", "--no-restore")
	} else if p, err := exec.LookPath("az"); err == nil {
		cmd = exec.CommandContext(ctx, p, "bicep", "build", "--file", path, "--stdout", "--no-restore")
	} else {
		return nil, fmt.Errorf("the Bicep compiler was not found. Install it with 'az bicep install', or compile the file to JSON first with 'az bicep build'")
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("the Bicep compiler reported: %s", msg)
	}
	return stdout.Bytes(), nil
}

func (r *reader) read(bicep bool) {
	// languageVersion 2.0 templates keep resources in an object keyed by
	// symbolic name; older ones use a list.
	var list []json.RawMessage
	if err := json.Unmarshal(r.tmpl.Resources, &list); err != nil {
		var byName map[string]json.RawMessage
		if json.Unmarshal(r.tmpl.Resources, &byName) == nil {
			for _, v := range byName {
				list = append(list, v)
			}
		}
	}
	for _, raw := range list {
		r.collect(raw, "", "", bicep)
	}

	for _, it := range r.items {
		if hidden[strings.ToLower(it.typ)] {
			continue
		}
		e := lookup(it.typ)
		// Show the name the resource gets in Azure when the code spells it
		// out; when it is computed, the name it has in the Bicep code.
		name, code := shortName(it.name), it.typ
		if it.symbol != "" {
			code = it.symbol + ": " + it.typ
			if strings.HasPrefix(it.name, "[") {
				name = it.symbol
			}
		}
		r.g.AddNode(&model.Node{
			ID: id(it.typ, it.name), Name: name, Kind: e.kind, Friendly: e.friendly, Code: code,
			Category: e.category, File: r.file, Line: it.line,
		})
	}
	for _, it := range r.items {
		me := id(it.typ, it.name)
		for _, d := range it.res.DependsOn {
			if to := r.resolveRef(d); to != "" {
				r.g.Connect(me, to, "", false)
			}
		}
		walkStrings(it.res.Properties, func(_ string, s string) {
			for _, m := range resourceIDCall.FindAllString(s, -1) {
				if to := r.resolveRef(m); to != "" && to != me {
					r.g.Connect(me, to, "", false)
				}
			}
		})
		r.rules(it)
	}
	r.parameters()
}

func (r *reader) collect(raw json.RawMessage, parentType, parentName string, bicep bool) {
	var res resource
	if json.Unmarshal(raw, &res) != nil || res.Type == "" {
		return
	}
	typ, rawName := res.Type, res.Name
	if parentType != "" && !strings.Contains(res.Type, ".") {
		typ = parentType + "/" + res.Type
		rawName = parentName + "/" + res.Name
	}
	it := &item{typ: typ, rawName: rawName, name: r.resolve(rawName), res: res}
	it.line, it.symbol = r.lineOf(typ, bicep)
	r.items = append(r.items, it)
	for _, child := range res.Resources {
		r.collect(child, typ, rawName, bicep)
	}
}

var bicepSymbol = regexp.MustCompile(`resource\s+([A-Za-z_]\w*)\s+$`)

// lineOf finds roughly where the nth resource of a type is in the source,
// and in Bicep also its symbolic name ("resource sql 'Microsoft.Sql/...").
func (r *reader) lineOf(typ string, bicep bool) (int, string) {
	needle := `"` + typ + `"`
	if bicep {
		needle = "'" + typ + "@"
	}
	n := r.seen[typ]
	r.seen[typ]++
	idx, from := -1, 0
	for i := 0; i <= n; i++ {
		j := bytes.Index(r.src[from:], []byte(needle))
		if j < 0 {
			break
		}
		idx = from + j
		from = idx + 1
	}
	if idx < 0 {
		return 0, ""
	}
	line := bytes.Count(r.src[:idx], []byte("\n")) + 1
	symbol := ""
	if bicep {
		start := bytes.LastIndexByte(r.src[:idx], '\n') + 1
		if m := bicepSymbol.FindSubmatch(r.src[start:idx]); m != nil {
			symbol = string(m[1])
		}
	}
	return line, symbol
}

var (
	paramCall      = regexp.MustCompile(`^\[?parameters\('([^']+)'\)\]?$`)
	varCall        = regexp.MustCompile(`^\[?variables\('([^']+)'\)\]?$`)
	resourceIDCall = regexp.MustCompile(`resourceId\([^()]*(\([^()]*\)[^()]*)*\)`)
	quoted         = regexp.MustCompile(`'([^']*)'|(parameters|variables)\('([^']+)'\)`)
)

// resolve turns "[parameters('vmName')]" into the parameter's default value
// where there is one, so boxes show real names.
func (r *reader) resolve(expr string) string {
	if m := paramCall.FindStringSubmatch(expr); m != nil {
		if p, ok := r.tmpl.Parameters[m[1]]; ok {
			if s, ok := p.DefaultValue.(string); ok && !strings.HasPrefix(s, "[") {
				return s
			}
		}
		return m[1]
	}
	if m := varCall.FindStringSubmatch(expr); m != nil {
		if s, ok := r.tmpl.Variables[m[1]].(string); ok && !strings.HasPrefix(s, "[") {
			return s
		}
		return m[1]
	}
	if strings.HasPrefix(expr, "[") {
		return expr
	}
	return expr
}

// resolveRef finds the resource a dependsOn entry or resourceId() points at.
func (r *reader) resolveRef(ref string) string {
	ref = strings.TrimSuffix(strings.TrimPrefix(ref, "["), "]")
	var typ string
	var names []string
	if strings.HasPrefix(ref, "resourceId(") {
		args := quoted.FindAllStringSubmatch(ref, -1)
		for _, a := range args {
			v := a[1]
			if a[2] != "" {
				v = r.resolve(a[2] + "('" + a[3] + "')")
			}
			if typ == "" && strings.Contains(v, "/") && strings.Contains(v, ".") {
				typ = v
				continue
			}
			if typ != "" {
				names = append(names, v)
			}
		}
	} else {
		// A plain name, or a symbolic name in languageVersion 2.0.
		for _, it := range r.items {
			if it.name == ref || it.rawName == ref || lastSegment(it.name) == ref {
				return id(it.typ, it.name)
			}
		}
		return ""
	}
	if typ == "" {
		return ""
	}
	name := strings.Join(names, "/")
	var only *item
	count := 0
	for _, it := range r.items {
		if !strings.EqualFold(it.typ, typ) {
			continue
		}
		if it.name == name {
			return id(it.typ, it.name)
		}
		only = it
		count++
	}
	if count == 1 {
		return id(only.typ, only.name)
	}
	return ""
}

func (r *reader) rules(it *item) {
	g, me, p, line := r.g, id(it.typ, it.name), it.res.Properties, it.line
	switch strings.ToLower(it.typ) {
	case "microsoft.network/networksecuritygroups":
		for _, sr := range list(p["securityRules"]) {
			if m, ok := sr.(map[string]any); ok {
				r.securityRule(me, mapOf(m["properties"]), line)
			}
		}
	case "microsoft.network/networksecuritygroups/securityrules":
		r.securityRule(me, p, line)
	case "microsoft.network/publicipaddresses":
		g.Expose(me, "", false)
		g.Add(model.Low, me, "Reachable from the internet",
			"This creates a public IP address. Whatever it is attached to can be reached from anywhere, so check which ports are open.", r.file, line)
	case "microsoft.storage/storageaccounts":
		if p["allowBlobPublicAccess"] == true {
			g.Add(model.High, me, "Files can be made public",
				"allowBlobPublicAccess: true lets containers in this account be readable by anyone on the internet. Set it to false.", r.file, line)
		}
		if p["supportsHttpsTrafficOnly"] == false {
			g.Add(model.Medium, me, "Unencrypted traffic is allowed",
				"Data can travel over plain HTTP. Set supportsHttpsTrafficOnly to true.", r.file, line)
		}
	case "microsoft.storage/storageaccounts/blobservices/containers":
		if a := str(p["publicAccess"]); strings.EqualFold(a, "Blob") || strings.EqualFold(a, "Container") {
			g.Expose(me, "public read", true)
			g.Add(model.High, me, "Files are public",
				"Anyone on the internet can read the files in this container without logging in. Use publicAccess: None.", r.file, line)
		}
	case "microsoft.sql/servers/firewallrules", "microsoft.dbforpostgresql/flexibleservers/firewallrules", "microsoft.dbformysql/flexibleservers/firewallrules":
		start, end := r.resolve(str(p["startIpAddress"])), r.resolve(str(p["endIpAddress"]))
		switch {
		case start == "0.0.0.0" && end == "255.255.255.255":
			g.Expose(me, "all addresses", true)
			g.Add(model.High, me, "Database open to the whole internet",
				"This firewall rule lets every IP address in the world try to connect to the database. Allow only the addresses that need it, or use a private endpoint.", r.file, line)
		case start == "0.0.0.0" && end == "0.0.0.0":
			g.Add(model.Medium, me, "Database open to all of Azure",
				"This rule allows every Azure service to connect, including services owned by other customers. Prefer a private endpoint.", r.file, line)
		}
	case "microsoft.compute/virtualmachines":
		// A written-out adminPassword is caught by the secret check below.
		if mapOf(mapOf(p["osProfile"])["linuxConfiguration"])["disablePasswordAuthentication"] == false {
			g.Add(model.Medium, me, "Password login is allowed",
				"Passwords can be guessed. Use SSH keys only by setting disablePasswordAuthentication to true.", r.file, line)
		}
	}

	for _, key := range []string{"minimumTlsVersion", "minimalTlsVersion", "minTlsVersion"} {
		if v := str(p[key]); v == "TLS1_0" || v == "TLS1_1" || v == "1.0" || v == "1.1" {
			g.Add(model.Medium, me, "Old TLS version allowed",
				fmt.Sprintf("%s = %q allows encryption that is no longer considered safe. Use TLS 1.2 or newer.", key, v), r.file, line)
		}
	}
	walkStrings(p, func(key, s string) {
		if !strings.HasPrefix(s, "[") {
			risk.CheckSecret(g, me, key, s, r.file, r.lineAfter(key, line), secretFix)
		}
	})
}

func (r *reader) securityRule(me string, p map[string]any, line int) {
	if !strings.EqualFold(str(p["direction"]), "Inbound") || !strings.EqualFold(str(p["access"]), "Allow") {
		return
	}
	sources := append(strs(p["sourceAddressPrefixes"]), r.resolve(str(p["sourceAddressPrefix"])))
	if !risk.FromAnywhere(sources) {
		return
	}
	var ports []string
	for _, s := range append(strs(p["destinationPortRanges"]), str(p["destinationPortRange"])) {
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "[") {
			s = "?"
		}
		ports = append(ports, s)
	}
	if len(ports) == 0 {
		ports = []string{"?"}
	}
	risk.OpenPorts(r.g, me, ports, r.file, line)
}

func (r *reader) parameters() {
	for name, p := range r.tmpl.Parameters {
		if !risk.SecretName(name) {
			continue
		}
		t := strings.ToLower(p.Type)
		def, _ := p.DefaultValue.(string)
		line := r.lineOfText(`"` + name + `"`)
		if line == 0 {
			line = r.lineOfText("param " + name + " ") // Bicep
		}
		switch {
		case (t == "securestring" || t == "string") && def != "" && !strings.HasPrefix(def, "[") && !risk.Placeholder(def):
			r.g.Add(model.High, "", "Password has a default value in the code",
				fmt.Sprintf("The parameter %q has its value written in the file. Remove the default and pass it in at deployment, for example from a key vault.", name), r.file, line)
		case t == "string":
			r.g.Add(model.Medium, "", "Password parameter is not marked secure",
				fmt.Sprintf("The parameter %q is a plain string, so its value shows up in deployment history and logs. Use securestring (or @secure() in Bicep).", name), r.file, line)
		}
	}
}

// lineAfter finds the line of a property at or after a resource's first
// line, so a finding points at the setting itself.
func (r *reader) lineAfter(key string, from int) int {
	start := 0
	for i, n := 0, 1; i < len(r.src) && n < from; i++ {
		if r.src[i] == '\n' {
			n++
			start = i + 1
		}
	}
	for _, needle := range []string{`"` + key + `"`, key + ":"} {
		if j := bytes.Index(r.src[start:], []byte(needle)); j >= 0 {
			return bytes.Count(r.src[:start+j], []byte("\n")) + 1
		}
	}
	return from
}

func (r *reader) lineOfText(s string) int {
	if i := bytes.Index(r.src, []byte(s)); i >= 0 {
		return bytes.Count(r.src[:i], []byte("\n")) + 1
	}
	return 0
}

func id(typ, name string) string { return "arm." + strings.ToLower(typ) + "." + name }

func shortName(name string) string {
	if strings.HasPrefix(name, "[") {
		return "(computed name)"
	}
	return lastSegment(name)
}

func lastSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

func walkStrings(v any, fn func(key, s string)) {
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch t := v.(type) {
		case string:
			fn(key, t)
		case map[string]any:
			for k, x := range t {
				walk(k, x)
			}
		case []any:
			for _, x := range t {
				walk(key, x)
			}
		}
	}
	walk("", v)
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprint(t)
	}
	return ""
}

func strs(v any) []string {
	var out []string
	for _, x := range list(v) {
		if s := str(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
