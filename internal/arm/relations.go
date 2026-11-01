package arm

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/relate"
	"github.com/Idris1980/lookfirst/internal/risk"
)

// What talks to what. A template says it in many ways: an app setting that
// holds a storage account's name, an environment variable with another
// app's address, a registry to pull images from, a role assignment that
// lets an identity use something. relations turns each of them into a line
// that says what it means, so the picture shows how the parts work
// together and not only the order Azure creates them in.

var (
	varRef   = regexp.MustCompile(`variables\('([^']+)'\)`)
	paramRef = regexp.MustCompile(`parameters\('([^']+)'\)`)
	guidRe   = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
)

// roleWords says what a built-in role lets its holder do, by the role's
// fixed id.
var roleWords = map[string]string{
	"7f951dda-4ed3-4680-a7ca-43fe172d538d": "may pull images",
	"8311e382-0749-4cb8-b61a-304f252e45ec": "may push images",
	"ba92f5b4-2d11-453d-a403-e96b0029c9fe": "may read and write blobs",
	"2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "may read blobs",
	"b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "owns the blobs",
	"974c5e8b-45b9-4653-ba55-5f855dd0fb88": "may use queues",
	"0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3": "may use tables",
	"17d1049b-9a84-46fb-8f53-869881c3d3ab": "manages the storage account",
	"4633458b-17de-408a-b874-0445c86b69e6": "may read secrets",
	"00482a5a-887f-4fb3-b363-3b7fe8e74483": "administers the key vault",
	"3913510d-42f4-4e42-8a64-420c390055eb": "may publish metrics",
	"acdd72a7-3385-48ef-bd42-f606fba81ae7": "may read everything",
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "full control (Owner)",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "full control (Contributor)",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "may hand out access",
}

// roleShort is the same, said in a word or two after "may use", for a line
// that already says how the two work together.
var roleShort = map[string]string{
	"7f951dda-4ed3-4680-a7ca-43fe172d538d": "images (pull)",
	"8311e382-0749-4cb8-b61a-304f252e45ec": "images (push)",
	"ba92f5b4-2d11-453d-a403-e96b0029c9fe": "blobs",
	"2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": "blobs (read)",
	"b7e6dc6d-f1e8-4753-8033-0f276bb0955b": "blobs (owner)",
	"974c5e8b-45b9-4653-ba55-5f855dd0fb88": "queues",
	"0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3": "tables",
	"17d1049b-9a84-46fb-8f53-869881c3d3ab": "the account (manage)",
	"4633458b-17de-408a-b874-0445c86b69e6": "secrets",
	"00482a5a-887f-4fb3-b363-3b7fe8e74483": "the vault (admin)",
	"3913510d-42f4-4e42-8a64-420c390055eb": "metrics",
	"acdd72a7-3385-48ef-bd42-f606fba81ae7": "everything (read)",
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "everything (Owner)",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "everything (Contributor)",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "access control",
}

// refsIn returns the resources a template expression refers to: through
// resourceId() and its kin, variables that hold an id, and variables or
// parameters that hold a resource's name.
func (r *reader) refsIn(s string) []string {
	if r.byName == nil {
		r.byName = map[string]string{}
		for _, it := range r.items {
			if m := varCall.FindStringSubmatch(it.rawName); m != nil {
				r.byName["v:"+m[1]] = id(it.typ, it.name)
			}
			if m := paramCall.FindStringSubmatch(it.rawName); m != nil {
				r.byName["p:"+m[1]] = id(it.typ, it.name)
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	add := func(to string) {
		if to != "" && !seen[to] {
			seen[to] = true
			out = append(out, to)
		}
	}
	for _, m := range resourceIDCall.FindAllString(s, -1) {
		add(r.resolveRef(m))
	}
	for _, m := range varRef.FindAllStringSubmatch(s, -1) {
		if to := r.resolveRef("[variables('" + m[1] + "')]"); to != "" {
			add(to)
		} else {
			add(r.byName["v:"+m[1]])
		}
	}
	for _, m := range paramRef.FindAllStringSubmatch(s, -1) {
		add(r.byName["p:"+m[1]])
	}
	return out
}

func (r *reader) itemByID(nodeID string) *item {
	for _, it := range r.items {
		if id(it.typ, it.name) == nodeID {
			return it
		}
	}
	return nil
}

// walkProps calls fn for every string in a resource's properties, with the
// path of keys to it and, inside app settings and environment variables
// ({"name": …, "value": …}), the setting's name.
func walkProps(v any, path []string, setting string, fn func(path []string, setting, s string)) {
	switch x := v.(type) {
	case string:
		fn(path, setting, x)
	case map[string]any:
		name, _ := x["name"].(string)
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := setting
			if (k == "value" || k == "secureValue") && name != "" {
				s = name
			}
			walkProps(x[k], append(append([]string{}, path...), k), s, fn)
		}
	case []any:
		for _, e := range x {
			walkProps(e, path, setting, fn)
		}
	}
}

// classify says what a reference from one resource to another means.
func classify(path []string, setting, s string, to *item) (string, string) {
	p := strings.ToLower(strings.Join(path, "/"))
	last := ""
	if len(path) > 0 {
		last = strings.ToLower(path[len(path)-1])
	}
	toType := ""
	if to != nil {
		toType = strings.ToLower(to.typ)
	}
	switch {
	case strings.HasPrefix(toType, "microsoft.managedidentity"):
		return "signs in as", model.Hosting
	case last == "serverfarmid":
		return "runs on", model.Hosting
	case strings.Contains(p, "workspaceresourceid") || strings.Contains(p, "logs/workspace"):
		return "sends logs to", model.Flow
	case strings.Contains(p, "imageregistrycredentials") || last == "image":
		return "pulls its image from", model.Flow
	case strings.Contains(p, "subnet"):
		return "in subnet", model.Hosting
	case strings.Contains(p, "networksecuritygroup"):
		return "protected by", model.Hosting
	case strings.Contains(p, "publicipaddress"):
		return "public address", model.Hosting
	case strings.Contains(p, "networkinterfaces"):
		return "network card", model.Hosting
	case strings.Contains(s, "defaultHostName") || strings.Contains(s, "hostNames") || strings.Contains(s, "https://"):
		return "calls over HTTPS", model.Flow
	case strings.HasPrefix(toType, "microsoft.insights/components"):
		return "sends telemetry to", model.Flow
	case strings.HasPrefix(toType, "microsoft.operationalinsights/workspaces"):
		return "sends logs to", model.Flow
	case strings.HasPrefix(toType, "microsoft.storage/storageaccounts"):
		if strings.HasPrefix(strings.ToLower(setting), "azurewebjobsstorage") {
			return "keeps its state in", model.Flow
		}
		return "reads and writes data in", model.Flow
	case strings.HasPrefix(toType, "microsoft.keyvault"):
		return "reads secrets from", model.Flow
	case strings.HasPrefix(toType, "microsoft.sql"), strings.HasPrefix(toType, "microsoft.dbfor"), strings.HasPrefix(toType, "microsoft.documentdb"), strings.HasPrefix(toType, "microsoft.cache"):
		return "uses data in", model.Flow
	case strings.HasPrefix(toType, "microsoft.servicebus"), strings.HasPrefix(toType, "microsoft.eventhub"), strings.HasPrefix(toType, "microsoft.eventgrid"):
		return "sends messages to", model.Flow
	case strings.HasPrefix(toType, "microsoft.web/serverfarms"):
		return "runs on", model.Hosting
	case strings.HasPrefix(toType, "microsoft.containerregistry"):
		return "pulls its image from", model.Flow
	}
	return relate.Meaning(last, "", toType)
}

// relations adds the lines that say how a resource works with others.
func (r *reader) relations(it *item) {
	me := id(it.typ, it.name)
	typ := strings.ToLower(it.typ)

	if typ == "microsoft.authorization/roleassignments" {
		r.roles = append(r.roles, it) // drawn in tidy, once every flow is known
		return
	}
	walkProps(it.res.Properties, nil, "", func(path []string, setting, s string) {
		for _, to := range r.refsIn(s) {
			if to == me {
				continue
			}
			label, kind := classify(path, setting, s, r.itemByID(to))
			r.g.ConnectKind(me, to, label, kind)
		}
	})
	for key := range mapOf(it.res.Identity["userAssignedIdentities"]) {
		for _, to := range r.refsIn(key) {
			r.g.ConnectKind(me, to, "signs in as", model.Hosting)
		}
	}
}

// roleAssignment becomes a line from whoever gets the role to what it is
// for, labelled with what the role allows, such as "may pull images".
func (r *reader) roleAssignment(it *item, me string) {
	p := it.res.Properties
	principals := r.refsIn(str(p["principalId"]))
	scopes := r.refsIn(it.res.Scope)
	if len(principals) == 0 || len(scopes) == 0 {
		return // drawn as a box of its own, as before
	}
	var words, short []string
	seen := map[string]bool{}
	for _, g := range r.roleIDs(str(p["roleDefinitionId"])) {
		g = strings.ToLower(g)
		w, sw := roleWords[g], roleShort[g]
		if w == "" {
			w = "has a role on"
		}
		if sw == "" {
			sw = strings.TrimPrefix(w, "may ")
		}
		if !seen[w] {
			seen[w] = true
			words, short = append(words, w), append(short, sw)
		}
	}
	if len(words) == 0 {
		words, short = []string{"has a role on"}, []string{"a role"}
	}
	r.grant(principals[0], scopes[0], strings.Join(words, ", "), short)
	r.converted[me] = true
}

// grant draws a role as a line of its own, or, when the two already talk,
// adds what it allows to that line after a dot, in short: "keeps its state
// in · may use blobs (owner), queues".
func (r *reader) grant(from, to, words string, short []string) {
	for i, e := range r.g.Edges {
		if e.From != from || e.To != to || e.Kind != model.Flow {
			continue
		}
		head, rights, has := strings.Cut(e.Label, " · may use ")
		if !has {
			rights = ""
		}
		for _, sw := range short {
			if !strings.Contains(rights, sw) {
				if rights != "" {
					rights += ", "
				}
				rights += sw
			}
		}
		r.g.Edges[i].Label = head + " · may use " + rights
		return
	}
	r.g.ConnectKind(from, to, words, model.Access)
}

// roleIDs finds the role ids in a roleDefinitionId expression, also through
// variables and lists of roles, as in variables('hostRoller')[copyIndex()].id.
func (r *reader) roleIDs(expr string) []string {
	ids := guidRe.FindAllString(expr, -1)
	for _, m := range varRef.FindAllStringSubmatch(expr, -1) {
		switch v := r.tmpl.Variables[m[1]].(type) {
		case string:
			ids = append(ids, guidRe.FindAllString(v, -1)...)
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					ids = append(ids, guidRe.FindAllString(s, -1)...)
				}
				if obj, ok := e.(map[string]any); ok {
					ids = append(ids, guidRe.FindAllString(str(obj["id"]), -1)...)
				}
			}
		}
	}
	return ids
}

// childOf are the parts of a storage account that are shown inside it.
var childOf = []string{
	"microsoft.storage/storageaccounts/blobservices/containers",
	"microsoft.storage/storageaccounts/fileservices/shares",
	"microsoft.storage/storageaccounts/queueservices/queues",
	"microsoft.storage/storageaccounts/tableservices/tables",
}

// tidy hides what is shown in another way: role assignments that became
// lines, and blob containers, shares, queues and tables, which are named
// inside their storage account. Anything with a finding stays visible.
func (r *reader) tidy() {
	for _, it := range r.roles {
		r.roleAssignment(it, id(it.typ, it.name))
	}
	// Its state is data too; say it once.
	for i, e := range r.g.Edges {
		if strings.Contains(e.Label, "keeps its state in") {
			r.g.Edges[i].Label = strings.Replace(e.Label, "reads and writes data in, ", "", 1)
			r.g.Edges[i].Label = strings.Replace(r.g.Edges[i].Label, ", reads and writes data in", "", 1)
		}
	}
	hasFinding := map[string]bool{}
	for _, f := range r.g.Findings {
		hasFinding[f.NodeID] = true
	}
	for nodeID := range r.converted {
		if n := r.g.Node(nodeID); n != nil && !hasFinding[nodeID] {
			n.Hidden = true
		}
	}
	for _, it := range r.items {
		typ := strings.ToLower(it.typ)
		isChild := false
		for _, c := range childOf {
			isChild = isChild || typ == c
		}
		if !isChild {
			continue
		}
		me := id(it.typ, it.name)
		accountName, _, _ := strings.Cut(it.name, "/")
		parent := r.g.Node(id("Microsoft.Storage/storageAccounts", accountName))
		child := r.g.Node(me)
		if parent == nil || child == nil || hasFinding[me] {
			continue
		}
		child.Hidden = true
		part := lastSegment(it.name)
		if strings.Contains(parent.Friendly, " · ") {
			parent.Friendly += ", " + part
		} else {
			parent.Friendly += " · " + part
		}
	}
}

// exposure draws what the internet can reach that rules alone do not:
// a container group with a public address, and web apps, which answer on
// their public address unless that is switched off.
func (r *reader) exposure(it *item, me string) {
	p := it.res.Properties
	switch strings.ToLower(it.typ) {
	case "microsoft.containerinstance/containergroups":
		ip := mapOf(p["ipAddress"])
		if !strings.EqualFold(str(ip["type"]), "Public") {
			return
		}
		var ports []string
		for _, port := range list(ip["ports"]) {
			switch v := mapOf(port)["port"].(type) {
			case float64:
				ports = append(ports, strconv.Itoa(int(v)))
			case string:
				if n, err := strconv.Atoi(r.resolve(v)); err == nil {
					ports = append(ports, strconv.Itoa(n))
				} else {
					ports = append(ports, "?")
				}
			}
		}
		if len(ports) == 0 {
			ports = []string{"?"}
		}
		risk.OpenPorts(r.g, me, ports, r.file, r.lineAfter("ipAddress", it.line))
	case "microsoft.web/sites":
		if !strings.EqualFold(str(p["publicNetworkAccess"]), "Disabled") {
			r.g.Expose(me, "HTTPS", false)
		}
	}
}
