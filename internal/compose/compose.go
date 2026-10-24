// Package compose reads docker-compose files and works out which containers
// they would start, which ports they would publish and what they can touch
// on the host.
package compose

import (
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
	"github.com/Idris1980/lookfirst/internal/source"
	"github.com/Idris1980/lookfirst/internal/yamlx"
)

const secretFix = "put it in a .env file that is not committed, or use Docker secrets"

var databaseImage = regexp.MustCompile(`(?i)(^|/)(postgres|postgis|mysql|mariadb|mongo|redis|valkey|elasticsearch|opensearch|mcr\.microsoft\.com/mssql|mssql|cassandra|couchdb|influxdb|neo4j|rabbitmq|memcached|clickhouse)`)

func Read(files []source.File) *model.Graph {
	g := &model.Graph{}
	for _, f := range files {
		g.Sources = append(g.Sources, f.Path)
		readFile(g, f)
	}
	return g
}

func id(service string) string { return "compose." + service }

func readFile(g *model.Graph, f source.File) {
	docs, err := yamlx.Documents(f.Data)
	if err != nil {
		g.Add(model.High, "", "Syntax error", err.Error(), f.Path, 0)
	}
	if len(docs) == 0 {
		return
	}
	services := yamlx.Get(docs[0], "services")

	// Create every box first, so lines can be drawn between them.
	yamlx.Pairs(services, func(k, svc *yaml.Node) {
		image := yamlx.Str(yamlx.Get(svc, "image"))
		node := &model.Node{
			ID: id(k.Value), Name: k.Value, Kind: "container", Friendly: "container", Code: "services." + k.Value,
			Category: model.Compute, File: f.Path, Line: k.Line,
		}
		if image != "" {
			node.Friendly = "container · " + image
		} else if yamlx.Get(svc, "build") != nil {
			node.Friendly = "container · built here"
		}
		if databaseImage.MatchString(image) {
			node.Kind, node.Category = "database", model.Data
		}
		g.AddNode(node)
	})
	yamlx.Pairs(yamlx.Get(docs[0], "volumes"), func(k, _ *yaml.Node) {
		g.AddNode(&model.Node{
			ID: "volume." + k.Value, Name: k.Value, Kind: "storage", Friendly: "Docker volume", Code: "volumes." + k.Value,
			Category: model.Data, File: f.Path, Line: k.Line,
		})
	})

	yamlx.Pairs(services, func(k, svc *yaml.Node) {
		service(g, f.Path, k.Value, svc)
	})
}

func service(g *model.Graph, file, name string, svc *yaml.Node) {
	me := id(name)
	isDB := g.Node(me).Kind == "database"

	if img := yamlx.Get(svc, "image"); img != nil {
		if v := img.Value; !strings.Contains(v, "@sha256:") && (!strings.Contains(lastPart(v), ":") || strings.HasSuffix(v, ":latest")) {
			g.Add(model.Low, me, "Image version is not pinned",
				fmt.Sprintf("%q can change under you the next time it is pulled. Pin a version, such as %s:1.2.3.", v, strings.TrimSuffix(v, ":latest")), file, img.Line)
		}
	}

	for _, p := range yamlx.Items(yamlx.Get(svc, "ports")) {
		hostIP, published, target := parsePort(p)
		if published == "" || hostIP == "127.0.0.1" || hostIP == "localhost" || hostIP == "::1" {
			continue
		}
		label := "port " + published
		lo, _, _ := risk.PortRange(target)
		portName, known := risk.PortName(lo)
		switch {
		case isDB || known:
			what := "This service"
			if known {
				what = portName
			}
			g.Add(model.High, me, fmt.Sprintf("%s is published on every network interface", what),
				fmt.Sprintf("Port %s is reachable by every machine that can reach this host, and from the internet if the host is public. Docker also bypasses firewalls such as ufw. Use \"127.0.0.1:%s:%s\" if only this machine needs it.", published, published, target), file, p.Line)
			g.Expose(me, label, true)
		default:
			g.Add(model.Low, me, fmt.Sprintf("Port %s is published on every network interface", published),
				fmt.Sprintf("Anyone who can reach this host can reach the service, and Docker bypasses firewalls such as ufw. If only this machine needs it, use \"127.0.0.1:%s:%s\".", published, target), file, p.Line)
			g.Expose(me, label, false)
		}
	}

	if n := yamlx.Get(svc, "privileged"); yamlx.True(n) {
		g.Add(model.High, me, "Container runs privileged",
			"A privileged container can do almost anything on the host, including escaping the container. Remove privileged: true and add only the capabilities you need.", file, n.Line)
	}
	if n := yamlx.Get(svc, "network_mode"); yamlx.Str(n) == "host" {
		g.Add(model.Medium, me, "Container shares the host's network",
			"network_mode: host removes the network wall between the container and the host. Every port it opens is open on the host.", file, n.Line)
	}
	if n := yamlx.Get(svc, "pid"); yamlx.Str(n) == "host" {
		g.Add(model.High, me, "Container can see every process on the host",
			"pid: host lets the container see and signal every process on the machine.", file, n.Line)
	}
	for _, c := range yamlx.Items(yamlx.Get(svc, "cap_add")) {
		switch strings.ToUpper(strings.TrimPrefix(c.Value, "CAP_")) {
		case "SYS_ADMIN", "ALL", "SYS_PTRACE", "SYS_MODULE":
			g.Add(model.High, me, "Container gets dangerous host powers",
				fmt.Sprintf("cap_add %s gives the container powers that make escaping to the host much easier.", c.Value), file, c.Line)
		case "NET_ADMIN":
			g.Add(model.Medium, me, "Container can change network settings",
				"NET_ADMIN lets the container change routing and firewall rules.", file, c.Line)
		}
	}

	for _, v := range yamlx.Items(yamlx.Get(svc, "volumes")) {
		volume(g, file, me, v)
	}

	env := yamlx.Get(svc, "environment")
	yamlx.Pairs(env, func(k, v *yaml.Node) {
		risk.CheckSecret(g, me, k.Value, yamlx.Str(v), file, k.Line, secretFix)
	})
	for _, item := range yamlx.Items(env) {
		if k, v, ok := strings.Cut(item.Value, "="); ok {
			risk.CheckSecret(g, me, k, v, file, item.Line, secretFix)
		}
	}

	deps := yamlx.Get(svc, "depends_on")
	for _, d := range yamlx.Items(deps) {
		g.Connect(me, id(d.Value), "", false)
	}
	yamlx.Pairs(deps, func(k, _ *yaml.Node) { g.Connect(me, id(k.Value), "", false) })
	for _, l := range yamlx.Items(yamlx.Get(svc, "links")) {
		target, _, _ := strings.Cut(l.Value, ":")
		g.Connect(me, id(target), "", false)
	}
}

// parsePort reads "8080:80", "127.0.0.1:8080:80", "80" or the long form.
func parsePort(n *yaml.Node) (hostIP, published, target string) {
	if n.Kind == yaml.MappingNode {
		return yamlx.Str(yamlx.Get(n, "host_ip")), yamlx.Str(yamlx.Get(n, "published")), yamlx.Str(yamlx.Get(n, "target"))
	}
	v, _, _ := strings.Cut(n.Value, "/") // drop /tcp, /udp
	parts := strings.Split(v, ":")
	switch len(parts) {
	case 1:
		return "", "", parts[0] // container port only: Docker picks a random host port
	case 2:
		return "", parts[0], parts[1]
	default:
		return strings.Trim(strings.Join(parts[:len(parts)-2], ":"), "[]"), parts[len(parts)-2], parts[len(parts)-1]
	}
}

var sensitiveHostPaths = []struct {
	path, why string
	sev       model.Severity
}{
	{"/var/run/docker.sock", "Whoever controls the Docker socket controls the whole host. A container with it can start a privileged container and take over the machine.", model.High},
	{"/run/docker.sock", "Whoever controls the Docker socket controls the whole host.", model.High},
	{"/etc", "The container can read or change the host's system settings and passwords.", model.High},
	{"/root", "The container can read the host's root user files, such as SSH keys.", model.High},
	{"/home", "The container can read every user's files on the host, such as SSH keys.", model.Medium},
	{"~/.ssh", "The container can read your SSH keys.", model.High},
	{"~/.aws", "The container can read your AWS credentials.", model.High},
	{"~/.azure", "The container can read your Azure login.", model.High},
	{"~/.kube", "The container can read your Kubernetes credentials.", model.High},
}

func volume(g *model.Graph, file, me string, v *yaml.Node) {
	var src, target string
	if v.Kind == yaml.MappingNode {
		src, target = yamlx.Str(yamlx.Get(v, "source")), yamlx.Str(yamlx.Get(v, "target"))
	} else {
		parts := strings.Split(v.Value, ":")
		src = parts[0]
		if len(parts) > 1 {
			target = parts[1]
		}
	}
	if target == "" {
		return // anonymous volume
	}
	if !strings.ContainsAny(src, "/.~\\") {
		g.Connect(me, "volume."+src, "", false)
		return
	}

	if src == "/" {
		g.Add(model.High, me, "The host's whole disk is mounted",
			"The container can read and change every file on the host.", file, v.Line)
	}
	for _, s := range sensitiveHostPaths {
		if src == s.path || strings.HasPrefix(src, s.path+"/") {
			g.Add(s.sev, me, "Sensitive host folder is mounted", fmt.Sprintf("%s is mounted. %s", src, s.why), file, v.Line)
			break
		}
	}
	folder := g.AddNode(&model.Node{
		ID: "hostpath." + src, Name: src, Kind: "folder", Friendly: "folder on the host",
		Category: model.Data, File: file, Line: v.Line,
	})
	g.Connect(me, folder.ID, "", false)
}

func lastPart(image string) string {
	if i := strings.LastIndex(image, "/"); i >= 0 {
		return image[i+1:]
	}
	return image
}
