// Package kubernetes reads Kubernetes manifests and works out which
// workloads they would run, how they are reached and what powers they get.
package kubernetes

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
	"github.com/Idris1980/lookfirst/internal/source"
	"github.com/Idris1980/lookfirst/internal/yamlx"
)

const secretFix = "use a Kubernetes Secret created outside Git, or an external secret store"

type object struct {
	kind, name string
	doc        *yaml.Node
	file       string
	line       int
}

func (o object) id() string { return "k8s." + o.kind + "." + o.name }

// workload is a kind that runs containers, with the path to its pod spec.
var workload = map[string][]string{
	"Pod":         {"spec"},
	"Deployment":  {"spec", "template", "spec"},
	"StatefulSet": {"spec", "template", "spec"},
	"DaemonSet":   {"spec", "template", "spec"},
	"ReplicaSet":  {"spec", "template", "spec"},
	"Job":         {"spec", "template", "spec"},
	"CronJob":     {"spec", "jobTemplate", "spec", "template", "spec"},
}

var display = map[string]struct {
	kind     string
	category model.Category
}{
	"Service":               {"loadbalancer", model.Network},
	"Ingress":               {"loadbalancer", model.Network},
	"NetworkPolicy":         {"shield", model.Security},
	"Secret":                {"key", model.Security},
	"ServiceAccount":        {"identity", model.Security},
	"Role":                  {"identity", model.Security},
	"ClusterRole":           {"identity", model.Security},
	"RoleBinding":           {"identity", model.Security},
	"ClusterRoleBinding":    {"identity", model.Security},
	"ConfigMap":             {"generic", model.Data},
	"PersistentVolumeClaim": {"storage", model.Data},
	"PersistentVolume":      {"storage", model.Data},
}

func Read(files []source.File) *model.Graph {
	g := &model.Graph{}
	var objs []object
	for _, f := range files {
		g.Sources = append(g.Sources, f.Path)
		docs, err := yamlx.Documents(f.Data)
		if err != nil {
			g.Add(model.High, "", "Syntax error", err.Error(), f.Path, 0)
		}
		for _, d := range docs {
			kind := yamlx.Str(yamlx.Get(d, "kind"))
			name := yamlx.Str(yamlx.Path(d, "metadata", "name"))
			if kind == "" || kind == "Namespace" {
				continue
			}
			if kind == "List" {
				continue // rare in hand-written files
			}
			objs = append(objs, object{kind, name, d, f.Path, d.Line})
		}
	}

	for _, o := range objs {
		n := &model.Node{
			ID: o.id(), Name: o.name, Friendly: strings.ToLower(o.kind), Code: o.kind + "/" + o.name,
			Kind: "generic", Category: model.Other, File: o.file, Line: o.line,
		}
		if _, ok := workload[o.kind]; ok {
			n.Kind, n.Category = "container", model.Compute
		} else if d, ok := display[o.kind]; ok {
			n.Kind, n.Category = d.kind, d.category
		}
		if o.kind == "Service" {
			if t := yamlx.Str(yamlx.Path(o.doc, "spec", "type")); t != "" {
				n.Friendly = "service · " + t
			}
		}
		g.AddNode(n)
	}

	for _, o := range objs {
		if path, ok := workload[o.kind]; ok {
			podSpec(g, o, yamlx.Path(o.doc, path...))
		}
		switch o.kind {
		case "Service":
			serviceObj(g, o, objs)
		case "Ingress":
			ingress(g, o)
		case "Secret":
			secretObj(g, o)
		case "ConfigMap":
			yamlx.Pairs(yamlx.Get(o.doc, "data"), func(k, v *yaml.Node) {
				risk.CheckSecret(g, o.id(), k.Value, yamlx.Str(v), o.file, k.Line, secretFix)
			})
		case "ClusterRoleBinding", "RoleBinding":
			if r := yamlx.Path(o.doc, "roleRef", "name"); yamlx.Str(r) == "cluster-admin" {
				g.Add(model.High, o.id(), "Full control of the cluster is handed out",
					"This binding gives cluster-admin, which can do anything in the whole cluster. Give only the permissions that are needed.", o.file, r.Line)
			}
		case "ClusterRole", "Role":
			for _, rule := range yamlx.Items(yamlx.Get(o.doc, "rules")) {
				if hasStar(yamlx.Get(rule, "verbs")) && hasStar(yamlx.Get(rule, "resources")) {
					g.Add(model.High, o.id(), "Role allows everything",
						"verbs: [\"*\"] on resources: [\"*\"] is the same as full admin. List only the resources and actions that are needed.", o.file, rule.Line)
				}
			}
		}
	}
	return g
}

func podSpec(g *model.Graph, o object, spec *yaml.Node) {
	if spec == nil {
		return
	}
	me := o.id()
	for _, key := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if n := yamlx.Get(spec, key); yamlx.True(n) {
			g.Add(model.High, me, fmt.Sprintf("Pod shares the node's %s", strings.TrimPrefix(key, "host")),
				fmt.Sprintf("%s: true removes the wall between the pod and the machine it runs on.", key), o.file, n.Line)
		}
	}
	for _, v := range yamlx.Items(yamlx.Get(spec, "volumes")) {
		hp := yamlx.Get(v, "hostPath")
		if hp == nil {
			continue
		}
		p := yamlx.Str(yamlx.Get(hp, "path"))
		sev, why := model.Medium, "The pod can read or change files on the machine it runs on."
		if strings.Contains(p, "docker.sock") || strings.Contains(p, "containerd.sock") || p == "/" || p == "/etc" || p == "/root" {
			sev, why = model.High, "This gives the pod control over the node it runs on."
		}
		g.Add(sev, me, "Folder on the node is mounted", fmt.Sprintf("hostPath %s is mounted. %s", p, why), o.file, hp.Line)
	}
	if sa := yamlx.Str(yamlx.Get(spec, "serviceAccountName")); sa != "" {
		g.Connect(me, "k8s.ServiceAccount."+sa, "", false)
	}

	containers := append(yamlx.Items(yamlx.Get(spec, "containers")), yamlx.Items(yamlx.Get(spec, "initContainers"))...)
	for _, c := range containers {
		cname := yamlx.Str(yamlx.Get(c, "name"))
		if img := yamlx.Get(c, "image"); img != nil {
			v := img.Value
			if !strings.Contains(v, "@sha256:") && (!strings.Contains(lastPart(v), ":") || strings.HasSuffix(v, ":latest")) {
				g.Add(model.Low, me, "Image version is not pinned",
					fmt.Sprintf("Container %q uses %q, which can change under you. Pin a version.", cname, v), o.file, img.Line)
			}
		}
		sc := yamlx.Get(c, "securityContext")
		if n := yamlx.Get(sc, "privileged"); yamlx.True(n) {
			g.Add(model.High, me, "Container runs privileged",
				fmt.Sprintf("Container %q can do almost anything on the node, including escaping the container.", cname), o.file, n.Line)
		}
		if n := yamlx.Get(sc, "allowPrivilegeEscalation"); yamlx.True(n) {
			g.Add(model.Medium, me, "Container may gain more rights",
				"allowPrivilegeEscalation: true lets a process gain more rights than it started with. Set it to false.", o.file, n.Line)
		}
		if n := yamlx.Get(sc, "runAsUser"); yamlx.Str(n) == "0" {
			g.Add(model.Medium, me, "Container runs as root",
				fmt.Sprintf("Container %q runs as user 0 (root). Run as a normal user and set runAsNonRoot: true.", cname), o.file, n.Line)
		}
		for _, e := range yamlx.Items(yamlx.Get(c, "env")) {
			if v := yamlx.Get(e, "value"); v != nil {
				risk.CheckSecret(g, me, yamlx.Str(yamlx.Get(e, "name")), v.Value, o.file, v.Line, secretFix)
			}
			if ref := yamlx.Str(yamlx.Path(e, "valueFrom", "secretKeyRef", "name")); ref != "" {
				g.Connect(me, "k8s.Secret."+ref, "", false)
			}
		}
	}
}

func serviceObj(g *model.Graph, o object, objs []object) {
	spec := yamlx.Get(o.doc, "spec")
	selector := yamlx.Get(spec, "selector")
	for _, w := range objs {
		path, ok := workload[w.kind]
		if !ok {
			continue
		}
		tmpl := yamlx.Path(w.doc, path[:len(path)-1]...) // the template, whose metadata holds the labels
		if w.kind == "Pod" {
			tmpl = w.doc
		}
		if matches(selector, yamlx.Path(tmpl, "metadata", "labels")) {
			g.Connect(o.id(), w.id(), "", false)
		}
	}

	var ports []string
	for _, p := range yamlx.Items(yamlx.Get(spec, "ports")) {
		ports = append(ports, yamlx.Str(yamlx.Get(p, "port")))
	}
	t := yamlx.Get(spec, "type")
	switch yamlx.Str(t) {
	case "LoadBalancer":
		ranges := yamlx.Items(yamlx.Get(spec, "loadBalancerSourceRanges"))
		if len(ranges) > 0 {
			return
		}
		if len(ports) == 0 {
			ports = []string{"?"}
		}
		risk.OpenPorts(g, o.id(), ports, o.file, t.Line)
	case "NodePort":
		g.Add(model.Medium, o.id(), "Port opened on every node",
			"type: NodePort opens a port on every machine in the cluster. If the nodes have public addresses, the service is on the internet. Prefer ClusterIP behind an Ingress.", o.file, t.Line)
		g.Expose(o.id(), "node port", false)
	}
}

func ingress(g *model.Graph, o object) {
	spec := yamlx.Get(o.doc, "spec")
	g.Expose(o.id(), "http", false)
	if yamlx.Get(spec, "tls") == nil {
		g.Add(model.Medium, o.id(), "No HTTPS",
			"This Ingress has no tls section, so traffic, including passwords, travels unencrypted. Add a certificate, for example with cert-manager.", o.file, o.line)
	}
	for _, r := range yamlx.Items(yamlx.Get(spec, "rules")) {
		for _, p := range yamlx.Items(yamlx.Path(r, "http", "paths")) {
			if svc := yamlx.Str(yamlx.Path(p, "backend", "service", "name")); svc != "" {
				g.Connect(o.id(), "k8s.Service."+svc, yamlx.Str(yamlx.Get(p, "path")), false)
			}
		}
	}
	if svc := yamlx.Str(yamlx.Path(spec, "defaultBackend", "service", "name")); svc != "" {
		g.Connect(o.id(), "k8s.Service."+svc, "", false)
	}
}

func secretObj(g *model.Graph, o object) {
	for _, key := range []string{"stringData", "data"} {
		if n := yamlx.Get(o.doc, key); n != nil && len(n.Content) > 0 {
			g.Add(model.High, o.id(), "Secret values are stored in the file",
				"Anyone who can read this file, or the Git history, can read the secret. Base64 in data: is not encryption. Create the Secret outside Git, or use Sealed Secrets or an external secret store.", o.file, n.Line)
			return
		}
	}
}

func matches(selector, labels *yaml.Node) bool {
	if selector == nil || labels == nil || len(selector.Content) == 0 {
		return false
	}
	ok := true
	yamlx.Pairs(selector, func(k, v *yaml.Node) {
		if yamlx.Str(yamlx.Get(labels, k.Value)) != v.Value {
			ok = false
		}
	})
	return ok
}

func hasStar(n *yaml.Node) bool {
	for _, i := range yamlx.Items(n) {
		if i.Value == "*" {
			return true
		}
	}
	return false
}

func lastPart(image string) string {
	if i := strings.LastIndex(image, "/"); i >= 0 {
		return image[i+1:]
	}
	return image
}
