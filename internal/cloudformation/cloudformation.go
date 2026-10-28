// Package cloudformation reads AWS CloudFormation templates, in YAML or
// JSON and including SAM, and works out what they would build, how the parts
// refer to each other, and the risks in them.
package cloudformation

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

const secretFix = "use a parameter with NoEcho: true, or a dynamic reference to Secrets Manager such as {{resolve:secretsmanager:name}}"

func Read(files []source.File) *model.Graph {
	g := &model.Graph{}
	for _, f := range files {
		g.Sources = append(g.Sources, f.Path)
		readFile(g, f)
	}
	return g
}

type resource struct {
	name       string // the logical id, such as "WebServer"
	typ        string
	key, props *yaml.Node
	body       *yaml.Node
	drawn      bool
}

func id(name string) string { return "cfn." + name }

type reader struct {
	g    *model.Graph
	file string
	res  map[string]*resource
}

func readFile(g *model.Graph, f source.File) {
	docs, err := yamlx.Documents(f.Data)
	if err != nil {
		g.Add(model.High, "", "Syntax error", err.Error(), f.Path, 0)
	}
	if len(docs) == 0 {
		return
	}
	root := docs[0]
	r := &reader{g: g, file: f.Path, res: map[string]*resource{}}

	var all []*resource
	yamlx.Pairs(yamlx.Get(root, "Resources"), func(k, v *yaml.Node) {
		res := &resource{name: k.Value, typ: yamlx.Str(yamlx.Get(v, "Type")), key: k, body: v, props: yamlx.Get(v, "Properties")}
		all = append(all, res)
		r.res[res.name] = res
	})

	for _, res := range all {
		e, ok := lookup(res.typ)
		if !ok {
			continue
		}
		res.drawn = true
		g.AddNode(&model.Node{
			ID: id(res.name), Name: res.name, Kind: e.kind, Friendly: e.friendly, Code: res.name + ": " + res.typ,
			Category: e.category, File: f.Path, Line: res.key.Line,
		})
	}
	// A line for every reference (!Ref, !GetAtt, !Sub, DependsOn) between
	// two things that are drawn.
	for _, res := range all {
		if !res.drawn {
			continue
		}
		for _, to := range refs(res.body) {
			if t, ok := r.res[to]; ok && t.drawn && to != res.name {
				g.Connect(id(res.name), id(to), "", false)
			}
		}
	}

	r.parameters(yamlx.Get(root, "Parameters"))
	for _, res := range all {
		r.check(res)
		r.secrets(res, "", res.props)
	}
}

// node is the box findings about a resource belong to: its own, or that of
// what it refers to when it is not drawn itself (a rule of a security group).
func (r *reader) node(res *resource, via ...string) string {
	if res.drawn {
		return id(res.name)
	}
	for _, key := range via {
		for _, to := range refs(yamlx.Get(res.props, key)) {
			if t, ok := r.res[to]; ok && t.drawn {
				return id(to)
			}
		}
	}
	return ""
}

// --- References --------------------------------------------------------

var subRef = regexp.MustCompile(`\$\{([A-Za-z0-9]+)(?:\.[A-Za-z0-9.]+)?\}`)

// refs lists the logical ids a part of a template refers to, in both the
// short form (!Ref Web) and the long form ({"Ref": "Web"}).
func refs(n *yaml.Node) []string {
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		switch n.Tag {
		case "!Ref":
			out = append(out, n.Value)
			return
		case "!GetAtt":
			if n.Kind == yaml.ScalarNode {
				name, _, _ := strings.Cut(n.Value, ".")
				out = append(out, name)
			} else if items := yamlx.Items(n); len(items) > 0 {
				out = append(out, yamlx.Str(items[0]))
			}
			return
		case "!Sub":
			s := yamlx.Str(n)
			if items := yamlx.Items(n); len(items) > 0 {
				s = yamlx.Str(items[0])
				walk(items[len(items)-1])
			}
			for _, m := range subRef.FindAllStringSubmatch(s, -1) {
				out = append(out, m[1])
			}
			return
		}
		if n.Kind == yaml.MappingNode {
			yamlx.Pairs(n, func(k, v *yaml.Node) {
				switch k.Value {
				case "Ref":
					out = append(out, yamlx.Str(v))
				case "Fn::GetAtt":
					if items := yamlx.Items(v); len(items) > 0 {
						out = append(out, yamlx.Str(items[0]))
					} else {
						name, _, _ := strings.Cut(yamlx.Str(v), ".")
						out = append(out, name)
					}
				case "Fn::Sub":
					s := yamlx.Str(v)
					if items := yamlx.Items(v); len(items) > 0 {
						s = yamlx.Str(items[0])
						walk(items[len(items)-1])
					}
					for _, m := range subRef.FindAllStringSubmatch(s, -1) {
						out = append(out, m[1])
					}
				case "DependsOn":
					if s := yamlx.Str(v); s != "" {
						out = append(out, s)
					}
					for _, it := range yamlx.Items(v) {
						out = append(out, yamlx.Str(it))
					}
				default:
					walk(v)
				}
			})
			return
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	return out
}

// literal returns a value written straight into the template, and false for
// anything worked out when it is deployed, such as !Ref or {"Ref": …}.
func literal(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode {
		return "", false
	}
	if strings.HasPrefix(n.Tag, "!") && !strings.HasPrefix(n.Tag, "!!") {
		return "", false
	}
	return n.Value, true
}

func isTrue(n *yaml.Node) bool {
	v, ok := literal(n)
	return ok && strings.EqualFold(v, "true")
}

func isFalse(n *yaml.Node) bool {
	v, ok := literal(n)
	return ok && strings.EqualFold(v, "false")
}

func line(n *yaml.Node, fallback int) int { return yamlx.Line(n, fallback) }

// --- Rules -------------------------------------------------------------

var adminPolicy = regexp.MustCompile(`arn:aws:iam::aws:policy/(AdministratorAccess|PowerUserAccess|IAMFullAccess)$`)

func (r *reader) check(res *resource) {
	p := res.props
	at := res.key.Line
	me := id(res.name)
	if !res.drawn {
		me = ""
	}
	add := func(sev model.Severity, node, title, detail string, n *yaml.Node) {
		r.g.Add(sev, node, title, detail, r.file, line(n, at))
	}

	switch res.typ {
	case "AWS::EC2::SecurityGroup":
		for _, rule := range yamlx.Items(yamlx.Get(p, "SecurityGroupIngress")) {
			r.ingress(me, rule, at)
		}
	case "AWS::EC2::SecurityGroupIngress":
		r.ingress(r.node(res, "GroupId"), p, at)

	case "AWS::EC2::Instance":
		for _, ni := range yamlx.Items(yamlx.Get(p, "NetworkInterfaces")) {
			if v := yamlx.Get(ni, "AssociatePublicIpAddress"); isTrue(v) {
				r.g.Expose(me, "", false)
				add(model.Low, me, "Reachable from the internet", "This server gets a public IP address. Check which ports its security group opens.", v)
			}
		}
	case "AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::Redshift::Cluster", "AWS::DocDB::DBCluster", "AWS::Neptune::DBCluster":
		if v := yamlx.Get(p, "PubliclyAccessible"); isTrue(v) {
			r.g.Expose(me, "public endpoint", true)
			add(model.High, me, "Database reachable from the internet", "PubliclyAccessible: true gives the database a public address. Set it to false and connect from inside the VPC.", v)
		}
		for _, k := range []string{"StorageEncrypted", "Encrypted"} {
			if v := yamlx.Get(p, k); isFalse(v) {
				add(model.Medium, me, "Data is not encrypted", k+": false stores the data unencrypted. Set it to true.", v)
			}
		}
	case "AWS::EC2::Volume", "AWS::EFS::FileSystem":
		if v := yamlx.Get(p, "Encrypted"); isFalse(v) {
			add(model.Medium, me, "Data is not encrypted", "Encrypted: false stores the data unencrypted. Set it to true.", v)
		}

	case "AWS::S3::Bucket":
		if v := yamlx.Get(p, "AccessControl"); strings.HasPrefix(yamlx.Str(v), "PublicRead") {
			r.g.Expose(me, "public read", true)
			add(model.High, me, "Bucket is public", fmt.Sprintf("AccessControl: %s lets anyone on the internet read the files. Remove it and keep the bucket private.", yamlx.Str(v)), v)
		}
		block := yamlx.Get(p, "PublicAccessBlockConfiguration")
		for _, k := range []string{"BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"} {
			if v := yamlx.Get(block, k); isFalse(v) {
				add(model.Medium, me, "Public access is not blocked", k+" is false, so the bucket can be made public by mistake. Set all four settings to true.", v)
				break
			}
		}

	case "AWS::Lambda::Url":
		if v := yamlx.Get(p, "AuthType"); yamlx.Str(v) == "NONE" {
			node := r.node(res, "TargetFunctionArn")
			if me != "" {
				node = me
			}
			r.g.Expose(node, "no login", true)
			add(model.Medium, node, "Function is open on the internet without login", "AuthType: NONE gives the Lambda function a public address that anyone can call. Use AWS_IAM, or check the caller in the function.", v)
		}
	case "AWS::Serverless::Function":
		if v := yamlx.Path(p, "FunctionUrlConfig", "AuthType"); yamlx.Str(v) == "NONE" {
			r.g.Expose(me, "no login", true)
			add(model.Medium, me, "Function is open on the internet without login", "AuthType: NONE gives the Lambda function a public address that anyone can call. Use AWS_IAM, or check the caller in the function.", v)
		}
	case "AWS::Lambda::Permission":
		if v := yamlx.Get(p, "Principal"); yamlx.Str(v) == "*" {
			add(model.High, r.node(res, "FunctionName"), "Anyone can call the function", "Principal: \"*\" lets any AWS account, or anyone on the internet, run this Lambda function. Name the service or account that needs it.", v)
		}

	case "AWS::ElasticLoadBalancingV2::Listener":
		if v := yamlx.Get(p, "Protocol"); yamlx.Str(v) == "HTTP" && !redirects(yamlx.Get(p, "DefaultActions")) {
			add(model.Low, me, "No HTTPS", "This listener serves plain HTTP, so traffic can be read on the way. Use HTTPS, or redirect HTTP to HTTPS.", v)
		}
	case "AWS::CloudFront::Distribution":
		for _, b := range append([]*yaml.Node{yamlx.Path(p, "DistributionConfig", "DefaultCacheBehavior")}, yamlx.Items(yamlx.Path(p, "DistributionConfig", "CacheBehaviors"))...) {
			if v := yamlx.Get(b, "ViewerProtocolPolicy"); yamlx.Str(v) == "allow-all" {
				add(model.Low, me, "No HTTPS", "ViewerProtocolPolicy: allow-all lets visitors use plain HTTP. Use redirect-to-https.", v)
				break
			}
		}
	case "AWS::EKS::Cluster":
		cfg := yamlx.Get(p, "ResourcesVpcConfig")
		if v := yamlx.Get(cfg, "EndpointPublicAccess"); !isFalse(v) && yamlx.Get(cfg, "PublicAccessCidrs") == nil {
			add(model.Low, me, "Kubernetes API is reachable from the internet", "The cluster's API answers on a public address for everyone. Set PublicAccessCidrs to your own addresses, or EndpointPublicAccess: false.", yamlx.Get(cfg, "EndpointPublicAccess"))
		}
	}

	// Every policy, wherever it is: on roles, users, buckets, queues, topics,
	// search domains and so on.
	for _, doc := range policies(p) {
		r.policy(r.node(res, "Bucket", "Queues", "Topics", "Roles", "Users", "Groups"), doc, at)
	}
	for _, arn := range yamlx.Items(yamlx.Get(p, "ManagedPolicyArns")) {
		if v, ok := literal(arn); ok && adminPolicy.MatchString(v) {
			add(model.High, me, "Full control of the AWS account", "This gives "+adminPolicy.FindStringSubmatch(v)[1]+", which can change almost everything in the account. Give only the permissions that are needed.", arn)
		}
	}
}

func redirects(actions *yaml.Node) bool {
	for _, a := range yamlx.Items(actions) {
		if yamlx.Str(yamlx.Get(a, "Type")) == "redirect" {
			return true
		}
	}
	return false
}

// ingress checks one inbound rule of a security group.
func (r *reader) ingress(node string, rule *yaml.Node, fallback int) {
	for _, k := range []string{"CidrIp", "CidrIpv6"} {
		v := yamlx.Get(rule, k)
		cidr, ok := literal(v)
		if !ok || !risk.FromAnywhere([]string{cidr}) {
			continue
		}
		from, _ := literal(yamlx.Get(rule, "FromPort"))
		to, _ := literal(yamlx.Get(rule, "ToPort"))
		spec := from
		proto, _ := literal(yamlx.Get(rule, "IpProtocol"))
		switch {
		case proto == "-1" || strings.EqualFold(proto, "all"):
			spec = "*"
		case from == "" || from == "-1":
			spec = "?"
		case to != "" && to != from:
			spec = from + "-" + to
		}
		risk.OpenPorts(r.g, node, []string{spec}, r.file, line(v, fallback))
	}
}

// policies finds the policy documents in a resource's properties.
func policies(p *yaml.Node) []*yaml.Node {
	var out []*yaml.Node
	for _, k := range []string{"PolicyDocument", "AssumeRolePolicyDocument", "AccessPolicies", "KeyPolicy"} {
		if d := yamlx.Get(p, k); d != nil {
			out = append(out, d)
		}
	}
	for _, item := range yamlx.Items(yamlx.Get(p, "Policies")) {
		if d := yamlx.Get(item, "PolicyDocument"); d != nil {
			out = append(out, d)
		}
	}
	return out
}

// policy checks the statements of one policy document.
func (r *reader) policy(node string, doc *yaml.Node, fallback int) {
	stmts := yamlx.Items(yamlx.Get(doc, "Statement"))
	if s := yamlx.Get(doc, "Statement"); s != nil && s.Kind == yaml.MappingNode {
		stmts = []*yaml.Node{s}
	}
	for _, st := range stmts {
		if e, _ := literal(yamlx.Get(st, "Effect")); e != "Allow" {
			continue
		}
		if p := yamlx.Get(st, "Principal"); everyone(p) && yamlx.Get(st, "Condition") == nil {
			r.g.Add(model.High, node, "Anyone can access it", `The policy allows Principal "*", which means anyone, including people outside your account, without any condition. Name the accounts or services that need access, or add a Condition.`, r.file, line(p, fallback))
		}
		if a := yamlx.Get(st, "Action"); hasStar(a) && hasStar(yamlx.Get(st, "Resource")) {
			r.g.Add(model.High, node, "Permission to do everything", `The policy allows every action ("*") on every resource ("*"). Name the actions and resources that are needed.`, r.file, line(a, fallback))
		}
	}
}

func everyone(p *yaml.Node) bool {
	if v, ok := literal(p); ok {
		return v == "*"
	}
	for _, k := range []string{"AWS", "*"} {
		v := yamlx.Get(p, k)
		if s, ok := literal(v); ok && s == "*" {
			return true
		}
		for _, it := range yamlx.Items(v) {
			if s, ok := literal(it); ok && s == "*" {
				return true
			}
		}
	}
	return false
}

func hasStar(n *yaml.Node) bool {
	if v, ok := literal(n); ok {
		return v == "*"
	}
	for _, it := range yamlx.Items(n) {
		if v, ok := literal(it); ok && v == "*" {
			return true
		}
	}
	return false
}

// --- Secrets and parameters -------------------------------------------

// secrets looks for passwords and keys written straight into the template.
func (r *reader) secrets(res *resource, name string, n *yaml.Node) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if v, ok := literal(n); ok && name != "" && !strings.HasPrefix(v, "{{resolve:") {
			risk.CheckSecret(r.g, r.node(res), name, v, r.file, n.Line, secretFix)
		}
	case yaml.MappingNode:
		// Environment variables: Variables: {DB_PASSWORD: "…"}.
		yamlx.Pairs(n, func(k, v *yaml.Node) { r.secrets(res, k.Value, v) })
	case yaml.SequenceNode:
		for _, it := range n.Content {
			// [{Name: DB_PASSWORD, Value: "…"}], as in ECS task definitions.
			if key := yamlx.Str(yamlx.Get(it, "Name")); key != "" && yamlx.Get(it, "Value") != nil {
				r.secrets(res, key, yamlx.Get(it, "Value"))
				continue
			}
			r.secrets(res, name, it)
		}
	}
}

// parameters checks inputs that hold passwords: they should be hidden in
// the console and logs (NoEcho), and have no value written in the file.
func (r *reader) parameters(params *yaml.Node) {
	yamlx.Pairs(params, func(k, v *yaml.Node) {
		if !risk.SecretName(k.Value) {
			return
		}
		if d, ok := literal(yamlx.Get(v, "Default")); ok && !risk.Placeholder(d) {
			r.g.Add(model.High, "", "Password has a default value in the code",
				fmt.Sprintf("The parameter %q has its value written in the file. Remove the Default and pass the value in when you deploy, or use Secrets Manager.", k.Value), r.file, line(yamlx.Get(v, "Default"), k.Line))
		}
		if !isTrue(yamlx.Get(v, "NoEcho")) {
			r.g.Add(model.Medium, "", "Password parameter is not hidden",
				fmt.Sprintf("The parameter %q is shown in plain text in the CloudFormation console and its events. Add NoEcho: true.", k.Value), r.file, k.Line)
		}
	})
}
