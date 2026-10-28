package terraform

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
)

var adminPolicy = regexp.MustCompile(`arn:aws:iam::aws:policy/(AdministratorAccess|PowerUserAccess|IAMFullAccess)$`)

// policyAttrs are where AWS resources keep a policy document.
var policyAttrs = map[string]string{
	"aws_iam_policy":            "policy",
	"aws_iam_role_policy":       "policy",
	"aws_iam_user_policy":       "policy",
	"aws_iam_group_policy":      "policy",
	"aws_iam_role":              "assume_role_policy",
	"aws_s3_bucket_policy":      "policy",
	"aws_sqs_queue_policy":      "policy",
	"aws_sns_topic_policy":      "policy",
	"aws_kms_key":               "policy",
	"aws_ecr_repository_policy": "policy",
	"aws_opensearch_domain":     "access_policies",
	"aws_elasticsearch_domain":  "access_policies",
	"aws_secretsmanager_secret": "policy",
}

// awsChecks holds the AWS rules beyond the network ones in check.
func awsChecks(c *config, g *model.Graph) {
	for _, r := range c.resources {
		// Rules and wiring that are not drawn report on what they belong
		// to, such as the function a permission is for.
		me := r.id()
		if g.Node(me) == nil {
			me = ""
			for _, ref := range references(r.body) {
				if g.Node(ref) != nil {
					me = ref
					break
				}
			}
		}
		add := func(sev model.Severity, title, detail, attr string) {
			g.Add(sev, me, title, detail, r.file, line(r.body, attr, r.line))
		}

		switch r.typ {
		case "aws_security_group_rule":
			if t, _ := str(r.body, "type"); t == "ingress" {
				// The rule is reported on the security group it belongs to.
				target := me
				for _, ref := range references(r.body) {
					if strings.HasPrefix(ref, "aws_security_group.") {
						target = ref
					}
				}
				awsRule(g, target, r.file, r.body, r.line, "cidr_blocks", "ipv6_cidr_blocks", "protocol")
			}

		case "aws_db_instance", "aws_rds_cluster", "aws_docdb_cluster", "aws_neptune_cluster":
			if v, set := boolean(r.body, "storage_encrypted"); set && !v {
				add(model.Medium, "Data is not encrypted", "storage_encrypted = false stores the data unencrypted. Set it to true.", "storage_encrypted")
			}
		case "aws_rds_cluster_instance", "aws_redshift_cluster", "aws_mq_broker", "aws_dms_replication_instance":
			if v, set := boolean(r.body, "publicly_accessible"); set && v {
				g.Expose(me, "public endpoint", true)
				add(model.High, "Reachable from the internet", "publicly_accessible = true gives it a public address. Keep it false and connect from inside the VPC.", "publicly_accessible")
			}
		case "aws_ebs_volume", "aws_efs_file_system":
			if v, set := boolean(r.body, "encrypted"); set && !v {
				add(model.Medium, "Data is not encrypted", "encrypted = false stores the data unencrypted. Set it to true.", "encrypted")
			}
		case "aws_s3_bucket":
			if acl, _ := str(r.body, "acl"); strings.HasPrefix(acl, "public-") {
				g.Expose(me, "public read", true)
				add(model.High, "Bucket is public", fmt.Sprintf("acl = %q lets anyone on the internet access this bucket. Use \"private\".", acl), "acl")
			}

		case "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_group_policy_attachment", "aws_iam_policy_attachment":
			if arn, _ := str(r.body, "policy_arn"); adminPolicy.MatchString(arn) {
				add(model.High, "Full control of the AWS account", "This gives "+adminPolicy.FindStringSubmatch(arn)[1]+", which can change almost everything in the account. Give only the permissions that are needed.", "policy_arn")
			}
		case "aws_iam_access_key":
			add(model.Medium, "Creates a long-lived access key", "Access keys do not expire, and Terraform keeps the secret in its state file. Prefer roles, or IAM Identity Center for people.", "user")

		case "aws_lambda_function_url":
			if t, _ := str(r.body, "authorization_type"); t == "NONE" {
				g.Expose(me, "no login", true)
				add(model.Medium, "Function is open on the internet without login", "authorization_type = \"NONE\" gives the Lambda function a public address that anyone can call. Use AWS_IAM, or check the caller in the function.", "authorization_type")
			}
		case "aws_lambda_permission":
			if p, _ := str(r.body, "principal"); p == "*" {
				add(model.High, "Anyone can call the function", "principal = \"*\" lets any AWS account, or anyone on the internet, run this Lambda function. Name the service or account that needs it.", "principal")
			}
		case "aws_lb_listener", "aws_alb_listener":
			if p, _ := str(r.body, "protocol"); p == "HTTP" && !redirectsToHTTPS(r.body) {
				add(model.Low, "No HTTPS", "This listener serves plain HTTP, so traffic can be read on the way. Use HTTPS, or redirect HTTP to HTTPS.", "protocol")
			}
		case "aws_cloudfront_distribution":
			for _, b := range r.body.Blocks {
				if b.Type != "default_cache_behavior" && b.Type != "ordered_cache_behavior" {
					continue
				}
				if p, _ := str(b.Body, "viewer_protocol_policy"); p == "allow-all" {
					g.Add(model.Low, me, "No HTTPS", "viewer_protocol_policy = \"allow-all\" lets visitors use plain HTTP. Use redirect-to-https.", r.file, line(b.Body, "viewer_protocol_policy", r.line))
					break
				}
			}
		case "aws_eks_cluster":
			for _, b := range r.body.Blocks {
				if b.Type != "vpc_config" {
					continue
				}
				// The API is public unless switched off, and open to all
				// unless limited to some addresses.
				public, set := boolean(b.Body, "endpoint_public_access")
				_, limited := b.Body.Attributes["public_access_cidrs"]
				if (!set || public) && (!limited || risk.FromAnywhere(strs(b.Body, "public_access_cidrs"))) {
					g.Add(model.Low, me, "Kubernetes API is reachable from the internet", "The cluster's API answers on a public address for everyone. Set public_access_cidrs to your own addresses, or endpoint_public_access = false.", r.file, line(b.Body, "endpoint_public_access", r.line))
				}
			}
		}

		if attr, ok := policyAttrs[r.typ]; ok {
			if a, ok := r.body.Attributes[attr]; ok {
				for _, st := range c.statements(a.Expr) {
					policyFindings(g, me, st, r.file, a.SrcRange.Start.Line)
				}
			}
		}
		for _, arn := range strs(r.body, "managed_policy_arns") {
			if adminPolicy.MatchString(arn) {
				add(model.High, "Full control of the AWS account", "This gives "+adminPolicy.FindStringSubmatch(arn)[1]+", which can change almost everything in the account. Give only the permissions that are needed.", "managed_policy_arns")
			}
		}
	}
}

func redirectsToHTTPS(body *hclsyntax.Body) bool {
	for _, b := range body.Blocks {
		if b.Type == "default_action" {
			if t, _ := str(b.Body, "type"); t == "redirect" {
				return true
			}
		}
	}
	return false
}

// statement is one statement of an IAM policy, whichever way it was written.
type statement struct {
	allow     bool
	anyone    bool // Principal "*"
	condition bool
	actions   []string
	resources []string
}

// statements reads a policy written as jsonencode({...}), as a JSON string
// (often a heredoc), or as data.aws_iam_policy_document.name.json.
func (c *config) statements(expr hclsyntax.Expression) []statement {
	if t, ok := expr.(*hclsyntax.ScopeTraversalExpr); ok && t.Traversal.RootName() == "data" && len(t.Traversal) >= 3 {
		if typ, ok := t.Traversal[1].(hcl.TraverseAttr); ok && typ.Name == "aws_iam_policy_document" {
			if name, ok := t.Traversal[2].(hcl.TraverseAttr); ok {
				if body := c.policyDocs[name.Name]; body != nil {
					return documentStatements(body)
				}
			}
		}
		return nil
	}
	if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "jsonencode" && len(call.Args) == 1 {
		// Parts that refer to other resources are unknown here; the rest,
		// such as "Principal" and "Action", is usually written out.
		v, _ := call.Args[0].Value(&hcl.EvalContext{})
		return jsonStatements(toGo(v))
	}
	if v, ok := literal(expr); ok && v.Type() == cty.String {
		var doc any
		if json.Unmarshal([]byte(v.AsString()), &doc) == nil {
			return jsonStatements(doc)
		}
	}
	return nil
}

func jsonStatements(doc any) []statement {
	m, _ := doc.(map[string]any)
	var raw []any
	switch s := m["Statement"].(type) {
	case []any:
		raw = s
	case map[string]any:
		raw = []any{s}
	}
	var out []statement
	for _, item := range raw {
		s, _ := item.(map[string]any)
		if s == nil {
			continue
		}
		st := statement{allow: s["Effect"] == "Allow", condition: s["Condition"] != nil}
		st.actions = goStrings(s["Action"])
		st.resources = goStrings(s["Resource"])
		switch p := s["Principal"].(type) {
		case string:
			st.anyone = p == "*"
		case map[string]any:
			for _, k := range []string{"AWS", "*"} {
				for _, v := range goStrings(p[k]) {
					st.anyone = st.anyone || v == "*"
				}
			}
		}
		out = append(out, st)
	}
	return out
}

// documentStatements reads data "aws_iam_policy_document" statement blocks.
func documentStatements(body *hclsyntax.Body) []statement {
	var out []statement
	for _, b := range body.Blocks {
		if b.Type != "statement" {
			continue
		}
		effect, set := str(b.Body, "effect")
		st := statement{allow: !set || effect == "Allow", actions: strs(b.Body, "actions"), resources: strs(b.Body, "resources")}
		for _, p := range b.Body.Blocks {
			switch p.Type {
			case "principals":
				t, _ := str(p.Body, "type")
				for _, id := range strs(p.Body, "identifiers") {
					st.anyone = st.anyone || ((t == "AWS" || t == "*") && id == "*")
				}
			case "condition":
				st.condition = true
			}
		}
		out = append(out, st)
	}
	return out
}

func policyFindings(g *model.Graph, node string, st statement, file string, ln int) {
	if !st.allow {
		return
	}
	if st.anyone && !st.condition {
		g.Add(model.High, node, "Anyone can access it", `The policy allows Principal "*", which means anyone, including people outside your account, without any condition. Name the accounts or services that need access, or add a condition.`, file, ln)
	}
	if contains(st.actions, "*") && contains(st.resources, "*") {
		g.Add(model.High, node, "Permission to do everything", `The policy allows every action ("*") on every resource ("*"). Name the actions and resources that are needed.`, file, ln)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func goStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// toGo turns the known parts of a cty value into plain Go values.
func toGo(v cty.Value) any {
	if v == cty.NilVal || v.IsNull() || !v.IsKnown() {
		return nil
	}
	t := v.Type()
	switch {
	case t == cty.String:
		return v.AsString()
	case t == cty.Bool:
		return v.True()
	case t == cty.Number:
		return v.AsBigFloat().String()
	case t.IsObjectType() || t.IsMapType():
		m := map[string]any{}
		for it := v.ElementIterator(); it.Next(); {
			k, e := it.Element()
			m[k.AsString()] = toGo(e)
		}
		return m
	case t.IsTupleType() || t.IsListType() || t.IsSetType():
		var out []any
		for it := v.ElementIterator(); it.Next(); {
			_, e := it.Element()
			out = append(out, toGo(e))
		}
		return out
	}
	return nil
}
