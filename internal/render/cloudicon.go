package render

import (
	"embed"
	"html/template"
	"regexp"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// The official Azure and AWS icons, used for boxes that are in a cloud.
// See cloudicons/NOTICE.md for where they come from and on what terms.
//
//go:embed cloudicons/*.svg
var cloudIconFiles embed.FS

// cloudIcon picks the official icon for a box: by cloud, then by the kind
// of icon, then by words in its plain name, first match wins. Boxes that
// are not in a cloud, or have no matching icon, keep LookFirst's own.
var cloudIconRules = []struct {
	cloud, kind string
	words       *regexp.Regexp // in the plain name; nil matches any
	icon        string
}{
	// AWS
	{"aws", "vm", regexp.MustCompile(`(?i)lightsail`), "aws-lightsail"},
	{"aws", "vm", nil, "aws-ec2"},
	{"aws", "function", regexp.MustCompile(`(?i)step functions`), "aws-stepfunctions"},
	{"aws", "function", nil, "aws-lambda"},
	{"aws", "kubernetes", nil, "aws-eks"},
	{"aws", "container", regexp.MustCompile(`(?i)app runner`), "aws-apprunner"},
	{"aws", "container", nil, "aws-ecs"},
	{"aws", "webapp", regexp.MustCompile(`(?i)api gateway|appsync`), "aws-apigateway"},
	{"aws", "webapp", regexp.MustCompile(`(?i)beanstalk`), "aws-beanstalk"},
	{"aws", "database", regexp.MustCompile(`(?i)dynamodb`), "aws-dynamodb"},
	{"aws", "database", regexp.MustCompile(`(?i)elasticache`), "aws-elasticache"},
	{"aws", "database", regexp.MustCompile(`(?i)aurora`), "aws-aurora"},
	{"aws", "database", regexp.MustCompile(`(?i)redshift`), "aws-redshift"},
	{"aws", "database", regexp.MustCompile(`(?i)opensearch|elasticsearch`), "aws-opensearch"},
	{"aws", "database", nil, "aws-rds"},
	{"aws", "storage", regexp.MustCompile(`(?i)\bs3\b|bucket`), "aws-s3"},
	{"aws", "storage", regexp.MustCompile(`(?i)ebs|disk`), "aws-ebs"},
	{"aws", "storage", regexp.MustCompile(`(?i)efs|file system`), "aws-efs"},
	{"aws", "storage", regexp.MustCompile(`(?i)registry|ecr`), "aws-ecr"},
	{"aws", "network", regexp.MustCompile(`(?i)transit`), "aws-transitgateway"},
	{"aws", "network", nil, "aws-vpc"},
	// Subnets: see cloudIconFor, which looks at the name.
	{"aws", "globe", regexp.MustCompile(`(?i)internet gateway`), "aws-igw"},
	{"aws", "globe", regexp.MustCompile(`(?i)nat`), "aws-nat"},
	{"aws", "globe", regexp.MustCompile(`(?i)cloudfront|cdn`), "aws-cloudfront"},
	{"aws", "globe", regexp.MustCompile(`(?i)lambda`), "aws-lambda"},
	{"aws", "publicip", nil, "aws-eip"},
	{"aws", "nic", regexp.MustCompile(`(?i)endpoint`), "aws-vpce"},
	{"aws", "nic", nil, "aws-eni"},
	{"aws", "loadbalancer", nil, "aws-elb"},
	{"aws", "dns", nil, "aws-route53"},
	{"aws", "firewall", regexp.MustCompile(`(?i)\bacl\b`), "aws-nacl"},
	{"aws", "firewall", regexp.MustCompile(`(?i)web application|waf`), "aws-waf"},
	{"aws", "firewall", nil, "aws-networkfirewall"},
	{"aws", "shield", regexp.MustCompile(`(?i)guardduty`), "aws-guardduty"},
	{"aws", "identity", regexp.MustCompile(`(?i)cognito`), "aws-cognito"},
	{"aws", "identity", regexp.MustCompile(`(?i)role`), "aws-iamrole"},
	{"aws", "identity", nil, "aws-iam"},
	{"aws", "key", regexp.MustCompile(`(?i)kms`), "aws-kms"},
	{"aws", "key", regexp.MustCompile(`(?i)secret|parameter`), "aws-secrets"},
	{"aws", "key", regexp.MustCompile(`(?i)certificate|tls`), "aws-acm"},
	{"aws", "key", nil, "aws-iam"},
	{"aws", "monitor", regexp.MustCompile(`(?i)cloudtrail`), "aws-cloudtrail"},
	{"aws", "monitor", nil, "aws-cloudwatch"},
	{"aws", "relay", regexp.MustCompile(`(?i)\bsqs\b|queue`), "aws-sqs"},
	{"aws", "relay", regexp.MustCompile(`(?i)\bsns\b|topic`), "aws-sns"},
	{"aws", "relay", regexp.MustCompile(`(?i)eventbridge|rule`), "aws-eventbridge"},
	{"aws", "relay", regexp.MustCompile(`(?i)kinesis|firehose|stream`), "aws-kinesis"},
	{"aws", "terminal", regexp.MustCompile(`(?i)systems manager`), "aws-ssm"},

	// Azure
	{"azure", "vm", nil, "azure-vm"},
	{"azure", "function", regexp.MustCompile(`(?i)function`), "azure-function"},
	{"azure", "kubernetes", nil, "azure-aks"},
	{"azure", "container", regexp.MustCompile(`(?i)container app`), "azure-containerapps"},
	{"azure", "container", regexp.MustCompile(`(?i)registry`), "azure-acr"},
	{"azure", "container", nil, "azure-aci"},
	{"azure", "plan", regexp.MustCompile(`(?i)container apps`), "azure-containerapps"},
	{"azure", "plan", nil, "azure-appserviceplan"},
	{"azure", "webapp", regexp.MustCompile(`(?i)function`), "azure-function"},
	{"azure", "webapp", regexp.MustCompile(`(?i)api management`), "azure-apim"},
	{"azure", "webapp", nil, "azure-appservice"},
	{"azure", "database", regexp.MustCompile(`(?i)cosmos`), "azure-cosmos"},
	{"azure", "database", regexp.MustCompile(`(?i)postgres`), "azure-postgres"},
	{"azure", "database", regexp.MustCompile(`(?i)mysql`), "azure-mysql"},
	{"azure", "database", regexp.MustCompile(`(?i)redis`), "azure-redis"},
	{"azure", "database", regexp.MustCompile(`(?i)sql`), "azure-sql"},
	{"azure", "storage", regexp.MustCompile(`(?i)registry`), "azure-acr"},
	{"azure", "storage", regexp.MustCompile(`(?i)disk`), "azure-disk"},
	{"azure", "storage", regexp.MustCompile(`(?i)container`), "azure-storagecontainer"},
	{"azure", "storage", nil, "azure-storage"},
	{"azure", "network", nil, "azure-vnet"},
	{"azure", "subnet", nil, "azure-subnet"},
	{"azure", "nic", regexp.MustCompile(`(?i)private endpoint`), "azure-privateendpoint"},
	{"azure", "nic", nil, "azure-nic"},
	{"azure", "publicip", nil, "azure-publicip"},
	{"azure", "loadbalancer", regexp.MustCompile(`(?i)application gateway`), "azure-appgw"},
	{"azure", "loadbalancer", nil, "azure-lb"},
	{"azure", "globe", regexp.MustCompile(`(?i)front door|cdn`), "azure-frontdoor"},
	{"azure", "dns", nil, "azure-dns"},
	{"azure", "shield", regexp.MustCompile(`(?i)bastion`), "azure-bastion"},
	{"azure", "shield", regexp.MustCompile(`(?i)defender`), "azure-defender"},
	{"azure", "shield", regexp.MustCompile(`(?i)security group|nsg`), "azure-nsg"},
	// A database firewall rule is not Azure Firewall, the product; it keeps
	// LookFirst's own icon.
	{"azure", "firewall", regexp.MustCompile(`(?i)firewall rule`), ""},
	{"azure", "firewall", nil, "azure-firewall"},
	{"azure", "key", nil, "azure-keyvault"},
	{"azure", "identity", regexp.MustCompile(`(?i)role`), "azure-roles"},
	{"azure", "identity", nil, "azure-identity"},
	{"azure", "relay", regexp.MustCompile(`(?i)service bus`), "azure-servicebus"},
	{"azure", "relay", regexp.MustCompile(`(?i)event hub`), "azure-eventhubs"},
	{"azure", "monitor", regexp.MustCompile(`(?i)log analytics`), "azure-loganalytics"},
	{"azure", "monitor", nil, "azure-monitor"},
}

func cloudIconFor(n *model.Node) string {
	if n.Cloud == "" {
		return ""
	}
	// AWS draws public and private subnets differently. A subnet is
	// private unless its name says it is public.
	if n.Cloud == "aws" && n.Kind == "subnet" {
		if strings.Contains(strings.ToLower(n.Name), "pub") {
			return "aws-subnet"
		}
		return "aws-subnet-private"
	}
	for _, r := range cloudIconRules {
		if r.cloud == n.Cloud && r.kind == n.Kind && (r.words == nil || r.words.MatchString(n.Friendly)) {
			return r.icon
		}
	}
	return ""
}

var (
	svgRoot   = regexp.MustCompile(`(?s)<svg\b([^>]*)>(.*)</svg>`)
	viewBoxRe = regexp.MustCompile(`viewBox="([^"]+)"`)
	titleRe   = regexp.MustCompile(`(?s)<title>.*?</title>`)
	idRe      = regexp.MustCompile(`\bid="([^"]+)"`)
	urlRefRe  = regexp.MustCompile(`url\(#([^)]+)\)`)
	hrefRe    = regexp.MustCompile(`href="#([^"]+)"`)
)

// iconSymbol turns an icon file into a <symbol> the report can reuse. The
// icon's ids get a prefix of its own, so two icons on a page cannot clash;
// nothing about how it looks is changed.
func iconSymbol(name string) (template.HTML, bool) {
	data, err := cloudIconFiles.ReadFile("cloudicons/" + name + ".svg")
	if err != nil {
		return "", false
	}
	m := svgRoot.FindStringSubmatch(string(data))
	if m == nil {
		return "", false
	}
	viewBox := "0 0 64 64"
	if v := viewBoxRe.FindStringSubmatch(m[1]); v != nil {
		viewBox = v[1]
	}
	inner := titleRe.ReplaceAllString(m[2], "")
	prefix := "ic-" + name + "-"
	inner = idRe.ReplaceAllString(inner, `id="`+prefix+`$1"`)
	inner = urlRefRe.ReplaceAllString(inner, `url(#`+prefix+`$1)`)
	inner = hrefRe.ReplaceAllString(inner, `href="#`+prefix+`$1"`)
	// The files are ours, checked when copied in, and contain no scripts.
	return template.HTML(`<symbol id="ic-` + name + `" viewBox="` + viewBox + `">` + inner + `</symbol>`), true
}

// iconSymbols returns the symbols for the icons a report uses, once each.
func iconSymbols(names []string) template.HTML {
	var b strings.Builder
	seen := map[string]bool{}
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		if s, ok := iconSymbol(n); ok {
			b.WriteString(string(s))
		}
	}
	return template.HTML(b.String())
}
