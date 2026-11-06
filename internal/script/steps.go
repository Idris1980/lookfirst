package script

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
	"github.com/Idris1980/lookfirst/internal/source"
)

// The steps of a script: every command that changes something in the
// cloud, or hands it code, a template or an image, in the order the script
// runs them. Commands that only look (show, list, describe) are left out;
// a command LookFirst does not know is listed as it is, so nothing that
// changes something is missed.

var (
	stepCLI = regexp.MustCompile(`(?:^\s*|[;&|({=]\s*|\$\(\s*)(az|aws|func|docker|kubectl|helm|terraform|sam|gcloud)\s+(.*)`)
	pushDir = regexp.MustCompile(`(?i)^\s*(Push-Location|Set-Location|pushd|cd)\s+(?:-Path\s+)?(.+?)\s*$`)
	// (Join-Path $PSScriptRoot "web") written inside a command.
	inlineJoin  = regexp.MustCompile(`\(Join-Path\s+([^)]*)\)`)
	popDir      = regexp.MustCompile(`(?i)^\s*(Pop-Location|popd)\b`)
	outputVar   = regexp.MustCompile(`\$(\w+)\.(\w+)\.value`)
	assignVar   = regexp.MustCompile(`^\s*\$?(\w+)\s*=\s*\$?\(?\s*(az|aws)\s`)
	queryOutput = regexp.MustCompile(`properties\.outputs(?:\.(\w+)\.value)?`)
	runScript   = regexp.MustCompile(`(?i)^\s*(?:&|\.|bash|sh|pwsh|powershell(?:\.exe)?|source|sudo\s+bash)?\s*(?:-File\s+)?["']?([^\s"';|&]+\.(?:ps1|sh))["']?(\s|$)`)
	adLookup    = regexp.MustCompile(`^\s*\$?(\w+)\s*=\s*\$\(\s*az\s+ad\s+(user|group|sp)\s+show\s+(?:--id|--group)\s+(\S+)`)
	showLookup  = regexp.MustCompile(`^\s*\$?(\w+)\s*=\s*\$\(\s*az\s+((?:[a-z-]+\s+)+?)show\b(.*)`)
	awsLookup   = regexp.MustCompile(`^\s*\$?(\w+)\s*=\s*\$?\(?\s*aws\s+\S+\s+describe-\S+.*?(?:Values=|--group-names\s+|--names\s+|--bucket\s+)([\w.-]+)`)
	psStep      = regexp.MustCompile(`(?i)\b((New|Remove|Set|Publish|Update|Add|Start|Stop|Restart|Invoke|Register|Enable|Disable|Grant|Revoke)-Az\w+)\b(.*)`)
)

func (s *scan) steps() {
	if s.f.Kind != source.Shell && s.f.Kind != source.PowerShell {
		return
	}
	lines := s.logicalLines()
	vars := stringVars(lines)
	resolve := pathResolver(lines)
	dir := []string{"."}           // where the script is, as it changes folder
	outputs := map[string]string{} // variable -> template output, or "*" for all of them

	createdAt := map[int][]*model.Node{}
	for _, n := range s.g.Nodes {
		if n.File == s.f.Path && n.Cloud != "" && !strings.HasPrefix(n.ID, "deploy.") {
			createdAt[n.Line] = append(createdAt[n.Line], n)
		}
	}

	// What a variable holds: $VpcId = aws ec2 create-vpc … holds the VPC,
	// named by create-tags afterwards. Used to name what later lines change.
	named := map[string]string{} // variable -> name
	for _, l := range lines {
		if m := awsCommand.FindStringSubmatch(l.code); m != nil && strings.HasPrefix(m[1], "ec2 create-tags") {
			res, _ := azFlag(m[1], "--resources")
			if v, t := varRef.FindStringSubmatch(res), nameTag.FindStringSubmatch(m[1]); v != nil && t != nil {
				named[strings.ToLower(v[1])] = t[1]
			}
		}
	}
	for _, l := range lines {
		if a := assigned.FindStringSubmatch(l.code); a != nil {
			v := strings.ToLower(a[1] + a[2])
			for _, n := range createdAt[l.n] {
				if !n.Hidden {
					named[v] = n.Name
				}
			}
		}
	}
	// Who a variable holds: GROUP=$(az ad group show --group "Ops" …), or
	// $WebId = aws ec2 describe-instances --filters Name=tag:Name,Values=web.
	for _, l := range lines {
		if m := awsLookup.FindStringSubmatch(l.code); m != nil {
			named[strings.ToLower(m[1])] = strings.Trim(m[2], `"'`)
		}
		if m := adLookup.FindStringSubmatch(l.code); m != nil {
			named[strings.ToLower(m[1])] = "the Entra " + m[2] + " " + strings.Trim(m[3], `"'`)
		} else if m := showLookup.FindStringSubmatch(l.code); m != nil {
			// ID=$(az storage account show -n st1 --query id): the id of st1.
			if n, _ := azFlag(expandVars(m[3], vars), "--name", "-n"); n != "" {
				thing := strings.TrimSpace(m[2])
				if thing == "group" {
					thing = "resource group"
				}
				named[strings.ToLower(m[1])] = "the " + thing + " " + strings.Trim(n, `"'`)
			}
		}
	}
	nameVars := func(args string) string {
		return useVar.ReplaceAllStringFunc(args, func(m string) string {
			if n, ok := named[strings.ToLower(strings.Trim(m, "${}"))]; ok {
				// Non-breaking spaces keep it one value for the flag it is
				// given to; they are made plain again in what the step says.
				return strings.ReplaceAll(n, " ", " ")
			}
			return m
		})
	}

	add := func(st model.Step, call *funcCall) {
		if call != nil {
			// The link goes to where the function is called, where the
			// values come from; what it says names the function.
			st.Line = call.line
			st.Says += " (in " + call.name + ")"
		}
		s.g.Steps = append(s.g.Steps, st)
	}
	funcs, inFunc := scriptFunctions(lines, s.f.Kind)
	zipped := map[string]string{} // a zip file -> the folder packed into it
	var handle func(l line, code string, call *funcCall)
	handle = func(l line, code string, call *funcCall) {
		code = inlineJoin.ReplaceAllStringFunc(code, func(m string) string {
			var parts []string
			for _, q := range quotedPart.FindAllStringSubmatch(m, -1) {
				parts = append(parts, q[1])
			}
			if len(parts) == 0 {
				return m
			}
			return strings.Join(parts, "/")
		})
		if m := pushDir.FindStringSubmatch(code); m != nil {
			dir = append(dir, resolve(expandVars(m[2], vars)))
			return
		}
		if popDir.MatchString(code) && len(dir) > 1 {
			dir = dir[:len(dir)-1]
			return
		}
		st := model.Step{File: s.f.Path, Line: l.n, Code: shorten(code)}

		// Another script it runs.
		if m := runScript.FindStringSubmatch(code); m != nil && !stepCLI.MatchString(code) {
			st.Runs = resolve(expandVars(m[1], vars))
			st.Says = "Runs the script " + st.Runs
			add(st, call)
			return
		}

		if s.printedOnly(code) {
			return // only shown to the user, as in echo "run: curl …"
		}
		// What it does on the machine itself, and containers it starts.
		if local, ok := localStep(expandVars(code, vars), dir[len(dir)-1], resolve); ok && (!stepCLI.MatchString(code) || localCompose.MatchString(code) || localRun.MatchString(code)) {
			local.File, local.Line, local.Code = st.File, st.Line, st.Code
			if m := compressArchive.FindStringSubmatch(code); m != nil {
				zipped[strings.ToLower(resolve(expandVars(m[2], vars)))] = strings.TrimSuffix(resolve(expandVars(m[1], vars)), "/*")
			}
			add(local, call)
			return
		}

		var tool, args string
		if m := stepCLI.FindStringSubmatch(code); m != nil {
			tool, args = m[1], expandVars(m[2], vars)
		} else if m := psStep.FindStringSubmatch(code); m != nil {
			tool, args = "ps", m[1]+expandVars(m[3], vars)
		} else {
			return
		}
		if tool == "docker" && strings.HasPrefix(args, "compose") {
			return // only docker compose up changes something, above
		}

		// A variable that keeps a deployment's outputs: $out = az
		// deployment group show … --query properties.outputs.
		if a := assignVar.FindStringSubmatch(code); a != nil {
			if q := queryOutput.FindStringSubmatch(args); q != nil {
				if q[1] != "" {
					outputs[strings.ToLower(a[1])] = q[1]
				} else {
					outputs[strings.ToLower(a[1])] = "*"
				}
			}
		}
		if readOnly(tool, args) {
			return
		}
		// What the command names by a deployment output, such as
		// $out.funcName.value.
		for _, m := range outputVar.FindAllStringSubmatch(args, -1) {
			if _, ok := outputs[strings.ToLower(m[1])]; ok {
				st.Output = m[2]
				args = strings.Replace(args, m[0], "«"+m[2]+"»", 1) // named once the template has run
			}
		}
		for v, out := range outputs {
			if out != "*" && (strings.Contains(args, "$"+v) || strings.Contains(strings.ToLower(args), "$"+v) || strings.Contains(strings.ToLower(args), "${"+v+"}")) {
				st.Output = out
			}
		}
		here := dir[len(dir)-1]
		s.describe(&st, tool, nameVars(args), here, resolve, createdAt[l.n])
		st.Says = strings.ReplaceAll(st.Says, " ", " ")
		if folder, ok := zipped[strings.ToLower(st.From)]; ok {
			st.Says = strings.Replace(st.Says, "Uploads "+st.From, "Uploads the code in "+folder+"/ (packed into a zip file)", 1)
			st.From = folder
		}
		add(st, call)
	}

	for _, l := range lines {
		if inFunc[l.n] {
			continue // run where it is called, below
		}
		code := l.code
		if name, args, ok := callOf(code, funcs); ok {
			fn := funcs[strings.ToLower(name)]
			call := &funcCall{name: fn.name, line: l.n, values: map[string]string{}}
			for i, p := range fn.params {
				if i < len(args) {
					call.values[strings.ToLower(p)] = args[i]
				}
			}
			for _, bl := range fn.body {
				handle(bl, call.substitute(bl.code), call)
			}
			continue
		}
		handle(l, code, nil)
	}
}

// readOnly reports whether a command only looks, waits or logs in, so it
// changes nothing and is not a step.
func readOnly(tool, args string) bool {
	words := firstWords(strings.Fields(args), 5)
	if len(words) == 0 {
		return true
	}
	last := strings.ToLower(words[len(words)-1])
	first := strings.ToLower(words[0])
	looks := func(w string) bool {
		switch w {
		case "show", "list", "wait", "login", "logout", "version", "ls", "validate", "validate-template", "what-if", "help", "get", "describe", "logs", "status", "plan", "fmt", "output", "init", "get-credentials", "get-login-password", "check-name", "exists":
			return true
		}
		return strings.HasPrefix(w, "list-") || strings.HasPrefix(w, "show-") || strings.HasPrefix(w, "get-") || strings.HasPrefix(w, "describe-")
	}
	switch tool {
	case "az":
		switch first {
		case "account", "login", "logout", "config", "extension", "bicep", "upgrade", "version", "provider", "feature", "cloud":
			return true
		}
		return looks(last)
	case "aws":
		if len(words) > 1 {
			op := strings.ToLower(words[1])
			return looks(op) || op == "create-tags" || first == "sts" || first == "configure" || (first == "s3" && op == "ls")
		}
		return true
	case "terraform", "helm", "sam":
		return looks(first) || first == "build" || first == "package" || first == "repo" || first == "dependency"
	case "kubectl":
		return looks(first) || first == "config" || first == "port-forward" || first == "exec" || first == "rollout" && len(words) > 1 && words[1] == "status"
	case "docker":
		return first != "build" && first != "push" && first != "run" && first != "compose" && !(first == "buildx" && len(words) > 1)
	case "func":
		return !(first == "azure" && len(words) > 2 && words[1] == "functionapp" && words[2] == "publish")
	case "ps":
		return false
	}
	return looks(last)
}

// describe says what one command does.
func (s *scan) describe(st *model.Step, tool, args, here string, resolve func(string) string, created []*model.Node) {
	flag := func(names ...string) string {
		v, _ := azFlag(args, names...)
		return strings.Trim(v, `"'`)
	}
	words := strings.Fields(args)
	verb := strings.Join(firstWords(words, 4), " ")
	name := flag("--name", "-n", "--function-name", "--stack-name")
	target := func(n string) {
		if id := s.cloudNode(n); id != "" {
			st.Changes = append(st.Changes, id)
		}
	}
	defer func() {
		// What it creates and what it expects to be there, by kind and
		// name, for the chain to tell what must exist before it runs.
		for _, n := range created {
			st.Made = append(st.Made, n.Kind+"|"+n.Name)
		}
		if tool == "az" && strings.HasPrefix(args, "group create") {
			st.Made = append(st.Made, "group|"+name)
		}
		if !st.Deletes {
			st.Needs = append(st.Needs, needsOf(tool, args, flag)...)
		}
	}()

	// A template handed to the cloud.
	for _, d := range deployCmds {
		if d.re.MatchString(tool + " " + args) {
			file := ""
			for _, f := range d.flags {
				v, ok := azFlag(args, f)
				if !ok {
					v, ok = psParam(args, strings.TrimPrefix(f, "-"))
				}
				if ok && v != "" {
					file = resolve(v)
					break
				}
			}
			st.Template = file
			st.Params = deployParams(args)
			if f, ok := st.Params["@"]; ok {
				st.Params["@"] = resolve(f)
			}
			cloud := "Azure"
			if d.cloud == "aws" {
				cloud = "AWS"
			}
			st.Says = fmt.Sprintf("Hands the template %s to %s to build", file, cloud)
			if len(st.Params) > 0 {
				var ps []string
				for _, k := range paramKeys(st.Params) {
					if k == "@" {
						ps = append(ps, "the parameters in "+st.Params[k])
						continue
					}
					ps = append(ps, k+"="+st.Params[k])
				}
				st.Says += ", with " + strings.Join(ps, ", ")
			}
			return
		}
	}

	op := ""
	if len(words) > 1 {
		op = words[1]
	}
	switch {
	case tool == "az" && strings.HasPrefix(args, "role assignment create"):
		st.Says = fmt.Sprintf("Gives %s the role %s on %s", firstNonEmpty(flag("--assignee"), flag("--assignee-object-id"), "someone"), flag("--role"), firstNonEmpty(flag("--scope"), "the subscription"))
		for _, n := range created {
			st.Creates = append(st.Creates, n.ID)
		}
	case tool == "aws" && words[0] == "iam" && len(created) == 0 && awsIAMWords[op] != "":
		st.Says = awsIAM(op, flag)
	case len(created) > 0:
		var names, extra []string
		for _, n := range created {
			st.Creates = append(st.Creates, n.ID)
			kind := plainKind(n.Friendly)
			if tool == "aws" && strings.HasPrefix(kind, "IAM identity") {
				kind = "IAM " + strings.TrimPrefix(op, "create-")
			}
			switch {
			case n.Hidden || n.Code == "made by az vm create":
				what := kind + " " + n.Name
				if n.Hidden {
					what = kind
				}
				if strings.HasSuffix(n.Name, "NSG") && strings.Contains(st.Code+args, "vm create") && !strings.Contains(args, "--nsg-rule NONE") {
					what += " (that lets anyone in on SSH or RDP)"
				}
				extra = append(extra, article(kind)+" "+what)
			default:
				names = append(names, "the "+kind+" "+n.Name)
			}
		}
		st.Says = "Creates " + strings.Join(names, ", ")
		if len(extra) > 0 {
			st.Says += ", and with it " + strings.Join(extra, ", ")
		}
		if f := flag("--custom-data", "--user-data"); f != "" {
			st.From = path.Join(here, resolve(f))
			st.Says += ", and runs " + st.From + " on it when it starts"
		}

	case tool == "az" && strings.HasPrefix(args, "group create"):
		st.Says = "Creates the resource group " + name + ", the folder in Azure that the rest is put in"
	case tool == "az" && strings.HasPrefix(args, "group delete"), tool == "ps" && strings.HasPrefix(strings.ToLower(args), "remove-azresourcegroup"):
		if name == "" {
			name, _ = psParam(args, "Name")
		}
		st.Deletes = true
		st.Says = "Deletes the resource group " + name + " and everything in it"

	case tool == "func" && strings.HasPrefix(args, "azure functionapp publish"):
		app := strings.Trim(firstOr(words, 3), `"'`)
		st.From = here
		st.Says = fmt.Sprintf("Uploads the code in %s to the function app %s", folderName(here), app)
		target(app)
	case tool == "az" && regexp.MustCompile(`^(functionapp|webapp)\s+(deployment\s+source\s+config-zip|deploy|up)\b`).MatchString(args):
		src := flag("--src", "--src-path")
		if src == "" {
			src = here
		} else {
			src = path.Join(here, resolve(src))
		}
		st.From = src
		st.Says = fmt.Sprintf("Uploads %s to the app %s", src, name)
		target(name)
	case tool == "az" && strings.HasPrefix(args, "acr build"):
		dirArg := lastPositional(words[2:])
		st.From = path.Join(here, resolve(dirArg))
		reg := flag("--registry", "-r")
		st.Says = fmt.Sprintf("Builds the container image %s from %s (its Dockerfile) in Azure and stores it in the registry %s", flag("--image", "-t"), st.From, reg)
		target(reg)
	case tool == "az" && strings.HasPrefix(args, "acr import"):
		st.Says = fmt.Sprintf("Copies the image %s into the registry %s", flag("--source"), name)
		target(name)
	case tool == "docker" && strings.HasPrefix(args, "build"):
		st.From = path.Join(here, resolve(lastPositional(words[1:])))
		st.Says = fmt.Sprintf("Builds the container image %s from %s on your computer", flag("-t", "--tag"), st.From)
	case tool == "docker" && strings.HasPrefix(args, "push"):
		st.Says = "Uploads the container image " + firstOr(words, 1) + " to its registry"
	case tool == "aws" && regexp.MustCompile(`^s3\s+(cp|sync|mv)\b`).MatchString(args):
		src := strings.Trim(firstOr(words, 2), `"'`)
		dst := strings.Trim(firstOr(words, 3), `"'`)
		st.From = path.Join(here, resolve(src))
		st.Says = fmt.Sprintf("Copies %s to %s", st.From, dst)
		if m := s3Target.FindStringSubmatch(dst); m != nil {
			target(m[1])
		}
	case tool == "aws" && strings.HasPrefix(args, "lambda update-function-code"):
		if z := flag("--zip-file"); z != "" {
			st.From = path.Join(here, resolve(z))
		}
		st.Says = fmt.Sprintf("Uploads %s as the code of the Lambda function %s", st.From, name)
		target(name)
	case tool == "kubectl" && regexp.MustCompile(`^(apply|create)\b`).MatchString(args):
		f := flag("-f", "--filename", "-k")
		st.Template = path.Join(here, resolve(f))
		st.Says = "Applies the Kubernetes files in " + st.Template + " to the cluster"
	case tool == "helm" && regexp.MustCompile(`^(install|upgrade)\b`).MatchString(args):
		st.Says = "Installs the Helm chart " + strings.Join(firstWords(words[1:], 2), " ") + " in the cluster"
	case tool == "terraform" && regexp.MustCompile(`^(apply|destroy)\b|^-chdir=\S+\s+(apply|destroy)\b`).MatchString(args):
		d := here
		if m := regexp.MustCompile(`-chdir=(\S+)`).FindStringSubmatch(args); m != nil {
			d = path.Join(here, resolve(m[1]))
		}
		if strings.Contains(args, "destroy") {
			st.Deletes = true
			st.Says = "Deletes everything the Terraform code in " + folderName(d) + " built"
		} else {
			st.Template = d
			st.Says = "Builds what the Terraform code in " + folderName(d) + " describes"
		}

	// Changes to what is already there.
	case tool == "az" && strings.HasPrefix(args, "network nsg rule create"), tool == "az" && strings.HasPrefix(args, "network nsg rule update"):
		ports := azFlagList(args, "--destination-port-ranges")
		if len(ports) == 0 && strings.Contains(args, "create") {
			ports = []string{"80"}
		}
		srcs := azFlagList(args, "--source-address-prefixes")
		access := flag("--access")
		nsg := flag("--nsg-name")
		verbWord := "Lets in"
		if strings.EqualFold(access, "Deny") {
			verbWord = "Blocks"
		}
		st.Says = fmt.Sprintf("%s %s on %s from %s", verbWord, portWords(ports), nsg, sourceWords(srcs))
		if strings.Contains(args, "update") && len(ports) == 0 {
			st.Says = fmt.Sprintf("Changes the rule %s on %s: now from %s", name, nsg, sourceWords(srcs))
		}
		target(nsg)
	case tool == "aws" && strings.HasPrefix(args, "ec2 authorize-security-group-ingress"):
		port := flag("--port")
		src := flag("--cidr", "--cidr-ip")
		who := sourceWords([]string{src})
		if g := flag("--source-group"); g != "" {
			who = "the group " + g
		}
		st.Says = fmt.Sprintf("Lets in %s on the security group %s from %s", portWords([]string{port}), flag("--group-id"), who)
	case tool == "az" && strings.HasPrefix(args, "vm open-port"):
		st.Says = fmt.Sprintf("Opens %s on the VM %s to everyone", portWords(strings.Split(flag("--port"), ",")), name)
		target(name)
	case tool == "az" && strings.HasPrefix(args, "role assignment create"):
		st.Says = fmt.Sprintf("Gives %s the role %s on %s", firstNonEmpty(flag("--assignee"), flag("--assignee-object-id"), "someone"), flag("--role"), firstNonEmpty(flag("--scope"), "the subscription"))
	case tool == "az" && strings.HasPrefix(args, "keyvault secret set"):
		st.Says = fmt.Sprintf("Stores the secret %s in the key vault %s", name, flag("--vault-name"))
		target(flag("--vault-name"))
	case tool == "az" && regexp.MustCompile(`^(webapp|functionapp)\s+config\s+appsettings\s+set\b`).MatchString(args):
		st.Says = "Sets app settings on " + name
		target(name)
	case tool == "az" && regexp.MustCompile(`^vm\s+(run-command|extension)\b`).MatchString(args):
		st.Says = "Runs commands on the VM " + firstNonEmpty(flag("--vm-name"), name)
		target(firstNonEmpty(flag("--vm-name"), name))
	case tool == "az" && regexp.MustCompile(`^network\s+vnet\s+subnet\s+update\b`).MatchString(args):
		st.Says = fmt.Sprintf("Puts the security group %s on the subnet %s", flag("--network-security-group", "--nsg"), name)
		target(name)

	case tool == "aws" && strings.HasPrefix(args, "ec2 associate-iam-instance-profile"):
		prof := flag("--iam-instance-profile")
		prof = strings.TrimPrefix(prof, "Name=")
		st.Says = fmt.Sprintf("Gives the EC2 server %s the instance profile %s, so it runs with that role's rights", flag("--instance-id"), prof)
		target(flag("--instance-id"))
	case tool == "aws" && strings.HasPrefix(args, "ec2 attach-internet-gateway"):
		st.Says = fmt.Sprintf("Connects the internet gateway %s to the VPC %s, so the VPC can reach the internet", flag("--internet-gateway-id"), flag("--vpc-id"))
		target(flag("--internet-gateway-id"))
	case tool == "aws" && strings.HasPrefix(args, "ec2 create-route-table"):
		st.Says = "Creates a route table in the VPC " + flag("--vpc-id")
	case tool == "aws" && strings.HasPrefix(args, "ec2 create-route "):
		to := flag("--destination-cidr-block")
		via := firstNonEmpty(flag("--gateway-id"), flag("--nat-gateway-id"), flag("--instance-id"), flag("--transit-gateway-id"))
		if to == "0.0.0.0/0" {
			st.Says = fmt.Sprintf("Sends all traffic for the internet (0.0.0.0/0) in the route table %s through %s", flag("--route-table-id"), via)
		} else {
			st.Says = fmt.Sprintf("Sends traffic for %s in the route table %s through %s", to, flag("--route-table-id"), via)
		}
	case tool == "aws" && strings.HasPrefix(args, "ec2 associate-route-table"):
		st.Says = fmt.Sprintf("Uses the route table %s for the subnet %s", flag("--route-table-id"), flag("--subnet-id"))
		target(flag("--subnet-id"))
	case tool == "aws" && strings.HasPrefix(args, "ec2 create-network-acl-entry"):
		way := "in"
		if strings.Contains(args, "--egress") {
			way = "out"
		}
		action := "Lets " + way
		if strings.EqualFold(flag("--rule-action"), "deny") {
			action = "Blocks"
		}
		ports := flag("--port-range")
		ports = strings.NewReplacer("From=", "", ",To=", "-").Replace(ports)
		if p := strings.Split(ports, "-"); len(p) == 2 && p[0] == p[1] {
			ports = p[0]
		}
		who := sourceWords([]string{flag("--cidr-block")})
		if way == "out" {
			who = strings.Replace(who, "anyone on", "anywhere on", 1)
		}
		st.Says = fmt.Sprintf("%s %s %s %s in the network ACL %s", action, portWords([]string{ports}), map[string]string{"in": "from", "out": "to"}[way], who, flag("--network-acl-id"))
		target(flag("--network-acl-id"))
	case tool == "aws" && strings.HasPrefix(args, "ec2 replace-network-acl-association"):
		st.Says = "Puts the network ACL " + flag("--network-acl-id") + " on a subnet in place of the default one"
		target(flag("--network-acl-id"))

	case tool == "az" && strings.HasPrefix(args, "storage blob upload"):
		st.From = path.Join(here, resolve(firstNonEmpty(flag("--file", "-f"), flag("--source", "-s"))))
		st.Says = fmt.Sprintf("Uploads %s to the container %s in the storage account %s", st.From, flag("--container-name", "-c", "--destination", "-d"), flag("--account-name"))
		target(flag("--account-name"))
	case tool == "az" && strings.HasPrefix(args, "resource tag"):
		st.Says = "Adds the tags " + strings.Join(azFlagList(args, "--tags"), " ") + " to " + firstNonEmpty(flag("--ids"), name, "the resources")
	case tool == "az" && strings.HasPrefix(args, "vm identity assign"):
		st.Says = "Gives the VM " + name + " a managed identity, so it can sign in to other Azure services without a password"
		target(name)
	case tool == "az" && strings.HasPrefix(args, "network private-dns link vnet create"):
		st.Says = fmt.Sprintf("Links the private DNS zone %s to the virtual network %s, so names there resolve to private addresses", flag("--zone-name", "-z"), flag("--virtual-network", "-v"))
	case tool == "az" && strings.HasPrefix(args, "network private-endpoint dns-zone-group create"):
		st.Says = fmt.Sprintf("Lets the private endpoint %s put its private address in the DNS zone %s", flag("--endpoint-name"), flag("--private-dns-zone"))
	case tool == "az" && strings.HasPrefix(args, "storage account network-rule add"):
		st.Says = fmt.Sprintf("Lets %s reach the storage account %s", firstNonEmpty(flag("--ip-address"), flag("--subnet"), flag("--vnet-name"), "a network"), flag("--account-name", "-n"))
		target(flag("--account-name", "-n"))
	case tool == "aws" && strings.HasPrefix(args, "s3 rb"):
		st.Deletes = true
		st.Says = "Deletes the bucket " + strings.Trim(firstOr(words, 2), `"'`)
		if strings.Contains(args, "--force") {
			st.Says += " and every file in it"
		}
	case tool == "aws" && op == "terminate-instances":
		st.Deletes = true
		st.Says = "Stops and deletes the EC2 server " + flag("--instance-ids")
		target(flag("--instance-ids"))
	case tool == "aws" && (strings.HasPrefix(op, "detach-") || strings.HasPrefix(op, "disassociate-")):
		thing := strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(op, "detach-"), "disassociate-"), "-", " ")
		st.Says = strings.TrimSpace("Disconnects the " + thing + " " + firstNonEmpty(flag("--internet-gateway-id"), flag("--association-id"), awsNameFlag(flag)))
	case tool == "aws" && strings.HasPrefix(op, "delete-"):
		st.Deletes = true
		thing := strings.ReplaceAll(strings.TrimPrefix(op, "delete-"), "-", " ")
		st.Says = strings.TrimSpace("Deletes the " + strings.ToUpper(words[0]) + " " + thing + " " + awsNameFlag(flag))
	case tool == "az" && regexp.MustCompile(`\bdelete\b`).MatchString(verb):
		st.Deletes = true
		thing := strings.TrimSuffix(verb, " delete")
		who := firstNonEmpty(name, flag("--assignee"), flag("--ids"))
		st.Says = strings.TrimSpace("Deletes the " + thing + " " + who)
		if thing == "role assignment" && flag("--role") != "" {
			st.Says = fmt.Sprintf("Takes the role %s away from %s", flag("--role"), firstNonEmpty(flag("--assignee"), "someone"))
		}
	case (tool == "az" || tool == "aws") && regexp.MustCompile(`(^|\s)(update|set|config)(\s|$)`).MatchString(verb):
		// A change: say which settings it changes.
		var changes []string
		for _, w := range strings.Fields(args) {
			if strings.HasPrefix(w, "--") && !regexp.MustCompile(`^--(name|resource-group|output|query|only-show-errors|subscription|yes)$|^-[gno]$`).MatchString(w) {
				v := flag(w)
				changes = append(changes, strings.TrimPrefix(w, "--")+" "+v)
			}
		}
		st.Says = "Changes " + strings.TrimSpace(name)
		if name == "" {
			st.Says = "Changes the " + strings.TrimSuffix(verb, " update")
		}
		if len(changes) > 0 {
			st.Says += ": " + strings.Join(changes, ", ")
		}
		target(name)

	// Deleting.
	case (tool == "az" && regexp.MustCompile(`\bdelete\b|\bpurge\b`).MatchString(verb)) ||
		(tool == "aws" && regexp.MustCompile(`\b(delete-\S+|terminate-instances|rb|rm)\b`).MatchString(verb)) ||
		(tool == "ps" && strings.HasPrefix(strings.ToLower(args), "remove-az")):
		st.Deletes = true
		st.Says = "Deletes " + strings.TrimSpace(verb+" "+name)

	default:
		prefix := tool + " "
		if tool == "ps" {
			prefix = ""
		}
		st.Says = "Runs " + prefix + verb
		if name != "" {
			st.Says += " on " + name
			target(name)
		}
	}
}

// cloudNode finds a box the script built, by its name.
func (s *scan) cloudNode(name string) string {
	if name == "" {
		return ""
	}
	for _, n := range s.g.Nodes {
		if n.Cloud != "" && n.Name == name {
			return n.ID
		}
	}
	return ""
}

// deployParams reads key=value parameters given to a deployment.
func deployParams(args string) map[string]string {
	out := map[string]string{}
	for _, w := range strings.Fields(args) {
		w = strings.Trim(w, `"'`)
		if strings.HasPrefix(w, "@") && len(w) > 1 {
			out["@"] = w[1:] // a parameters file
			continue
		}
		if k, v, ok := strings.Cut(w, "="); ok && !strings.HasPrefix(k, "-") && regexp.MustCompile(`^\w+$`).MatchString(k) {
			out[k] = v
		}
	}
	// --parameter-overrides Key=Value (CloudFormation) is read the same way.
	return out
}

func portWords(ports []string) string {
	var ps []string
	for _, p := range ports {
		if p = strings.Trim(p, `"'`); p != "" {
			ps = append(ps, p)
		}
	}
	switch {
	case len(ps) == 0:
		return "traffic"
	case len(ps) == 1 && (ps[0] == "*" || ps[0] == "-1"):
		return "every port"
	case len(ps) == 1:
		if name, ok := risk.PortName(atoi(ps[0])); ok {
			return fmt.Sprintf("port %s (%s)", ps[0], name)
		}
		return "port " + ps[0]
	}
	return "ports " + strings.Join(ps, ", ")
}

func sourceWords(srcs []string) string {
	if len(srcs) == 0 || risk.FromAnywhere(srcs) {
		return "anyone on the internet"
	}
	if model.AddressSource(srcs[0]) == model.You {
		return "only your own IP address"
	}
	return strings.Join(srcs, ", ")
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func firstWords(words []string, n int) []string {
	var out []string
	for _, w := range words {
		if strings.HasPrefix(w, "-") || len(out) == n {
			break
		}
		out = append(out, w)
	}
	return out
}

func firstOr(words []string, i int) string {
	if i < len(words) {
		return words[i]
	}
	return ""
}

// lastPositional is the last word that is not a flag or a flag's value.
func lastPositional(words []string) string {
	last := "."
	for i := 0; i < len(words); i++ {
		w := words[i]
		if strings.HasPrefix(w, "-") {
			if !strings.Contains(w, "=") && i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") {
				i++
			}
			continue
		}
		last = w
	}
	return strings.Trim(last, `"'`)
}

func folderName(d string) string {
	if d == "." || d == "" {
		return "the script's folder"
	}
	return d + "/"
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

func shorten(code string) string {
	code = strings.Join(strings.Fields(code), " ")
	if len(code) > 160 {
		code = code[:157] + "…"
	}
	return code
}

func paramKeys(m map[string]string) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// plainKind is a kind of thing without the cloud's name: "VPC in AWS"
// gives "VPC".
func plainKind(friendly string) string {
	return strings.TrimSuffix(strings.TrimSuffix(friendly, " in AWS"), " in Azure")
}

// awsIAMWords are the IAM commands that join users, groups, roles and
// policies, and what they mean.
var awsIAMWords = map[string]string{
	"attach-group-policy":               "Gives the group %[1]s the policy %[2]s",
	"attach-user-policy":                "Gives the user %[3]s the policy %[2]s",
	"attach-role-policy":                "Gives the role %[4]s the policy %[2]s",
	"detach-group-policy":               "Takes the policy %[2]s away from the group %[1]s",
	"detach-user-policy":                "Takes the policy %[2]s away from the user %[3]s",
	"detach-role-policy":                "Takes the policy %[2]s away from the role %[4]s",
	"add-user-to-group":                 "Puts the user %[3]s in the group %[1]s",
	"remove-user-from-group":            "Takes the user %[3]s out of the group %[1]s",
	"put-role-policy":                   "Gives the role %[4]s the rights in %[5]s (policy %[6]s)",
	"put-user-policy":                   "Gives the user %[3]s the rights in %[5]s (policy %[6]s)",
	"put-group-policy":                  "Gives the group %[1]s the rights in %[5]s (policy %[6]s)",
	"add-role-to-instance-profile":      "Puts the role %[4]s in the instance profile %[7]s, so a server with it runs as that role",
	"remove-role-from-instance-profile": "Takes the role %[4]s out of the instance profile %[7]s",
	"create-access-key":                 "Makes a long-lived access key for the user %[3]s",
	"create-login-profile":              "Gives the user %[3]s a password to sign in to the AWS console",
}

func awsIAM(op string, flag func(...string) string) string {
	policy := flag("--policy-arn")
	if i := strings.LastIndex(policy, "/"); i >= 0 {
		policy = policy[i+1:]
	}
	doc := strings.TrimPrefix(strings.TrimPrefix(flag("--policy-document"), "file://"), "fileb://")
	return fmt.Sprintf(awsIAMWords[op], flag("--group-name"), policy, flag("--user-name"), flag("--role-name"), doc, flag("--policy-name"), flag("--instance-profile-name"))
}

// awsNameFlag is the name an AWS command gives what it acts on.
func awsNameFlag(flag func(...string) string) string {
	return firstNonEmpty(flag("--group-name"), flag("--user-name"), flag("--role-name"), flag("--policy-name"),
		flag("--instance-profile-name"), flag("--bucket"), flag("--function-name"), flag("--group-id"),
		flag("--vpc-id"), flag("--subnet-id"), flag("--db-instance-identifier"), flag("--stack-name"), flag("--policy-arn"))
}

func article(word string) string {
	if word != "" && strings.ContainsRune("aeiouAEIOU", rune(word[0])) {
		return "an"
	}
	return "a"
}

// A function the script defines, and what it is called with.
type scriptFunc struct {
	name   string
	params []string
	body   []line
}

type funcCall struct {
	name   string
	line   int
	values map[string]string // parameter -> the value it is called with
}

var (
	psFuncDef       = regexp.MustCompile(`(?i)^\s*function\s+([\w-]+)\s*(?:\(([^)]*)\))?\s*\{?\s*$`)
	shFuncDef       = regexp.MustCompile(`^\s*(?:function\s+)?([\w-]+)\s*\(\)\s*\{?\s*$|^\s*function\s+([\w-]+)\s*\{?\s*$`)
	psParamLine     = regexp.MustCompile(`(?i)^\s*param\s*\(([^)]*)\)`)
	paramName       = regexp.MustCompile(`\$(\w+)`)
	callArg         = regexp.MustCompile(`"[^"]*"|'[^']*'|\S+`)
	compressArchive = regexp.MustCompile(`(?i)\bCompress-Archive\b.*?-Path\s+("[^"]*"|\S+).*?-DestinationPath\s+("[^"]*"|\S+)`)
)

// scriptFunctions finds the functions a script defines, with their
// parameters and the lines inside them.
func scriptFunctions(lines []line, kind source.Kind) (map[string]*scriptFunc, map[int]bool) {
	funcs := map[string]*scriptFunc{}
	inFunc := map[int]bool{}
	for i := 0; i < len(lines); i++ {
		code := lines[i].code
		var fn *scriptFunc
		if kind == source.PowerShell {
			if m := psFuncDef.FindStringSubmatch(code); m != nil {
				fn = &scriptFunc{name: m[1]}
				for _, p := range paramName.FindAllStringSubmatch(m[2], -1) {
					fn.params = append(fn.params, p[1])
				}
			}
		} else if m := shFuncDef.FindStringSubmatch(code); m != nil {
			fn = &scriptFunc{name: m[1] + m[2]}
			for k := 1; k <= 9; k++ {
				fn.params = append(fn.params, fmt.Sprint(k))
			}
		}
		if fn == nil {
			continue
		}
		depth := strings.Count(code, "{") - strings.Count(code, "}")
		inFunc[lines[i].n] = true
		j := i + 1
		if depth == 0 && j < len(lines) && strings.TrimSpace(lines[j].code) == "{" {
			depth = 1
			inFunc[lines[j].n] = true
			j++
		}
		for ; j < len(lines) && depth > 0; j++ {
			c := lines[j].code
			depth += strings.Count(c, "{") - strings.Count(c, "}")
			inFunc[lines[j].n] = true
			if m := psParamLine.FindStringSubmatch(c); m != nil && len(fn.params) == 0 {
				for _, p := range paramName.FindAllStringSubmatch(m[1], -1) {
					fn.params = append(fn.params, p[1])
				}
				continue
			}
			if depth > 0 || strings.TrimSpace(c) != "}" {
				fn.body = append(fn.body, lines[j])
			}
		}
		funcs[strings.ToLower(fn.name)] = fn
		i = j - 1
	}
	return funcs, inFunc
}

// callOf reports whether a line calls one of the script's functions, and
// with which values.
func callOf(code string, funcs map[string]*scriptFunc) (string, []string, bool) {
	words := callArg.FindAllString(strings.TrimSpace(code), -1)
	if len(words) == 0 {
		return "", nil, false
	}
	name := strings.TrimPrefix(words[0], "&")
	if _, ok := funcs[strings.ToLower(name)]; !ok {
		return "", nil, false
	}
	var args []string
	for _, w := range words[1:] {
		if strings.ContainsAny(w, "|;") {
			break
		}
		if strings.HasPrefix(w, "-") && len(w) > 1 && !strings.ContainsAny(w[1:2], "0123456789") {
			continue // a named argument's name; its value is taken in order
		}
		args = append(args, strings.Trim(w, `"'`))
	}
	return name, args, true
}

// substitute puts the values a function is called with into a line of it.
func (c *funcCall) substitute(code string) string {
	return useVar.ReplaceAllStringFunc(code, func(m string) string {
		if v, ok := c.values[strings.ToLower(strings.Trim(m, "${}"))]; ok {
			return v
		}
		return m
	})
}

// needFlags are the flags that name something a command expects to be
// there already, and the kind of thing they name.
var needFlags = map[string][]struct{ flag, kind string }{
	"az": {
		{"--resource-group", "group"}, {"-g", "group"},
		{"--vnet-name", "network"}, {"--subnet", "subnet"},
		{"--nsg", "shield"}, {"--network-security-group", "shield"},
		{"--plan", "plan"}, {"--registry", "registry"},
		{"--vault-name", "key"}, {"--account-name", "storage"}, {"--storage-account", "storage"},
		{"--server", "database"}, {"--environment", "environment"},
	},
	"aws": {
		{"--vpc-id", "network"}, {"--subnet-id", "subnet"}, {"--group-id", "shield"},
		{"--security-group-ids", "shield"}, {"--key-name", "key pair"},
		{"--iam-instance-profile", "instance profile"}, {"--role", "role"},
		{"--image-id", "image"},
	},
}

// needsOf lists what a command names that it does not create itself.
func needsOf(tool, args string, flag func(...string) string) []string {
	var out []string
	for _, f := range needFlags[tool] {
		v := strings.Trim(flag(f.flag), `"'`)
		if v == "" || strings.HasPrefix(v, "«") {
			continue
		}
		// The command's own subject (--name) is not something it needs.
		if (f.kind == "group" && strings.HasPrefix(args, "group ")) || (f.kind == "network" && strings.HasPrefix(args, "network vnet create")) {
			continue
		}
		if f.kind == "subnet" && strings.HasPrefix(args, "network vnet subnet create") {
			continue
		}
		if f.flag == "--group-id" && !strings.HasPrefix(args, "ec2 ") {
			continue
		}
		if f.flag == "--iam-instance-profile" {
			v = strings.TrimPrefix(strings.TrimPrefix(v, "Name="), "Arn=")
		}
		if f.flag == "--image-id" && !strings.HasPrefix(v, "ami-") {
			continue
		}
		out = append(out, f.kind+"|"+v)
	}
	return out
}
