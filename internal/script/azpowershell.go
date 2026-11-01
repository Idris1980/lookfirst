package script

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
)

// Azure PowerShell (the Az module) builds Azure with cmdlets such as
// New-AzVM and New-AzStorageAccount. The parts are tied together through
// variables: $nic = New-AzNetworkInterface … -SubnetId $vnet.Subnets[0].Id.

var (
	psCmdlet   = regexp.MustCompile(`(?i)(?:^|[;|({]\s*|^\s*\$(\w+)\s*=\s*)((?:New|Add|Set|Update)-Az(\w+))\b(.*)`)
	psAssigned = regexp.MustCompile(`^\s*\$(\w+)\s*=\s*(?:New|Add|Set)-Az`)
	psLiteral  = regexp.MustCompile(`^\s*\$(\w+)\s*=\s*["']([^"'$]+)["']\s*$`)
	psVarRef   = regexp.MustCompile(`\$(\w+)`)
	psCamel    = regexp.MustCompile(`([a-z0-9])([A-Z])|([A-Z]+)([A-Z][a-z])`)
	linuxImage = regexp.MustCompile(`(?i)ubuntu|debian|rhel|redhat|centos|suse|linux|oracle|alma|rocky|flatcar|mariner`)
	// ConvertTo-SecureString "Passw0rd!" -AsPlainText: a password written in the script.
	plainSecure = regexp.MustCompile(`(?i)ConvertTo-SecureString\s+(?:-String\s+)?["']([^"'$]+)["']\s+-AsPlainText`)

	// What New-Az<noun> builds. Nouns ending in Config, or creating
	// in-memory objects only, are not drawn.
	psNouns = map[string]struct{ kind, friendly string }{
		"vm": {"vm", "virtual machine in Azure"}, "vmss": {"vm", "VM scale set in Azure"},
		"virtualnetwork": {"network", "virtual network in Azure"}, "publicipaddress": {"publicip", "public IP address in Azure"},
		"networksecuritygroup": {"shield", "network security group in Azure"}, "networkinterface": {"nic", "network interface in Azure"},
		"loadbalancer": {"loadbalancer", "load balancer in Azure"}, "applicationgateway": {"loadbalancer", "application gateway in Azure"},
		"bastion": {"shield", "Azure Bastion in Azure"}, "firewall": {"firewall", "Azure Firewall in Azure"},
		"privateendpoint": {"nic", "private endpoint in Azure"}, "natgateway": {"globe", "NAT gateway in Azure"},
		"storageaccount": {"storage", "storage account in Azure"}, "storagecontainer": {"storage", "storage container in Azure"},
		"sqlserver": {"database", "SQL server in Azure"}, "sqldatabase": {"database", "SQL database in Azure"},
		"postgresqlflexibleserver": {"database", "PostgreSQL server in Azure"}, "mysqlflexibleserver": {"database", "MySQL server in Azure"},
		"cosmosdbaccount": {"database", "Cosmos DB in Azure"}, "rediscache": {"database", "Redis cache in Azure"},
		"keyvault": {"key", "key vault in Azure"}, "webapp": {"webapp", "web app in Azure"}, "functionapp": {"webapp", "function app in Azure"},
		"appserviceplan": {"plan", "App Service plan in Azure"}, "akscluster": {"kubernetes", "Kubernetes in Azure"},
		"containerregistry": {"storage", "container registry in Azure"}, "containergroup": {"container", "container group in Azure"},
		"containerapp": {"container", "container app in Azure"}, "userassignedidentity": {"identity", "managed identity in Azure"},
		"roleassignment": {"identity", "role assignment in Azure"}, "operationalinsightsworkspace": {"monitor", "Log Analytics in Azure"},
		"resourcegroupdeployment": {"terminal", "template deployment in Azure"},
	}
	psNotDrawn = regexp.MustCompile(`(?i)(config|object|credential|^resourcegroup$|^tag$|firewallrule$|^aduser|^adgroup|^adapplication|^adserviceprincipal|ruleset$)`)
)

// psParam returns a cmdlet parameter's value: -Name web, -Name:"web", -Port $port.
func psParam(args, name string) (string, bool) {
	re := regexp.MustCompile(`(?i)(?:^|\s)-` + regexp.QuoteMeta(name) + `(?::|\s+)("[^"]*"|'[^']*'|@\([^)]*\)|\$[\w.\[\]]+|[^\s-][^\s]*)`)
	if m := re.FindStringSubmatch(args); m != nil {
		return strings.Trim(m[1], `"'`), true
	}
	return "", false
}

// psSwitch reports a switch parameter that is on: -Linux, -Linux:$true.
func psSwitch(args, name string) bool {
	re := regexp.MustCompile(`(?i)(?:^|\s)-` + regexp.QuoteMeta(name) + `(:\$true)?(\s|$)`)
	return re.MatchString(args)
}

func psTrue(v string) bool { return strings.EqualFold(v, "$true") || strings.EqualFold(v, "true") }

// psList turns 22,3389 or @(22, 3389) or "22","80" into its items.
func psList(v string) []string {
	v = strings.TrimSuffix(strings.TrimPrefix(v, "@("), ")")
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.Trim(strings.TrimSpace(p), `"'`); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *scan) azPowerShell() {
	lines := s.logicalLines()

	literals := map[string]string{} // $vmName = "web01"
	httpsLater := false
	for _, l := range lines {
		if m := psLiteral.FindStringSubmatch(l.code); m != nil {
			literals[strings.ToLower(m[1])] = m[2]
		}
		if strings.Contains(strings.ToLower(l.code), "set-azwebapp") {
			if v, _ := psParam(l.code, "HttpsOnly"); psTrue(v) {
				httpsLater = true
			}
		}
		if m := plainSecure.FindStringSubmatch(l.code); m != nil {
			risk.CheckSecret(s.g, s.me, "password", m[1], s.f.Path, l.n,
				"read it with Read-Host -AsSecureString, or from Azure Key Vault with Get-AzKeyVaultSecret, instead of writing it in the script")
		}
	}
	resolve := func(v string) string {
		if strings.HasPrefix(v, "$") {
			if lit, ok := literals[strings.ToLower(strings.TrimPrefix(v, "$"))]; ok {
				return lit
			}
		}
		return v
	}

	nodes := map[string]string{}        // variable -> node id
	configRefs := map[string][]string{} // $vmConfig -> nodes added to it
	type pendingRule struct {
		ports []string
		line  int
	}
	rules := map[string]pendingRule{} // $rule -> an NSG rule open to everyone

	for _, l := range lines {
		m := psCmdlet.FindStringSubmatch(l.code)
		if m == nil {
			continue
		}
		assigned := strings.ToLower(m[1])
		if a := psAssigned.FindStringSubmatch(l.code); a != nil {
			assigned = strings.ToLower(a[1])
		}
		verb := strings.ToLower(strings.SplitN(m[2], "-", 2)[0])
		noun := strings.ToLower(m[3])
		args := m[4]
		cmdlet := m[2]
		refs := func() []string {
			var out []string
			for _, r := range psVarRef.FindAllStringSubmatch(args, -1) {
				if id, ok := nodes[strings.ToLower(r[1])]; ok {
					out = append(out, id)
				}
				out = append(out, configRefs[strings.ToLower(r[1])]...)
			}
			return out
		}

		// Rules and settings that are not things of their own.
		switch noun {
		case "networksecurityruleconfig":
			if ports, ok := psOpenRule(args); ok {
				if nsg, _ := psParam(args, "NetworkSecurityGroup"); nsg != "" {
					if id, ok := nodes[strings.ToLower(strings.TrimPrefix(nsg, "$"))]; ok {
						s.g.Expose(id, "", false)
						risk.OpenPorts(s.g, id, ports, s.f.Path, l.n)
						continue
					}
				}
				if assigned != "" {
					rules[assigned] = pendingRule{ports, l.n}
				} else {
					risk.OpenPorts(s.g, s.me, ports, s.f.Path, l.n)
				}
			}
			continue
		case "sqlserverfirewallrule", "postgresqlflexibleserverfirewallrule", "mysqlflexibleserverfirewallrule":
			if psSwitch(args, "AllowAllAzureIPs") {
				s.databaseAccess(s.me, "0.0.0.0", l.n)
			}
			start, _ := psParam(args, "StartIpAddress")
			end, _ := psParam(args, "EndIpAddress")
			s.databaseAccess(s.me, resolve(start)+"-"+resolve(end), l.n)
			continue
		}
		if verb != "new" {
			// Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id and the like.
			if vm, _ := psParam(args, "VM"); vm != "" {
				key := strings.ToLower(strings.TrimPrefix(vm, "$"))
				configRefs[key] = append(configRefs[key], refs()...)
				if assigned != "" && assigned != key {
					configRefs[assigned] = configRefs[key]
				}
			}
			continue
		}
		if psNotDrawn.MatchString(noun) {
			if strings.HasSuffix(noun, "config") && assigned != "" {
				configRefs[assigned] = refs()
			}
			continue
		}

		what, known := psNouns[noun]
		if !known {
			what.kind = "generic"
			what.friendly = strings.ToLower(psCamel.ReplaceAllString(psCamel.ReplaceAllString(m[3], "$1$3 $2$4"), "$1$3 $2$4")) + " in Azure"
		}
		name := ""
		for _, p := range []string{"Name", "VMName", "ResourceName", "ClusterName", "ServerName", "VaultName", "RegistryName", "AccountName"} {
			if v, ok := psParam(args, p); ok {
				name = resolve(v)
				break
			}
		}
		if name == "" {
			if assigned != "" {
				name = "$" + assigned
			} else {
				name = what.friendly
			}
		}
		id := "azure." + what.kind + "." + name
		s.g.AddNode(&model.Node{ID: id, Name: name, Kind: what.kind, Friendly: what.friendly, Code: cmdlet,
			Cloud: "azure", Type: cmdlet, Category: cloudColumn(what.kind), File: s.f.Path, Line: l.n})
		if assigned != "" {
			nodes[assigned] = id
		}
		linked := false
		for _, to := range refs() {
			if to != id {
				s.g.Connect(id, to, "", false)
				linked = true
			}
		}
		if !linked {
			s.g.Connect(s.me, id, "", false)
		}
		add := func(sev model.Severity, title, detail string) { s.g.Add(sev, id, title, detail, s.f.Path, l.n) }

		switch noun {
		case "vm":
			// The simple form (no -VM object) opens ports by default:
			// 3389 and 5985 for Windows, 22 for Linux.
			if _, isConfig := psParam(args, "VM"); isConfig {
				break
			}
			var ports []string
			why := ""
			if v, ok := psParam(args, "OpenPorts"); ok {
				ports = psList(resolve(v))
			} else {
				image, _ := psParam(args, "Image")
				if psSwitch(args, "Linux") || linuxImage.MatchString(resolve(image)) {
					ports = []string{"22"}
				} else {
					ports = []string{"3389", "5985"}
				}
				why = "New-AzVM opens these ports to every address by default when -OpenPorts is not given."
			}
			if len(ports) > 0 {
				s.g.Expose(id, "", false)
				risk.OpenPorts(s.g, id, ports, s.f.Path, l.n)
				if why != "" {
					add(model.Low, "Ports are opened without being named", why+" Give -OpenPorts with only the ports you need, and allow them only from your own address.")
				}
			}
		case "networksecuritygroup":
			if v, ok := psParam(args, "SecurityRules"); ok {
				for _, r := range psVarRef.FindAllStringSubmatch(v, -1) {
					if rule, ok := rules[strings.ToLower(r[1])]; ok {
						s.g.Expose(id, "", false)
						risk.OpenPorts(s.g, id, rule.ports, s.f.Path, rule.line)
						delete(rules, strings.ToLower(r[1]))
					}
				}
			}
		case "storageaccount":
			if v, _ := psParam(args, "AllowBlobPublicAccess"); psTrue(v) {
				s.g.Expose(id, "public read", true)
				add(model.High, "Files can be made public", "-AllowBlobPublicAccess $true lets containers in this account be opened to anyone on the internet. Leave it out, or use $false.")
			}
			if v, _ := psParam(args, "EnableHttpsTrafficOnly"); strings.EqualFold(v, "$false") {
				add(model.Medium, "Unencrypted traffic is allowed", "-EnableHttpsTrafficOnly $false lets data travel over plain HTTP. Leave it out (the default is $true).")
			}
			if v, _ := psParam(args, "MinimumTlsVersion"); v == "TLS1_0" || v == "TLS1_1" {
				add(model.Medium, "Old TLS version allowed", "-MinimumTlsVersion "+v+" allows encryption that is no longer considered safe. Use TLS1_2.")
			}
			s.psNetwork(args, add)
		case "storagecontainer":
			if v, _ := psParam(args, "Permission"); strings.EqualFold(v, "Blob") || strings.EqualFold(v, "Container") {
				s.g.Expose(id, "public read", true)
				add(model.High, "Files are public", "-Permission "+v+" lets anyone on the internet read the files in this container. Use -Permission Off.")
			}
		case "keyvault":
			if !psSwitch(args, "EnablePurgeProtection") {
				add(model.Low, "Deleted secrets can be lost for good", "Without purge protection, a deleted key vault or secret can be purged at once, by mistake or by an attacker. Add -EnablePurgeProtection.")
			}
			s.psNetwork(args, add)
		case "containerregistry":
			if psSwitch(args, "EnableAdminUser") {
				add(model.Medium, "Registry admin account is on", "-EnableAdminUser gives the registry one shared user name and password with full push and pull rights. Leave it out and use Microsoft Entra identities or tokens.")
			}
			s.psNetwork(args, add)
		case "cosmosdbaccount":
			if _, ok := psParam(args, "IpRule"); !ok {
				s.psNetwork(args, add)
			}
		case "rediscache":
			if v, _ := psParam(args, "EnableNonSslPort"); psTrue(v) {
				add(model.Medium, "Unencrypted traffic is allowed", "-EnableNonSslPort opens Redis on port 6379 without encryption. Leave it out and connect on the TLS port.")
			}
		case "webapp", "functionapp":
			if !httpsLater {
				add(model.Low, "No HTTPS", "The app also answers on plain HTTP, because HTTPS-only is off by default. Run Set-AzWebApp -HttpsOnly $true after creating it.")
			}
		case "akscluster":
			if _, ok := psParam(args, "ApiServerAccessAuthorizedIpRange"); !ok && !psSwitch(args, "EnableApiServerAccessPrivateCluster") {
				add(model.Low, "Kubernetes API is reachable from the internet", "The cluster's API answers on a public address for everyone. Add -ApiServerAccessAuthorizedIpRange with your own addresses, or make it a private cluster.")
			}
		case "roleassignment":
			if v, _ := psParam(args, "RoleDefinitionName"); broadPSRole(resolve(v)) {
				add(model.High, "Full control in Azure is handed out", fmt.Sprintf("This gives the %s role, which can change or delete everything in its scope. Give a narrower built-in role, such as Reader or a service-specific role, at the smallest scope that works.", resolve(v)))
			}
		}
	}
	// NSG rules never put in a group of their own still open the ports.
	for _, r := range rules {
		risk.OpenPorts(s.g, s.me, r.ports, s.f.Path, r.line)
	}
}

func broadPSRole(role string) bool {
	switch strings.ToLower(role) {
	case "owner", "contributor", "user access administrator":
		return true
	}
	return false
}

// psOpenRule reads New-AzNetworkSecurityRuleConfig: an inbound allow rule
// from every address returns its ports.
func psOpenRule(args string) ([]string, bool) {
	access, _ := psParam(args, "Access")
	direction, _ := psParam(args, "Direction")
	if !strings.EqualFold(access, "Allow") || !strings.EqualFold(direction, "Inbound") {
		return nil, false
	}
	src, _ := psParam(args, "SourceAddressPrefix")
	if !risk.FromAnywhere(psList(src)) {
		return nil, false
	}
	ports, _ := psParam(args, "DestinationPortRange")
	list := psList(ports)
	if len(list) == 0 || strings.HasPrefix(ports, "$") {
		list = []string{"?"}
	}
	return list, true
}

// psNetwork reports a service open to every network unless public access
// is off or a network rule set narrows it down.
func (s *scan) psNetwork(args string, add func(model.Severity, string, string)) {
	if v, _ := psParam(args, "PublicNetworkAccess"); strings.EqualFold(v, "Disabled") {
		return
	}
	if _, ok := psParam(args, "NetworkRuleSet"); ok {
		return
	}
	if v, _ := psParam(args, "NetworkRuleSetDefaultAction"); strings.EqualFold(v, "Deny") {
		return
	}
	add(model.Low, "Open to every network", "The service answers on its public address to every network; only its login or keys protect it. Add -PublicNetworkAccess Disabled and a private endpoint, or a network rule set that denies by default.")
}
