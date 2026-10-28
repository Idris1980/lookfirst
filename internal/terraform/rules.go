package terraform

import (
	"fmt"

	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
)

// check runs every rule and adds findings and internet lines to the graph.
func check(c *config, g *model.Graph) {
	add := g.Add

	for _, r := range c.resources {
		switch r.typ {
		case "azurerm_network_security_group":
			for _, b := range r.body.Blocks {
				if b.Type == "security_rule" {
					azureRule(g, r, b.Body, b.DefRange().Start.Line)
				}
			}
		case "azurerm_network_security_rule":
			azureRule(g, r, r.body, r.line)
		case "aws_security_group":
			for _, b := range r.body.Blocks {
				if b.Type == "ingress" {
					awsRule(g, r.id(), r.file, b.Body, b.DefRange().Start.Line, "cidr_blocks", "ipv6_cidr_blocks", "protocol")
				}
			}
		case "aws_vpc_security_group_ingress_rule":
			awsRule(g, r.id(), r.file, r.body, r.line, "cidr_ipv4", "cidr_ipv6", "ip_protocol")

		case "azurerm_public_ip", "aws_eip":
			g.Expose(r.id(), "", false)
			add(model.Low, r.id(), "Reachable from the internet",
				"This creates a public IP address. Whatever it is attached to can be reached from anywhere, so check which ports are open.", r.file, r.line)
		case "aws_instance":
			if v, set := boolean(r.body, "associate_public_ip_address"); set && v {
				g.Expose(r.id(), "", false)
				add(model.Low, r.id(), "Reachable from the internet",
					"This machine gets a public IP address. Check which ports its security group opens.", r.file, line(r.body, "associate_public_ip_address", r.line))
			}

		case "azurerm_linux_virtual_machine":
			if v, set := boolean(r.body, "disable_password_authentication"); set && !v {
				add(model.Medium, r.id(), "Password login is allowed",
					"Passwords can be guessed. Use SSH keys only by setting disable_password_authentication = true.", r.file, line(r.body, "disable_password_authentication", r.line))
			}

		case "tls_private_key":
			add(model.Medium, r.id(), "Private key is saved in the Terraform state",
				"Terraform stores this private key unencrypted in its state file (terraform.tfstate), and sensitive = true does not change that. Anyone who can read the state can log in with it. Create the key yourself, for example with ssh-keygen, and give Terraform only the public key.", r.file, r.line)

		case "azurerm_storage_account":
			if v, set := boolean(r.body, "allow_nested_items_to_be_public"); set && v {
				add(model.High, r.id(), "Files can be made public",
					"Containers in this storage account may allow anyone on the internet to read the files. Set allow_nested_items_to_be_public = false.", r.file, line(r.body, "allow_nested_items_to_be_public", r.line))
			}
			if v, set := boolean(r.body, "https_traffic_only_enabled"); set && !v {
				add(model.Medium, r.id(), "Unencrypted traffic is allowed",
					"Data can travel over plain HTTP, where it can be read on the way. Set https_traffic_only_enabled = true.", r.file, line(r.body, "https_traffic_only_enabled", r.line))
			}
		case "azurerm_storage_container":
			if t, _ := str(r.body, "container_access_type"); t == "blob" || t == "container" {
				g.Expose(r.id(), "public read", true)
				add(model.High, r.id(), "Files are public",
					"Anyone on the internet can read the files in this container without logging in. Use container_access_type = \"private\".", r.file, line(r.body, "container_access_type", r.line))
			}
		case "aws_s3_bucket_acl":
			if acl, _ := str(r.body, "acl"); strings.HasPrefix(acl, "public-") {
				add(model.High, r.id(), "Bucket is public",
					fmt.Sprintf("The ACL %q lets anyone on the internet access this bucket. Use \"private\".", acl), r.file, line(r.body, "acl", r.line))
			}
		case "aws_s3_bucket_public_access_block":
			for _, name := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if v, set := boolean(r.body, name); set && !v {
					add(model.Medium, r.id(), "Public access is not blocked",
						fmt.Sprintf("%s is false, so the bucket can be made public by mistake. Set all four settings to true.", name), r.file, line(r.body, name, r.line))
					break
				}
			}

		case "azurerm_mssql_firewall_rule", "azurerm_postgresql_flexible_server_firewall_rule", "azurerm_mysql_flexible_server_firewall_rule":
			start, _ := str(r.body, "start_ip_address")
			end, _ := str(r.body, "end_ip_address")
			switch {
			case start == "0.0.0.0" && end == "255.255.255.255":
				g.Expose(r.id(), "all addresses", true)
				add(model.High, r.id(), "Database open to the whole internet",
					"This firewall rule lets every IP address in the world try to connect to the database. Allow only the addresses that need it, or use a private endpoint.", r.file, r.line)
			case start == "0.0.0.0" && end == "0.0.0.0":
				add(model.Medium, r.id(), "Database open to all of Azure",
					"This rule allows every Azure service to connect, including services owned by other customers. Prefer a private endpoint.", r.file, r.line)
			}
		case "aws_db_instance":
			if v, set := boolean(r.body, "publicly_accessible"); set && v {
				g.Expose(r.id(), "public endpoint", true)
				add(model.High, r.id(), "Database reachable from the internet",
					"publicly_accessible = true gives the database a public address. Keep it false and connect from inside the VPC.", r.file, line(r.body, "publicly_accessible", r.line))
			}
		}

		for _, name := range []string{"min_tls_version", "minimum_tls_version"} {
			if v, ok := str(r.body, name); ok && (strings.Contains(v, "1_0") || strings.Contains(v, "1_1") || v == "1.0" || v == "1.1") {
				add(model.Medium, r.id(), "Old TLS version allowed",
					fmt.Sprintf("%s = %q allows encryption that is no longer considered safe. Use TLS 1.2 or newer.", name, v), r.file, line(r.body, name, r.line))
			}
		}
	}

	awsChecks(c, g)
	secrets(c, g)
}

func azureRule(g *model.Graph, r resource, body *hclsyntax.Body, fallback int) {
	dir, _ := str(body, "direction")
	access, _ := str(body, "access")
	if !strings.EqualFold(dir, "Inbound") || !strings.EqualFold(access, "Allow") {
		return
	}
	if !risk.FromAnywhere(strs(body, "source_address_prefix", "source_address_prefixes")) {
		return
	}
	ports := strs(body, "destination_port_range", "destination_port_ranges")
	if len(ports) == 0 {
		ports = []string{"?"}
	}
	risk.OpenPorts(g, r.id(), ports, r.file, line(body, "source_address_prefix", fallback))
}

func awsRule(g *model.Graph, node, file string, body *hclsyntax.Body, fallback int, v4, v6, proto string) {
	if !risk.FromAnywhere(strs(body, v4, v6)) {
		return
	}
	var spec string
	from, _ := str(body, "from_port")
	to, _ := str(body, "to_port")
	switch p, _ := str(body, proto); {
	case p == "-1" || p == "all":
		spec = "*"
	case from == "" && to == "":
		spec = "?"
	case from == to:
		spec = from
	default:
		spec = from + "-" + to
	}
	risk.OpenPorts(g, node, []string{spec}, file, line(body, v4, fallback))
}

// secrets looks for passwords and keys written straight into the code.
func secrets(c *config, g *model.Graph) {
	const fix = "use a variable marked sensitive = true, filled from a key vault or an environment variable"
	scan := func(nodeID string, body *hclsyntax.Body, file string) {
		walk(body, func(a *hclsyntax.Attribute) {
			v, ok := literal(a.Expr)
			if !ok || v.Type() != cty.String {
				return
			}
			risk.CheckSecret(g, nodeID, a.Name, v.AsString(), file, a.SrcRange.Start.Line, fix)
		})
	}

	for _, r := range c.resources {
		scan(r.id(), r.body, r.file)
	}
	for _, r := range c.providers {
		scan("", r.body, r.file)
	}
	for _, r := range c.locals {
		scan("", r.body, r.file)
	}
	for _, v := range c.variables {
		if !risk.SecretName(v.name) {
			continue
		}
		if d, ok := str(v.body, "default"); ok && !risk.Placeholder(d) {
			g.Add(model.High, "", "Password has a default value in the code",
				fmt.Sprintf("The variable %q has its value written in the file. Remove the default and pass the value in when you run Terraform, for example from a key vault.", v.name), v.file, line(v.body, "default", v.line))
		}
	}
}
