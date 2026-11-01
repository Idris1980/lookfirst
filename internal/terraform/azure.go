package terraform

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/Idris1980/lookfirst/internal/model"
)

// publicByDefault are Azure services that answer on a public address to
// every network unless public access is switched off or narrowed down. SQL,
// PostgreSQL and MySQL are not here: their firewall lets nobody in until a
// rule is added, and those rules are checked on their own.
var publicByDefault = map[string]bool{
	"azurerm_storage_account":      true,
	"azurerm_key_vault":            true,
	"azurerm_cosmosdb_account":     true,
	"azurerm_container_registry":   true,
	"azurerm_redis_cache":          true,
	"azurerm_servicebus_namespace": true,
	"azurerm_eventhub_namespace":   true,
	"azurerm_cognitive_account":    true,
	"azurerm_search_service":       true,
}

// broadRoleNames are the built-in Azure roles that can change everything in
// their scope; broadRoleIDs the same by their fixed ids.
var broadRoleNames = map[string]bool{"Owner": true, "Contributor": true, "User Access Administrator": true}

var broadRoleIDs = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
}

// azureChecks holds the Azure rules beyond the network ones in check.
func azureChecks(c *config, g *model.Graph) {
	for _, r := range c.resources {
		me := r.id()
		add := func(sev model.Severity, title, detail string, body *hclsyntax.Body, attr string) {
			g.Add(sev, me, title, detail, r.file, line(body, attr, r.line))
		}

		switch r.typ {
		case "azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app",
			"azurerm_app_service", "azurerm_function_app":
			switch v, set := boolean(r.body, "https_only"); {
			case set && !v:
				add(model.Medium, "No HTTPS", "https_only = false lets the app answer on plain HTTP. Set https_only = true.", r.body, "https_only")
			case !set && r.body.Attributes["https_only"] == nil:
				add(model.Low, "No HTTPS", "https_only is not set, and Azure's default is to answer on plain HTTP too. Set https_only = true.", r.body, "https_only")
			}
			for _, b := range r.body.Blocks {
				if b.Type != "site_config" {
					continue
				}
				if v, _ := str(b.Body, "minimum_tls_version"); v == "1.0" || v == "1.1" {
					add(model.Medium, "Old TLS version allowed", fmt.Sprintf("minimum_tls_version = %q allows encryption that is no longer considered safe. Use 1.2 or newer.", v), b.Body, "minimum_tls_version")
				}
				if v, _ := str(b.Body, "ftps_state"); v == "AllAllowed" {
					add(model.Medium, "Files can be uploaded over unencrypted FTP", "ftps_state = \"AllAllowed\" lets anyone with the deployment password upload files over plain FTP. Use FtpsOnly, or Disabled.", b.Body, "ftps_state")
				}
				if v, set := boolean(b.Body, "remote_debugging_enabled"); set && v {
					add(model.Medium, "Remote debugging is on", "remote_debugging_enabled opens a debugging port on the app. Turn it off outside short debugging sessions.", b.Body, "remote_debugging_enabled")
				}
			}

		case "azurerm_key_vault":
			if v, set := boolean(r.body, "purge_protection_enabled"); !set || !v {
				add(model.Low, "Deleted secrets can be lost for good", "Without purge protection, a deleted key vault or secret can be purged at once, by mistake or by an attacker. Set purge_protection_enabled = true.", r.body, "purge_protection_enabled")
			}
		case "azurerm_container_registry":
			if v, set := boolean(r.body, "admin_enabled"); set && v {
				add(model.Medium, "Registry admin account is on", "admin_enabled gives the registry one shared user name and password with full push and pull rights. Turn it off and use Microsoft Entra identities or tokens.", r.body, "admin_enabled")
			}
		case "azurerm_redis_cache":
			for _, name := range []string{"non_ssl_port_enabled", "enable_non_ssl_port"} {
				if v, set := boolean(r.body, name); set && v {
					add(model.Medium, "Unencrypted traffic is allowed", name+" opens Redis on port 6379 without encryption. Set it to false and connect on the TLS port.", r.body, name)
				}
			}
		case "azurerm_kubernetes_cluster":
			private, _ := boolean(r.body, "private_cluster_enabled")
			limited := false
			for _, b := range r.body.Blocks {
				if b.Type == "api_server_access_profile" && len(strs(b.Body, "authorized_ip_ranges")) > 0 {
					limited = true
				}
			}
			if _, ok := r.body.Attributes["api_server_authorized_ip_ranges"]; ok {
				limited = true // older provider versions
			}
			if !private && !limited {
				add(model.Low, "Kubernetes API is reachable from the internet", "The cluster's API answers on a public address for everyone. Set api_server_access_profile.authorized_ip_ranges to your own addresses, or private_cluster_enabled = true.", r.body, "private_cluster_enabled")
			}
			if v, set := boolean(r.body, "role_based_access_control_enabled"); set && !v {
				add(model.High, "Kubernetes access control is off", "role_based_access_control_enabled = false means everyone who can log in to the cluster can do anything in it. Set it to true.", r.body, "role_based_access_control_enabled")
			}
		case "azurerm_role_assignment":
			role, _ := str(r.body, "role_definition_name")
			if id, ok := str(r.body, "role_definition_id"); ok {
				for guid, name := range broadRoleIDs {
					if strings.Contains(strings.ToLower(id), guid) {
						role = name
					}
				}
			}
			if broadRoleNames[role] {
				target := me
				if g.Node(me) == nil {
					target = ""
				}
				g.Add(model.High, target, "Full control in Azure is handed out", fmt.Sprintf("This gives the %s role, which can change or delete everything in its scope. Give a narrower built-in role, such as Reader or a service-specific role.", role), r.file, line(r.body, "role_definition_name", r.line))
			}
		case "azurerm_mssql_database":
			if v, set := boolean(r.body, "transparent_data_encryption_enabled"); set && !v {
				add(model.Medium, "Data is not encrypted", "transparent_data_encryption_enabled = false leaves the database files and backups unencrypted. Set it to true.", r.body, "transparent_data_encryption_enabled")
			}
		}

		if publicByDefault[r.typ] && openToEveryNetwork(c, r) {
			add(model.Low, "Open to every network", "The service answers on its public address to every network; only its login protects it. Restrict it with network rules (default_action = \"Deny\"), or set public_network_access_enabled = false and use a private endpoint.", r.body, "public_network_access_enabled")
		}
	}
}

// openToEveryNetwork is true unless public access is switched off, or a
// firewall, network rule set or private network narrows it down.
func openToEveryNetwork(c *config, r resource) bool {
	if v, set := boolean(r.body, "public_network_access_enabled"); set && !v {
		return false
	}
	for _, name := range []string{"ip_range_filter", "ip_rules", "allowed_ips", "delegated_subnet_id", "virtual_network_subnet_id"} {
		if _, ok := r.body.Attributes[name]; ok {
			return false
		}
	}
	if v, _ := boolean(r.body, "is_virtual_network_filter_enabled"); v {
		return false
	}
	for _, b := range r.body.Blocks {
		switch b.Type {
		case "network_rules", "network_acls", "network_rule_set":
			if a, _ := str(b.Body, "default_action"); a == "Deny" {
				return false
			}
		}
	}
	// A separate rules resource, such as azurerm_storage_account_network_rules.
	for _, other := range c.resources {
		if !strings.HasSuffix(other.typ, "_network_rules") {
			continue
		}
		for _, ref := range references(other.body) {
			if ref == r.id() {
				if a, _ := str(other.body, "default_action"); a == "Deny" {
					return false
				}
			}
		}
	}
	return true
}
