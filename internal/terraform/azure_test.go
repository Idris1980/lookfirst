package terraform

import (
	"testing"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/source"
)

func TestAzureRules(t *testing.T) {
	tf := `
resource "azurerm_linux_web_app" "plain" {
  https_only = false
  site_config {
    minimum_tls_version      = "1.0"
    ftps_state               = "AllAllowed"
    remote_debugging_enabled = true
  }
}
resource "azurerm_linux_web_app" "unset" {
  site_config {}
}
resource "azurerm_linux_web_app" "good" {
  https_only = true
  site_config { ftps_state = "Disabled" }
}

resource "azurerm_key_vault" "kv" { purge_protection_enabled = false }
resource "azurerm_key_vault" "private" {
  purge_protection_enabled      = true
  public_network_access_enabled = false
}

resource "azurerm_storage_account" "open" {}
resource "azurerm_storage_account" "ruled" {}
resource "azurerm_storage_account_network_rules" "ruled" {
  storage_account_id = azurerm_storage_account.ruled.id
  default_action     = "Deny"
}

resource "azurerm_container_registry" "acr" { admin_enabled = true }
resource "azurerm_kubernetes_cluster" "aks" { role_based_access_control_enabled = false }
resource "azurerm_kubernetes_cluster" "limited" {
  api_server_access_profile { authorized_ip_ranges = ["203.0.113.10/32"] }
}
resource "azurerm_role_assignment" "owner" { role_definition_name = "Owner" }
resource "azurerm_role_assignment" "reader" { role_definition_name = "Reader" }
`
	g := Read([]source.File{{Path: "main.tf", Kind: source.Terraform, Data: []byte(tf)}})
	got := map[string]map[string]model.Severity{}
	for _, f := range g.Findings {
		if got[f.Title] == nil {
			got[f.Title] = map[string]model.Severity{}
		}
		got[f.Title][f.NodeID] = f.Severity
	}
	want := []struct {
		title, node string
		sev         model.Severity
	}{
		{"No HTTPS", "azurerm_linux_web_app.plain", model.Medium},
		{"No HTTPS", "azurerm_linux_web_app.unset", model.Low},
		{"Old TLS version allowed", "azurerm_linux_web_app.plain", model.Medium},
		{"Files can be uploaded over unencrypted FTP", "azurerm_linux_web_app.plain", model.Medium},
		{"Remote debugging is on", "azurerm_linux_web_app.plain", model.Medium},
		{"Deleted secrets can be lost for good", "azurerm_key_vault.kv", model.Low},
		{"Open to every network", "azurerm_storage_account.open", model.Low},
		{"Registry admin account is on", "azurerm_container_registry.acr", model.Medium},
		{"Kubernetes access control is off", "azurerm_kubernetes_cluster.aks", model.High},
		{"Kubernetes API is reachable from the internet", "azurerm_kubernetes_cluster.aks", model.Low},
		{"Full control in Azure is handed out", "azurerm_role_assignment.owner", model.High},
	}
	for _, w := range want {
		if sev, ok := got[w.title][w.node]; !ok || sev != w.sev {
			t.Errorf("%q on %s: got %v (found %v), want %v", w.title, w.node, sev, ok, w.sev)
		}
	}
	for title, node := range map[string]string{
		"No HTTPS":                                      "azurerm_linux_web_app.good",
		"Open to every network":                         "azurerm_storage_account.ruled",
		"Deleted secrets can be lost for good":          "azurerm_key_vault.private",
		"Full control in Azure is handed out":           "azurerm_role_assignment.reader",
		"Kubernetes API is reachable from the internet": "azurerm_kubernetes_cluster.limited",
	} {
		if _, ok := got[title][node]; ok {
			t.Errorf("false alarm %q on %s", title, node)
		}
	}
	if _, ok := got["Open to every network"]["azurerm_key_vault.private"]; ok {
		t.Error("a key vault with public access off is not open to every network")
	}
}
