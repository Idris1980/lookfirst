package arm

import (
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/source"
)

// A web front in a container that calls a function app, which keeps its
// state and data in storage and sends telemetry; the front pulls its image
// with an identity that has AcrPull on the registry.
const flowTemplate = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "variables": {
    "stName": "stdata01",
    "funcName": "func-demo",
    "acrName": "acrdemo01",
    "funcId": "[resourceId('Microsoft.Web/sites', variables('funcName'))]",
    "acrPull": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')]"
  },
  "resources": [
    {"type": "Microsoft.Storage/storageAccounts", "name": "[variables('stName')]", "properties": {"publicNetworkAccess": "Disabled"}},
    {"type": "Microsoft.Storage/storageAccounts/blobServices/containers", "name": "[concat(variables('stName'), '/default/orders')]",
     "dependsOn": ["[resourceId('Microsoft.Storage/storageAccounts', variables('stName'))]"]},
    {"type": "Microsoft.Insights/components", "name": "appi-demo", "properties": {}},
    {"type": "Microsoft.Web/serverfarms", "name": "plan-demo", "properties": {}},
    {"type": "Microsoft.Web/sites", "name": "[variables('funcName')]", "kind": "functionapp,linux",
     "dependsOn": ["[resourceId('Microsoft.Web/serverfarms', 'plan-demo')]"],
     "properties": {
       "httpsOnly": true,
       "serverFarmId": "[resourceId('Microsoft.Web/serverfarms', 'plan-demo')]",
       "siteConfig": {"appSettings": [
         {"name": "AzureWebJobsStorage__accountName", "value": "[variables('stName')]"},
         {"name": "APPLICATIONINSIGHTS_CONNECTION_STRING", "value": "[reference(resourceId('Microsoft.Insights/components', 'appi-demo')).ConnectionString]"}
       ]}
     }},
    {"type": "Microsoft.ContainerRegistry/registries", "name": "[variables('acrName')]", "properties": {"publicNetworkAccess": "Disabled"}},
    {"type": "Microsoft.ManagedIdentity/userAssignedIdentities", "name": "id-web"},
    {"type": "Microsoft.Authorization/roleAssignments", "name": "[guid('pull')]",
     "scope": "[concat('Microsoft.ContainerRegistry/registries/', variables('acrName'))]",
     "properties": {
       "roleDefinitionId": "[variables('acrPull')]",
       "principalId": "[reference(resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', 'id-web')).principalId]"
     }},
    {"type": "Microsoft.ContainerInstance/containerGroups", "name": "web",
     "identity": {"type": "UserAssigned", "userAssignedIdentities": {"[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', 'id-web')]": {}}},
     "properties": {
       "containers": [{"name": "web", "properties": {
         "image": "[concat(variables('acrName'), '.azurecr.io/web:1')]",
         "environmentVariables": [{"name": "API_URL", "value": "[concat('https://', reference(variables('funcId')).defaultHostName)]"}]
       }}],
       "imageRegistryCredentials": [{"server": "[concat(variables('acrName'), '.azurecr.io')]",
         "identity": "[resourceId('Microsoft.ManagedIdentity/userAssignedIdentities', 'id-web')]"}],
       "ipAddress": {"type": "Public", "ports": [{"port": 80}]}
     }}
  ]
}`

func TestLinesSayWhatTheyMean(t *testing.T) {
	g := Read([]source.File{{Path: "main.json", Data: []byte(flowTemplate), Kind: source.ARM}})
	st := id("Microsoft.Storage/storageAccounts", "stdata01")
	fn := id("Microsoft.Web/sites", "func-demo")
	web := id("Microsoft.ContainerInstance/containerGroups", "web")
	ident := id("Microsoft.ManagedIdentity/userAssignedIdentities", "id-web")
	acr := id("Microsoft.ContainerRegistry/registries", "acrdemo01")

	want := []struct{ from, to, kind, label string }{
		{model.InternetID, web, model.Flow, "port 80"},
		{web, fn, model.Flow, "calls over HTTPS"},
		{web, acr, model.Flow, "pulls its image from"},
		{web, ident, model.Hosting, "signs in as"},
		{ident, acr, model.Access, "may pull images"},
		{fn, st, model.Flow, "keeps its state in"},
		{fn, id("Microsoft.Insights/components", "appi-demo"), model.Flow, "sends telemetry to"},
		{fn, id("Microsoft.Web/serverfarms", "plan-demo"), model.Hosting, "runs on"},
	}
	for _, w := range want {
		found := false
		for _, e := range g.Edges {
			if e.From == w.from && e.To == w.to {
				found = true
				if e.Kind != w.kind || !strings.Contains(e.Label, w.label) {
					t.Errorf("%s -> %s: got %s %q, want %s %q", w.from, w.to, e.Kind, e.Label, w.kind, w.label)
				}
			}
		}
		if !found {
			t.Errorf("no line %s -> %s (%s)", w.from, w.to, w.label)
		}
	}
	if !g.HasMeaning() {
		t.Error("the graph should know what its lines mean")
	}

	// The role assignment is the line above, and the blob container is
	// named inside its storage account; both stay in the graph.
	for _, n := range g.Nodes {
		switch strings.ToLower(n.Type) {
		case "microsoft.authorization/roleassignments", "microsoft.storage/storageaccounts/blobservices/containers":
			if !n.Hidden {
				t.Errorf("%s should be hidden in the picture", n.ID)
			}
		}
	}
	if n := g.Node(st); n == nil || !strings.Contains(n.Friendly, "orders") {
		t.Errorf("the storage account should name its container: %+v", n)
	}
	if n := g.Node(fn); n == nil || n.Friendly != "function app" {
		t.Errorf("a web app of kind functionapp is a function app: %+v", n)
	}
}
