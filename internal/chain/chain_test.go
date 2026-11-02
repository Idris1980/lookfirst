package chain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/analyze"
)

func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// flat lists every step as "num says", all the way down.
func flat(items []Item) []string {
	var out []string
	for _, it := range items {
		n := it.Num
		if it.Skipped {
			n = "-"
		}
		out = append(out, n+" "+it.Says)
		out = append(out, flat(it.Sub)...)
	}
	return out
}

func build(t *testing.T, dir string) []Chain {
	t.Helper()
	projects, err := analyze.Paths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	return Build(analyze.Merge(projects))
}

func expect(t *testing.T, got []string, want ...string) {
	t.Helper()
	i := 0
	for _, g := range got {
		if i < len(want) && strings.HasPrefix(g, want[i]) {
			i++
		}
	}
	if i < len(want) {
		t.Errorf("missing, in this order, %q\ngot:\n%s", want[i], strings.Join(got, "\n"))
	}
}

// A script that builds a template, uploads code to the app the template
// made, builds an image, and runs the template again with a part that is
// only built the second time; and a script that tears it all down.
func TestScriptTemplateCodeChain(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"deploy.ps1": `$rg = "rg-demo"
$mall = Join-Path $PSScriptRoot "templates" "main.json"
az group create --name $rg --location swedencentral
az deployment group create --resource-group $rg --template-file $mall --output none
$out = az deployment group show --resource-group $rg --name main --query properties.outputs -o json | ConvertFrom-Json
Push-Location (Join-Path $PSScriptRoot "app")
func azure functionapp publish $out.appName.value --python
Pop-Location
az acr build --registry $out.registry.value --image web:1 (Join-Path $PSScriptRoot "web")
az deployment group create --resource-group $rg --template-file $mall --parameters withWeb=true
`,
		"destroy.ps1": "az group delete --name rg-demo --yes\n",
		"templates/main.json": `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "parameters": {"withWeb": {"type": "bool", "defaultValue": false}},
  "variables": {"app": "func-demo", "acr": "acrdemo"},
  "resources": [
    {"type": "Microsoft.Web/serverfarms", "name": "plan-demo", "properties": {}},
    {"type": "Microsoft.Web/sites", "name": "[variables('app')]", "kind": "functionapp",
     "properties": {"httpsOnly": true, "serverFarmId": "[resourceId('Microsoft.Web/serverfarms', 'plan-demo')]"}},
    {"type": "Microsoft.ContainerRegistry/registries", "name": "[variables('acr')]", "properties": {}},
    {"type": "Microsoft.ContainerInstance/containerGroups", "name": "web", "condition": "[parameters('withWeb')]",
     "properties": {"ipAddress": {"type": "Public", "ports": [{"port": 80}]}}}
  ],
  "outputs": {"appName": {"type": "string", "value": "[variables('app')]"}, "registry": {"type": "string", "value": "[variables('acr')]"}}
}`,
		"app/function_app.py": "import azure.functions as func\napp = func.FunctionApp()\n",
		"web/Dockerfile":      "FROM nginx:1.27\nUSER nginx\n",
	})
	chains := build(t, dir)
	if len(chains) != 2 || !strings.Contains(chains[0].Title, "deploy.ps1") || !strings.Contains(chains[1].Title, "destroy.ps1") {
		t.Fatalf("want deploy.ps1 first, then destroy.ps1: %+v", chains)
	}
	got := flat(chains[0].Items)
	expect(t, got,
		"1 Creates the resource group rg-demo",
		"2 Hands the template templates/main.json to Azure",
		"2.1 Creates the App Service plan plan-demo",
		"2.2 Creates the function app func-demo",
		"2.3 Creates the container registry acrdemo",
		"- Creates the container group web",
		"3 Uploads the code in app/ to the function app func-demo",
		"4 Builds the container image web:1 from web",
		"5 Hands the template templates/main.json to Azure to build, with withWeb=true",
		"5.1 Creates the container group web",
		"5.2 Updates the 3 things",
	)
	// The step that opens the container to the internet says so.
	found := false
	var walk func(items []Item)
	walk = func(items []Item) {
		for _, it := range items {
			if it.Num == "5.1" {
				for _, r := range it.Risks {
					found = found || strings.Contains(r.Title, "port 80")
				}
			}
			walk(it.Sub)
		}
	}
	walk(chains[0].Items)
	if !found {
		t.Error("step 5.1 should carry the risk of port 80 open to the internet")
	}
	expect(t, flat(chains[1].Items), "1 Deletes the resource group rg-demo and everything in it")
}

// A setup script of the kind an AI assistant writes for a new server.
func TestMachineSetupChain(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"setup.sh": `#!/bin/bash
set -e
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y git nginx
curl -fsSL https://example.com/install.sh | sudo bash
sudo useradd -m deploy
sudo usermod -aG docker deploy
sudo ufw allow 22
sudo systemctl enable --now nginx
docker compose up -d
`,
		"docker-compose.yml": "services:\n  web:\n    image: nginx:1.27\n    ports:\n      - \"8080:80\"\n",
	})
	chains := build(t, dir)
	if len(chains) == 0 {
		t.Fatal("no chain")
	}
	expect(t, flat(chains[0].Items),
		"1 Updates every installed package",
		"2 Installs git, nginx on the machine",
		"3 Downloads https://example.com/install.sh and runs it straight away",
		"4 Creates the user deploy",
		"5 Adds deploy to the group docker, which gives it full control",
		"6 Opens 22 in the machine's firewall",
		"7 Starts the service nginx and makes it start every time",
		"8 Starts the containers described in docker-compose.yml",
		"8.1 Starts the container web from the image nginx:1.27",
	)
	for _, c := range chains[1:] {
		if strings.Contains(c.Title, "docker-compose") {
			t.Errorf("the compose file is started by setup.sh, so it needs no chain of its own: %v", c.Title)
		}
	}
}

// Infrastructure code no script deploys gets a chain of its own, in the
// order the cloud must build it.
func TestTemplateOnItsOwn(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"main.tf": `resource "aws_instance" "web" {
  ami           = "ami-123"
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.a.id
}
resource "aws_subnet" "a" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
`,
	})
	chains := build(t, dir)
	if len(chains) != 1 || !strings.Contains(chains[0].Title, "terraform apply") {
		t.Fatalf("chains: %+v", chains)
	}
	expect(t, flat(chains[0].Items), "1 Creates the VPC main", "2 Creates the subnet a", "3 Creates the EC2 instance web")
}

// A function in the script runs where it is called, with the values it
// is called with, as in Publish $out.appName.value "$PSScriptRoot\app".
func TestScriptFunctions(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"deploy.ps1": `function Publish-App($appName, $folder) {
    Push-Location $folder
    func azure functionapp publish $appName --python
    Pop-Location
}
az group create --name rg-demo --location swedencentral
Publish-App "func-one" "$PSScriptRoot\one"
Publish-App "func-two" "$PSScriptRoot\two"
`,
	})
	got := flat(build(t, dir)[0].Items)
	expect(t, got,
		"1 Creates the resource group rg-demo",
		"2 Uploads the code in one/ to the function app func-one (in Publish-App)",
		"3 Uploads the code in two/ to the function app func-two (in Publish-App)",
	)
	if len(got) != 3 {
		t.Errorf("the function's own lines are not steps where it is defined: %q", got)
	}
}
