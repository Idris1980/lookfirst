package chain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/analyze"
	"github.com/Idris1980/lookfirst/internal/explain"
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
		if it.Skipped || it.Existing {
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

// A teardown loop, a stack whose database goes without a copy, a server's
// user data, a backup from /tmp on the server and the metadata service:
// each was once said wrong, or not at all.
func TestStacksLoopsAndUserData(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"deploy.ps1": `param([string]$Prefix = "shop")
aws cloudformation deploy --template-file data.yaml --stack-name "$Prefix-data"
aws cloudformation deploy --template-file web.yaml --stack-name "$Prefix-web"
`,
		"destroy.ps1": `param([string]$Prefix = "shop")
foreach ($Layer in "web", "data") {
    $Stack = "$Prefix-$Layer"
    aws cloudformation delete-stack --stack-name $Stack
    aws cloudformation wait stack-delete-complete --stack-name $Stack
}
`,
		"backup.sh": `#!/bin/bash
DUMP="/tmp/db.sql"
aws s3 cp "$DUMP" "s3://shop-backup/"
`,
		"restore.sh": `#!/bin/bash
TOKEN=$(curl -sS -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
IP=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)
`,
		"data.yaml": `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Files:
    Type: AWS::EFS::FileSystem
    Properties:
      Encrypted: true
  Db:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      Engine: mysql
      DBInstanceClass: db.t3.micro
      AllocatedStorage: "20"
      StorageEncrypted: true
`,
		"web.yaml": `AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Ami:
    Type: AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>
    Default: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
Resources:
  Web:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Ref Ami
      InstanceType: t3.micro
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          dnf install -y httpd
          curl -sSLo /tmp/app.tgz https://example.com/app.tgz
          systemctl enable --now httpd php-fpm
`,
	})
	chains := build(t, dir)
	byTitle := map[string][]string{}
	for _, c := range chains {
		byTitle[c.Title] = flat(c.Items)
	}
	expect(t, byTitle["When deploy.ps1 is run"],
		"2 Hands the template web.yaml to AWS to build",
		"2.1 Creates the EC2 server Web",
		"2.1.1 When it starts, installs httpd",
		"2.1.2 When it starts, downloads https://example.com/app.tgz",
		"2.1.3 When it starts, starts the services httpd and php-fpm and makes them start every time",
	)
	expect(t, byTitle["When destroy.ps1 is run"],
		"1 Deletes the CloudFormation stack shop-web and everything it built",
		"1.1 Deletes the EC2 server Web",
		"2 Deletes the CloudFormation stack shop-data and everything it built",
		"2.1 Deletes the RDS database Db and all the data in it. No copy is kept",
		"2.2 Deletes the EFS file system Files and all the data in it",
	)
	expect(t, byTitle["When backup.sh is run"], "1 Copies /tmp/db.sql to s3://shop-backup/")
	expect(t, byTitle["When restore.sh is run"],
		"1 Asks the cloud server's own metadata service for latest/api/token",
		"2 Asks the cloud server's own metadata service for latest/meta-data/public-ipv4")
	for _, lines := range byTitle {
		for _, l := range lines {
			if strings.Contains(l, "$Layer") || strings.Contains(l, "CLOUDFORMATION") || strings.Contains(l, "public-ipv4)") || strings.Contains(l, "on the internet example.com") {
				t.Errorf("said wrong: %q", l)
			}
		}
	}

	projects, err := analyze.Paths([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	g := analyze.Merge(projects)
	titles := map[string]bool{}
	for _, f := range g.Findings {
		titles[f.Title] = true
	}
	for _, want := range []string{"Database is deleted without a final copy"} {
		if !titles[want] {
			t.Errorf("missing finding %q", want)
		}
	}
	// Amazon Linux 2023 requires IMDSv2; the metadata service is not the internet; a server starting its services is normal.
	for _, not := range []string{"Unencrypted connection", "Old metadata service may be on", "Makes something start automatically", "Syntax error"} {
		if titles[not] {
			t.Errorf("finding %q should not be there", not)
		}
	}
	summary := strings.Join(explain.Summary(g), " ")
	for _, want := range []string{"on the internet: example.com", "own metadata service (169.254.169.254)"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary misses %q:\n%s", want, summary)
		}
	}
	if strings.Contains(summary, "169.254.169.254 and") || strings.Contains(summary, "169.254.169.254.") && strings.Contains(summary, "internet: 169") {
		t.Errorf("the metadata service is counted as the internet:\n%s", summary)
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

// What the code expects to be there and does not create is said at the
// step that needs it; what an earlier script makes is said once.
func TestNeedsWhatExists(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"1-network.sh": "az group create --name rg-a --location swedencentral\naz network vnet create -g rg-a --name vnet-a --address-prefixes 10.0.0.0/16\n",
		"2-vm.sh":      "az vm create -g rg-a -n web --image Ubuntu2404 --vnet-name vnet-a --subnet snet-missing\n",
		"main.tf":      "data \"aws_vpc\" \"main\" {\n  id = \"vpc-123\"\n}\nresource \"aws_subnet\" \"a\" {\n  vpc_id     = data.aws_vpc.main.id\n  cidr_block = \"10.0.1.0/24\"\n}\n",
	})
	chains := build(t, dir)
	var vm, tf *Chain
	for i := range chains {
		switch {
		case strings.Contains(chains[i].Title, "2-vm.sh"):
			vm = &chains[i]
		case strings.Contains(chains[i].Title, "main.tf"):
			tf = &chains[i]
		}
	}
	if vm == nil || tf == nil {
		t.Fatalf("chains: %+v", chains)
	}
	step := vm.Items[0]
	if len(step.Needs) != 1 || !strings.Contains(step.Needs[0], "subnet snet-missing") {
		t.Errorf("the VM needs the subnet nothing creates: %q", step.Needs)
	}
	uses := strings.Join(step.Uses, "|")
	if !strings.Contains(uses, "resource group rg-a, made in step 1 of 1-network.sh") || !strings.Contains(uses, "virtual network vnet-a, made in step 2 of 1-network.sh") {
		t.Errorf("uses: %q", step.Uses)
	}
	expect(t, flat(tf.Items), "- Uses the existing VPC main", "1 Creates the subnet a")
	if !tf.Items[0].Existing {
		t.Error("a data source is used, not created")
	}
}

// A teardown script: names found with describe and kept in variables, inline
// policies, plain words for EC2 parts, and a database deleted with no copy.
func TestTeardownScript(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, map[string]string{
		"destroy.ps1": `$SgNamn = "shop-web-sg"
$Instanser = aws ec2 describe-instances --filters "Name=tag:Name,Values=shop-web" --query "Reservations[].Instances[].InstanceId" --output text
$Lista = $Instanser -split "\s+"
aws ec2 terminate-instances --instance-ids $Lista
$SgId = aws ec2 describe-security-groups --filters "Name=group-name,Values=$SgNamn" --query "SecurityGroups[0].GroupId" --output text
aws ec2 delete-security-group --group-id $SgId
aws iam delete-role-policy --role-name shop-app --policy-name read-files
aws iam delete-role-policy --role-name shop-app --policy-name write-backup
aws rds delete-db-instance --db-instance-identifier shop-db --skip-final-snapshot --delete-automated-backups
`,
	})
	chains := build(t, dir)
	if len(chains) == 0 {
		t.Fatal("no chain")
	}
	expect(t, flat(chains[0].Items),
		"1 Stops and deletes the EC2 server shop-web",
		"2 Deletes the security group shop-web-sg",
		"3 Deletes the policy read-files from the role shop-app",
		"4 Deletes the policy write-backup from the role shop-app",
		"5 Deletes the RDS database shop-db and all the data in it, with no final snapshot and without its automatic backups",
	)
	found := false
	for _, it := range chains[0].Items {
		for _, r := range it.Risks {
			found = found || r.Title == "Database is deleted without a final copy"
		}
	}
	if !found {
		t.Error("deleting the database with --skip-final-snapshot should carry the finding")
	}
}
