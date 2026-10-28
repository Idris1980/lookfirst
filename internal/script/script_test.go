package script

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/source"
)

func TestPipInstallArgs(t *testing.T) {
	cases := map[string][]string{
		"requests flask==3.0":                       {"requests", "flask"},
		"-r requirements.txt":                       nil,
		"--upgrade pip -r reqs/dev.txt numpy>=1.26": {"pip", "numpy"},
		"-e . pandas[excel]":                        {"pandas"},
		"--index-url https://example.com/simple x":  {"x"},
		"./local.whl":                               nil,
	}
	for in, want := range cases {
		if got := PipInstallArgs(in); !reflect.DeepEqual(got, want) {
			t.Errorf("PipInstallArgs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNpmInstallArgs(t *testing.T) {
	cases := []struct {
		in   string
		npx  bool
		want []string
	}{
		{"express axios@1.7.0 --save", false, []string{"express", "axios"}},
		{"-D @types/node@20", false, []string{"@types/node"}},
		{"--yes @vscode/vsce@3.6.0 package --target win32-x64", true, []string{"@vscode/vsce"}},
		{"create-react-app my-app", true, []string{"create-react-app"}},
		{"./local-folder", false, nil},
	}
	for _, c := range cases {
		if got := NpmInstallArgs(c.in, c.npx); !reflect.DeepEqual(got, c.want) {
			t.Errorf("NpmInstallArgs(%q, %v) = %q, want %q", c.in, c.npx, got, c.want)
		}
	}
}

func TestLookalike(t *testing.T) {
	for name, want := range map[string]string{"reqeusts": "requests", "axois": "axios", "expresss": "express", "beautifulsup4": "beautifulsoup4"} {
		got, ok := lookalike(name, map[string]bool{want: true})
		if !ok || got != want {
			t.Errorf("lookalike(%q) = %q, %v; want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"requests", "python_dateutil", "flask-cors", "abc"} {
		if like, ok := lookalike(name, pythonPopular); ok {
			t.Errorf("lookalike(%q) = %q, want no match", name, like)
		}
	}
}

// An install script as AI assistants write it: every risk is on its own line.
func TestInstallScript(t *testing.T) {
	sh := `#!/bin/bash
sudo apt-get update && sudo apt-get upgrade -y
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
rm get-docker.sh
sudo usermod -aG docker $USER
`
	g := Read([]source.File{{Path: "setup.sh", Kind: source.Shell, Data: []byte(sh)}})
	got := map[string][]int{}
	for _, f := range g.Findings {
		got[f.Title] = append(got[f.Title], f.Line)
	}
	want := map[string][]int{
		"Downloads code and runs it":                    {3, 5},
		"User can take over the machine through Docker": {7},
		"Runs with admin rights":                        {2},
	}
	for title, lines := range want {
		if !reflect.DeepEqual(got[title], lines) {
			t.Errorf("%q on lines %v, want %v", title, got[title], lines)
		}
	}
	for _, p := range []string{"bash", "sh", "apt-get", "usermod"} {
		if g.Node("program."+p) == nil {
			t.Errorf("the picture is missing the program %q", p)
		}
	}
	if g.Node("program.-E") != nil {
		t.Error(`sudo's option -E was taken for a program`)
	}

	// The same download split over two lines, and autostart set up on three.
	split := "curl -fsSL https://deb.nodesource.com/setup_22.x \\\n  -o /tmp/nodesource_setup.sh\nbash /tmp/nodesource_setup.sh\n" +
		"systemctl enable --now docker\ncat > /etc/systemd/system/app.service <<EOF\nEOF\nsystemctl enable --now app.service\n"
	g = Read([]source.File{{Path: "b.sh", Kind: source.Shell, Data: []byte(split)}})
	got = map[string][]int{}
	for _, f := range g.Findings {
		got[f.Title] = append(got[f.Title], f.Line)
	}
	if !reflect.DeepEqual(got["Downloads code and runs it"], []int{3}) {
		t.Errorf("download split over two lines: %v, want [3]", got["Downloads code and runs it"])
	}
	if n := len(got["Makes something start automatically"]); n != 1 {
		t.Errorf("autostart reported %d times, want once", n)
	}

	// The shebang alone does not run bash.
	g = Read([]source.File{{Path: "a.sh", Kind: source.Shell, Data: []byte("#!/bin/bash\necho hi\n")}})
	if g.Node("program.bash") != nil {
		t.Error("the shebang was taken for running bash")
	}
}

// An Azure CLI script: what it builds is drawn, and az's defaults are checked
// even when a command is split over several lines.
func TestAzureCLI(t *testing.T) {
	ps := "az storage account create --name $storageName --resource-group $rg\n" +
		"az vm create --resource-group $rg --name \"TestVM\" `\n" +
		"  --image Ubuntu2204 --generate-ssh-keys\n" +
		"az vm create -g $rg -n Quiet --image Ubuntu2204 --nsg-rule NONE\n" +
		"az vm create -g $rg -n Win --image Win2022Datacenter --nsg-rule RDP\n" +
		"az postgres flexible-server create -g $rg --name $dbName --public-access all\n" +
		"az sql server firewall-rule create -g $rg -s sql1 -n azure --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0\n"
	g := Read([]source.File{{Path: "env.ps1", Kind: source.PowerShell, Data: []byte(ps)}})
	got := map[string][]int{}
	for _, f := range g.Findings {
		got[f.Title] = append(got[f.Title], f.Line)
	}
	want := map[string][]int{
		"SSH (port 22) is open to the internet":                    {2},
		"Remote Desktop (RDP) (port 3389) is open to the internet": {5},
		"Database open to the whole internet":                      {6},
		"Database open to all of Azure":                            {7},
	}
	for title, lines := range want {
		if !reflect.DeepEqual(got[title], lines) {
			t.Errorf("%q on lines %v, want %v", title, got[title], lines)
		}
	}
	for _, id := range []string{"azure.storage.$storageName", "azure.vm.TestVM", "azure.vm.Quiet", "azure.database.$dbName"} {
		if g.Node(id) == nil {
			t.Errorf("the picture is missing %q", id)
		}
	}
}

// Lines that look risky but are not, from real installers.
func TestNotRisky(t *testing.T) {
	cases := []struct {
		code, title string
		want        bool
	}{
		{`echo -e "  Run: ${G}curl -fsSL https://x.example/i.sh | sudo bash -s -- -y${NC}"`, "Downloads code and runs it", false},
		{`echo "curl -fsSL https://x.example/i.sh | bash" | sh`, "Downloads code and runs it", true},
		{`rm -rf "${INSTALL_DIR}"`, "Can delete everything", false},
		{`rm -rf "$BUILD_DIR"/*`, "Can delete everything", true},
		{`if [ -f "$dst/tunica.env" ]; then continue; fi`, "Touches sensitive files", false},
		{`if [ -f ".env" ]; then source .env; fi`, "Touches sensitive files", true},
	}
	for _, c := range cases {
		g := Read([]source.File{{Path: "i.sh", Kind: source.Shell, Data: []byte(c.code + "\n")}})
		found := false
		for _, f := range g.Findings {
			found = found || f.Title == c.title
		}
		if found != c.want {
			t.Errorf("%q: %q found = %v, want %v", c.code, c.title, found, c.want)
		}
	}
}

// An AWS CLI script: what it builds is drawn and tied together through the
// variables holding the ids, and what it opens is checked.
func TestAWSCLI(t *testing.T) {
	ps := "$VpcId = aws ec2 create-vpc --cidr-block 10.0.0.0/16 --query Vpc.VpcId --output text\n" +
		"aws ec2 create-tags --resources $VpcId --tags Key=Name,Value=demo-vpc\n" +
		"$Sub = aws ec2 create-subnet --vpc-id $VpcId --cidr-block 10.0.1.0/24 --query Subnet.SubnetId --output text\n" +
		"$WebSg = aws ec2 create-security-group --group-name web-sg `\n" +
		"    --description \"web\" --vpc-id $VpcId --query GroupId --output text\n" +
		"aws ec2 authorize-security-group-ingress --group-id $WebSg --protocol tcp --port 80 --cidr 0.0.0.0/0\n" +
		"aws ec2 authorize-security-group-ingress --group-id $WebSg --protocol tcp --port 22 --cidr \"$MinIp/32\"\n" +
		"aws ec2 authorize-security-group-ingress --group-id $WebSg --ip-permissions IpProtocol=tcp,FromPort=3389,ToPort=3389,IpRanges=[{CidrIp=0.0.0.0/0}]\n" +
		"$Nacl = aws ec2 create-network-acl --vpc-id $VpcId --query NetworkAcl.NetworkAclId --output text\n" +
		"aws ec2 create-network-acl-entry --network-acl-id $Nacl --ingress --rule-number 130 --protocol tcp --port-range From=1024,To=65535 --cidr-block 0.0.0.0/0 --rule-action allow\n" +
		"$Web = aws ec2 run-instances --image-id ami-1 --subnet-id $Sub --security-group-ids $WebSg --associate-public-ip-address `\n" +
		"    --tag-specifications \"ResourceType=instance,Tags=[{Key=Name,Value=web}]\" --query Instances[0].InstanceId --output text\n" +
		"aws rds create-db-instance --db-instance-identifier shop-db --engine mysql --publicly-accessible --master-user-password Hunter2Hunter2\n" +
		"aws sqs create-queue --queue-name orders\n" +
		"aws iam attach-role-policy --role-name app --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n" +
		"aws lambda add-permission --function-name f --statement-id s --action lambda:InvokeFunction --principal '*'\n" +
		"Write-Host \"Done: http://$WebIp\"\n"
	g := Read([]source.File{{Path: "deploy.ps1", Kind: source.PowerShell, Data: []byte(ps)}})
	got := map[string][]int{}
	for _, f := range g.Findings {
		got[f.Title] = append(got[f.Title], f.Line)
	}
	want := map[string][]int{
		"Web traffic (port 80) is allowed from the internet":       {6},
		"Remote Desktop (RDP) (port 3389) is open to the internet": {8},
		"Reachable from the internet":                              {11},
		"Database reachable from the internet":                     {13},
		"Full control of the AWS account":                          {15},
		"Anyone can call the function":                             {16},
	}
	for title, lines := range want {
		if !reflect.DeepEqual(got[title], lines) {
			t.Errorf("%q on lines %v, want %v", title, got[title], lines)
		}
	}
	for _, title := range []string{"SSH (port 22) is open to the internet", "Unencrypted connection", "Every port is open to the internet"} {
		if got[title] != nil {
			t.Errorf("unexpected %q on lines %v", title, got[title])
		}
	}
	if len(got["Password or key written in the code"]) != 1 {
		t.Errorf("the RDS password was not found: %v", got)
	}
	for _, id := range []string{"aws.network.demo-vpc", "aws.subnet.$Sub", "aws.shield.web-sg", "aws.firewall.$Nacl", "aws.vm.web", "aws.database.shop-db", "aws.generic.orders"} {
		if g.Node(id) == nil {
			t.Errorf("the picture is missing %q", id)
		}
	}
	nacls := 0
	for _, n := range g.Nodes {
		if n.Kind == "firewall" {
			nacls++
		}
	}
	if nacls != 1 {
		t.Errorf("%d network ACLs drawn, want 1 (an entry is not an ACL)", nacls)
	}
}

// boto3: the same AWS rules as the command line, from Python calls that
// span several lines.
func TestBoto3(t *testing.T) {
	py := `import boto3, json
ec2 = boto3.client("ec2", region_name="eu-north-1")
rds = boto3.client('rds')
iam = boto3.client("iam")

vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
sg = ec2.create_security_group(GroupName="web-sg", Description="web", VpcId=vpc["Vpc"]["VpcId"])
ec2.authorize_security_group_ingress(
    GroupId=sg["GroupId"],
    IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
    ],
)
server = ec2.run_instances(ImageId="ami-1", MinCount=1, MaxCount=1,
    TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web"}]}])
rds.create_db_instance(DBInstanceIdentifier="shop", Engine="mysql", PubliclyAccessible=True)
iam.attach_role_policy(RoleName="app", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
iam.put_role_policy(RoleName="app", PolicyName="all",
    PolicyDocument=json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
`
	g := Read([]source.File{{Path: "setup.py", Kind: source.Python, Data: []byte(py)}})
	got := map[string][]int{}
	for _, f := range g.Findings {
		got[f.Title] = append(got[f.Title], f.Line)
	}
	want := map[string][]int{
		"SSH (port 22) is open to the internet": {8},
		"Database reachable from the internet":  {17},
		"Full control of the AWS account":       {18},
		"Permission to do everything":           {19},
	}
	for title, lines := range want {
		if !reflect.DeepEqual(got[title], lines) {
			t.Errorf("%q on lines %v, want %v (all: %v)", title, got[title], lines, got)
		}
	}
	for _, id := range []string{"aws.network.$vpc", "aws.shield.web-sg", "aws.vm.web", "aws.database.shop"} {
		if g.Node(id) == nil {
			t.Errorf("the picture is missing %q", id)
		}
	}
	linked := false
	for _, e := range g.Edges {
		linked = linked || (e.From == "aws.shield.web-sg" && e.To == "aws.network.$vpc")
	}
	if !linked {
		t.Errorf("no line from the security group to its VPC: %v", g.Edges)
	}
}

func TestKebab(t *testing.T) {
	for in, want := range map[string]string{"PubliclyAccessible": "publicly-accessible", "DBInstanceIdentifier": "db-instance-identifier", "CidrIp": "cidr-ip", "ACL": "acl"} {
		if got := kebab(in); got != want {
			t.Errorf("kebab(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripComments(t *testing.T) {
	cases := []struct {
		kind      source.Kind
		in        string
		keep, cut string
	}{
		{source.Python, "x = '#not a comment'  # real comment\n", "#not a comment", "real comment"},
		{source.Python, "s = \"\"\"doc # kept\"\"\"\n# gone\n", "doc # kept", "gone"},
		{source.JavaScript, "const u = 'http://x.com'; // gone\n/* gone too */ y()\n", "http://x.com", "gone"},
		{source.Shell, "echo \"a # b\" # gone\necho $#\n", "a # b", "gone"},
		{source.PowerShell, "<# gone\nstill gone #>\nWrite-Host 'x # kept'\n", "x # kept", "gone"},
	}
	for _, c := range cases {
		out := string(stripComments([]byte(c.in), c.kind))
		if !strings.Contains(out, c.keep) {
			t.Errorf("%s: %q lost %q: %q", c.kind, c.in, c.keep, out)
		}
		if strings.Contains(out, c.cut) {
			t.Errorf("%s: %q kept comment %q: %q", c.kind, c.in, c.cut, out)
		}
		if strings.Count(out, "\n") != strings.Count(c.in, "\n") {
			t.Errorf("%s: line count changed", c.kind)
		}
	}
}
