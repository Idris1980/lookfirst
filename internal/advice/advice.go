// Package advice explains each kind of finding to someone who has never
// heard of it: what could actually happen, how to fix it step by step, and
// where AWS and Microsoft say the same thing in their own security
// guidance (the AWS Foundational Security Best Practices controls in
// Security Hub, and the Microsoft cloud security benchmark).
package advice

import (
	"regexp"
	"strings"
)

// Ref is a link to official guidance.
type Ref struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// Advice is the full explanation of one kind of finding.
type Advice struct {
	Story string   // what could happen, in plain words
	Fix   []string // what to do, step by step
	AWS   []Ref    // AWS's own controls and guidance
	Azure []Ref    // Microsoft's own controls and guidance
	More  []Ref    // guidance that is not about one cloud
}

// For returns the advice for a finding title, and false when there is none.
func For(title string) (Advice, bool) {
	// "SSH (port 22) is open to the internet (only in AWS)" is explained
	// like the same finding in the code.
	if i := strings.Index(title, " (only in "); i > 0 {
		title = title[:i]
	}
	if a, ok := exact[title]; ok {
		return a, true
	}
	for _, p := range patterns {
		if p.re.MatchString(title) {
			return p.advice, true
		}
	}
	return Advice{}, false
}

// Refs returns the official references that fit the cloud a finding is
// about: "aws", "azure", or "" for both and the general ones.
func (a Advice) Refs(cloud string) []Ref {
	var out []Ref
	switch cloud {
	case "aws":
		out = append(out, a.AWS...)
	case "azure":
		out = append(out, a.Azure...)
	default:
		out = append(append(out, a.AWS...), a.Azure...)
	}
	return append(out, a.More...)
}

// --- Official sources ---------------------------------------------------

func fsbp(id, title string) Ref {
	svc, n, _ := strings.Cut(id, ".")
	s := strings.ToLower(svc)
	return Ref{"AWS Security Hub " + id + ": " + title,
		"https://docs.aws.amazon.com/securityhub/latest/userguide/" + s + "-controls.html#" + s + "-" + n}
}

var mcsbDomain = map[string]string{
	"NS": "network-security", "IM": "identity-management", "PA": "privileged-access", "DP": "data-protection",
	"AM": "asset-management", "LT": "logging-threat-detection", "PV": "posture-vulnerability-management",
	"ES": "endpoint-security", "BR": "backup-recovery", "DS": "devops-security",
}

func mcsb(id, title string) Ref {
	domain, _, _ := strings.Cut(id, "-")
	return Ref{"Microsoft cloud security benchmark " + id + ": " + title,
		"https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-v2-" + mcsbDomain[domain]}
}

func doc(label, url string) Ref { return Ref{label, url} }

var (
	ns1 = mcsb("NS-1", "Establish network segmentation boundaries")
	ns2 = mcsb("NS-2", "Secure cloud native services with network controls")
	ns8 = mcsb("NS-8", "Detect and disable insecure services and protocols")
	dp3 = mcsb("DP-3", "Encrypt sensitive data in transit")
	dp4 = mcsb("DP-4", "Enable data at rest encryption by default")
	dp8 = mcsb("DP-8", "Ensure security of key and certificate repository")
	im8 = mcsb("IM-8", "Restrict the exposure of credentials and secrets")
	pa7 = mcsb("PA-7", "Follow just enough administration (least privilege) principle")
	ds  = mcsb("DS-2", "Secure the software supply chain")

	awsSecrets   = doc("AWS Secrets Manager: what it is", "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html")
	azKeyVault   = doc("Azure Key Vault: overview", "https://learn.microsoft.com/en-us/azure/key-vault/general/overview")
	awsSSM       = doc("AWS Systems Manager Session Manager: log in without opening SSH", "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html")
	azBastion    = doc("Azure Bastion: log in without a public port", "https://learn.microsoft.com/en-us/azure/bastion/bastion-overview")
	azNSG        = doc("Azure network security groups", "https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview")
	awsSG        = doc("AWS security groups", "https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html")
	azPrivate    = doc("Azure Private Link and private endpoints", "https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-overview")
	awsIAMBest   = doc("AWS IAM security best practices", "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html")
	azRBACBest   = doc("Azure RBAC best practices", "https://learn.microsoft.com/en-us/azure/role-based-access-control/best-practices")
	awsS3Block   = doc("Amazon S3 Block Public Access", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html")
	azBlobAnon   = doc("Prevent anonymous read access to Azure blobs", "https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent")
	azStorageTLS = doc("Azure Storage: require a minimum TLS version", "https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version")
	tfState      = doc("Terraform: sensitive data in state", "https://developer.hashicorp.com/terraform/language/state/sensitive-data")
	dockerSec    = doc("Docker Engine security", "https://docs.docker.com/engine/security/")
	dockerRoot   = doc("Docker rootless mode", "https://docs.docker.com/engine/security/rootless/")
	k8sPSS       = doc("Kubernetes Pod Security Standards", "https://kubernetes.io/docs/concepts/security/pod-security-standards/")
	owaspSQLi    = doc("OWASP: SQL injection prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html")
	owaspCmd     = doc("OWASP: OS command injection defense", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html")
	owaspDeser   = doc("OWASP: deserialization", "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html")
	owaspSecrets = doc("OWASP: secrets management", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html")
	owaspTLS     = doc("OWASP: transport layer security", "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html")
	mitreIngress = doc("MITRE ATT&CK T1105: Ingress tool transfer", "https://attack.mitre.org/techniques/T1105/")
	mitrePersist = doc("MITRE ATT&CK TA0003: Persistence", "https://attack.mitre.org/tactics/TA0003/")
	mitreObfusc  = doc("MITRE ATT&CK T1027: Obfuscated files or information", "https://attack.mitre.org/techniques/T1027/")
	mitreCreds   = doc("MITRE ATT&CK T1552: Unsecured credentials", "https://attack.mitre.org/techniques/T1552/")
	mitreDefense = doc("MITRE ATT&CK T1562: Impair defenses", "https://attack.mitre.org/techniques/T1562/")
	slsa         = doc("OWASP: software supply chain security", "https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html")
)

// --- What each finding means --------------------------------------------

var openLoginPort = Advice{
	Story: "Robots scan the whole internet around the clock and find a newly opened login port within minutes. They then try thousands of user names and passwords, or a known weakness in the login service. If one attempt works, they control the server: they can read its data, use it to attack others, or mine cryptocurrency on your bill.",
	Fix: []string{
		"Allow the port only from your own IP address (a /32 address), not from 0.0.0.0/0, * or Internet.",
		"Better: close the port completely and log in through AWS Systems Manager Session Manager or Azure Bastion, which need no open port.",
		"Use SSH keys instead of passwords, and turn off password login.",
	},
	AWS:   []Ref{fsbp("EC2.19", "Security groups should not allow unrestricted access to ports with high risk"), fsbp("EC2.21", "Network ACLs should not allow ingress from 0.0.0.0/0 to port 22 or port 3389"), awsSSM, awsSG},
	Azure: []Ref{ns1, azBastion, azNSG},
}

var openDatabasePort = Advice{
	Story: "A database port that anyone can reach is found by scanners within minutes. Attackers then guess the password, use default accounts, or exploit an unpatched version. A successful attempt gives them every row in the database, and a database is usually where the most valuable data lives.",
	Fix: []string{
		"Never open a database port to the internet. Let only the application's own network or security group reach it.",
		"Connect from your own computer through a VPN, a bastion host or a private endpoint instead.",
	},
	AWS:   []Ref{fsbp("EC2.19", "Security groups should not allow unrestricted access to ports with high risk"), fsbp("RDS.2", "RDS DB instances should prohibit public access"), awsSG},
	Azure: []Ref{ns1, ns2, azPrivate},
}

var openPort = Advice{
	Story: "Whatever listens on this port can be reached by anyone on the internet. If that program has a weakness, or needs no login, a stranger can use it.",
	Fix: []string{
		"Open only the ports the service really needs, and only to the addresses that need them.",
		"Put web services behind a load balancer or gateway with HTTPS, and keep everything else private.",
	},
	AWS:   []Ref{fsbp("EC2.18", "Security groups should only allow unrestricted incoming traffic for authorized ports"), awsSG},
	Azure: []Ref{ns1, azNSG},
}

var webPort = Advice{
	Story: "This is normal for a website: visitors have to reach it. It is listed so you know exactly which doors are open. Plain HTTP on port 80 is not encrypted, so it should only redirect to HTTPS.",
	Fix: []string{
		"Make sure only the web ports are open, and that port 80 only redirects to HTTPS on 443.",
		"Consider a web application firewall (AWS WAF, Azure Web Application Firewall) in front of public sites.",
	},
	AWS:   []Ref{fsbp("ELB.1", "Application Load Balancer should be configured to redirect all HTTP requests to HTTPS")},
	Azure: []Ref{mcsb("NS-6", "Deploy web application firewall"), dp3},
}

var everyPort = Advice{
	Story: "Every service on the machine, including ones you did not know were running, can be reached from the whole internet. This is the widest door there is.",
	Fix: []string{
		"Replace the rule with one rule per port the service needs.",
		"Limit each rule to the addresses that need it.",
	},
	AWS:   []Ref{fsbp("EC2.18", "Security groups should only allow unrestricted incoming traffic for authorized ports"), fsbp("EC2.19", "Security groups should not allow unrestricted access to ports with high risk")},
	Azure: []Ref{ns1, azNSG},
}

var secretInCode = Advice{
	Story: "Code is copied, shared, pasted into chats and pushed to Git, and Git keeps every old version forever. Bots search public repositories for keys and passwords and use them within minutes of a push. Anyone who gets the file gets the same access as you.",
	Fix: []string{
		"Remove the value from the code, and change it (revoke the key, set a new password): assume it is already known.",
		"Store it in AWS Secrets Manager or Azure Key Vault, or pass it in as a hidden parameter or environment variable.",
		"If it was ever pushed to Git, removing it in a new commit is not enough; the old commit still has it.",
	},
	AWS:   []Ref{awsSecrets, fsbp("CodeBuild.2", "CodeBuild project environment variables should not contain clear text credentials"), fsbp("ECS.8", "Secrets should not be passed as container environment variables")},
	Azure: []Ref{im8, azKeyVault},
	More:  []Ref{owaspSecrets, mitreCreds},
}

var publicFiles = Advice{
	Story: "Anyone who finds or guesses the address can download every file, without logging in. Search engines and scanners list open buckets and containers, and leaked customer data, backups and logs are among the most common causes of data breaches.",
	Fix: []string{
		"Keep storage private, and turn on the account-wide public access block.",
		"Share single files with time-limited signed links (S3 presigned URLs, Azure SAS), or serve a public website through a CDN (CloudFront, Azure Front Door).",
	},
	AWS:   []Ref{fsbp("S3.1", "S3 general purpose buckets should have block public access settings enabled"), fsbp("S3.2", "S3 general purpose buckets should block public read access"), fsbp("S3.8", "S3 general purpose buckets should block public access"), awsS3Block},
	Azure: []Ref{ns2, azBlobAnon},
}

var publicDatabase = Advice{
	Story: "The database gets an address on the internet. From then on only its password stands between the world and your data, and passwords get guessed, leaked or reused.",
	Fix: []string{
		"Turn public access off and let only the application reach the database, inside the same network.",
		"Use a private endpoint (Azure) or keep the database in private subnets (AWS), and connect through a VPN or bastion when you need to.",
	},
	AWS:   []Ref{fsbp("RDS.2", "RDS DB Instances should prohibit public access"), fsbp("Redshift.1", "Amazon Redshift clusters should prohibit public access"), fsbp("DMS.1", "Database Migration Service replication instances should not be public")},
	Azure: []Ref{ns2, azPrivate, doc("Azure SQL: firewall rules", "https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure")},
}

var adminRights = Advice{
	Story: "Whoever or whatever gets these rights can do almost anything in the account: read all data, delete everything, create expensive resources or lock you out. If the server or function that has them is ever broken into, the attacker gets the whole account.",
	Fix: []string{
		"Give only the permissions the job needs (least privilege), for example read access to one bucket.",
		"Start from a narrow managed policy or role, and let AWS IAM Access Analyzer or Azure's access reviews show what is really used.",
	},
	AWS:   []Ref{fsbp("IAM.1", `IAM policies should not allow full "*" administrative privileges`), fsbp("IAM.21", "IAM customer managed policies that you create should not allow wildcard actions for services"), awsIAMBest},
	Azure: []Ref{pa7, azRBACBest},
}

var anyonePrincipal = Advice{
	Story: `A policy with Principal "*" lets anyone, including people outside your account and organisation, use what it allows. Unless that is a deliberate public website, it is a door left open to the world.`,
	Fix: []string{
		"Name the AWS accounts, roles or services that need access instead of \"*\".",
		"If it must be public, add a condition (for example aws:SourceVpc or aws:PrincipalOrgID) and allow only the read action needed.",
	},
	AWS: []Ref{fsbp("S3.6", "S3 general purpose bucket policies should restrict access to other AWS accounts"), fsbp("SQS.3", "SQS queue access policies should not allow public access"),
		fsbp("SNS.4", "SNS topic access policies should not allow public access"), fsbp("KMS.5", "KMS keys should not be publicly accessible"), fsbp("Lambda.1", "Lambda function policies should prohibit public access")},
}

var downloadRun = Advice{
	Story: "The script fetches code from the internet and runs it straight away, often with administrator rights. Nobody reads what runs, and whoever controls that address, now or later, decides what happens on your machine. This is one of the most common ways malware is installed.",
	Fix: []string{
		"Download the file first, read it, check it against a published checksum or signature, and only then run it.",
		"Prefer the vendor's signed package repository (apt, dnf, winget) with its signing key over an install script.",
	},
	Azure: []Ref{ds},
	More:  []Ref{mitreIngress},
}

var exact = map[string]Advice{
	"Every port is open to the internet": everyPort,
	"A port is open to the internet": {
		Story: "Traffic from anywhere is allowed, but the port comes from a variable LookFirst cannot see. If that variable is a login or database port, it is wide open.",
		Fix:   []string{"Check which value the variable gets, and limit the source addresses whatever the port is."},
		AWS:   []Ref{fsbp("EC2.18", "Security groups should only allow unrestricted incoming traffic for authorized ports")},
		Azure: []Ref{ns1},
	},
	"Reachable from the internet": {
		Story: "The resource gets a public address. That is only safe if what listens behind it is meant to be public and its firewall is tight; every open port on it is reachable from anywhere.",
		Fix: []string{
			"Give public addresses only to what must be public, such as a load balancer.",
			"Keep servers and databases in private networks and reach them through a bastion, VPN or Session Manager.",
		},
		AWS:   []Ref{fsbp("EC2.9", "Amazon EC2 instances should not have a public IPv4 address"), fsbp("EC2.15", "Amazon EC2 subnets should not automatically assign public IP addresses")},
		Azure: []Ref{ns1, azBastion},
	},
	"Files are public":         publicFiles,
	"Files can be made public": publicFiles,
	"Files are made public":    publicFiles,
	"Bucket is public":         publicFiles,
	"Public access is not blocked": {
		Story: "The safety catch that stops a bucket from ever becoming public is off. One wrong policy or ACL later, by you or a script, and the files are open to everyone.",
		Fix:   []string{"Set all four public access block settings to true, for the bucket and for the whole account."},
		AWS:   []Ref{fsbp("S3.1", "S3 general purpose buckets should have block public access settings enabled"), awsS3Block},
	},
	"Anyone can access it": anyonePrincipal,
	"Anyone can call the function": {
		Story: "Any AWS account, and through it anyone, can run the function. Each run costs you money, and if the function reads data or changes things, a stranger can make it do so.",
		Fix:   []string{"Name the service or account allowed to call it (for example apigateway.amazonaws.com), and add a SourceArn condition."},
		AWS:   []Ref{fsbp("Lambda.1", "Lambda function policies should prohibit public access")},
	},
	"Function is open on the internet without login": {
		Story: "The function gets a public web address that anyone can call without logging in. Bots find such addresses, and every call runs your code and costs you money.",
		Fix: []string{
			"Use AuthType AWS_IAM so callers must sign their requests, or put the function behind API Gateway with authorisation.",
			"If it must be open, check the caller inside the function and limit how often it can run.",
		},
		AWS: []Ref{fsbp("Lambda.1", "Lambda function policies should prohibit public access"), doc("AWS Lambda: function URL access control", "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html")},
	},
	"Full control of the AWS account": adminRights,
	"Permission to do everything":     adminRights,
	"Role allows everything":          adminRights,
	"Full control of the cluster is handed out": {
		Story: "The account or pod gets cluster-admin, the highest right in Kubernetes. Anyone who takes over that pod can read every secret and run anything on every node.",
		Fix:   []string{"Bind a role with only the verbs and resources needed, in one namespace (Role and RoleBinding instead of ClusterRoleBinding)."},
		More:  []Ref{doc("Kubernetes: RBAC good practices", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")},
	},
	"Database reachable from the internet": publicDatabase,
	"Database open to the whole internet":  publicDatabase,
	"Database admin panel is published on every network interface": {
		Story: "phpMyAdmin, Adminer and similar panels give whoever logs in full control of the database. Bots look for them by name, and they are often left with weak or default passwords.",
		Fix:   []string{"Publish the panel on 127.0.0.1 only (\"127.0.0.1:8080:80\"), or leave it out and start it only when you need it."},
		More:  []Ref{dockerSec},
	},
	"Database open to all of Azure": {
		Story: "The rule 0.0.0.0–0.0.0.0 means \"allow Azure services\". That is every service in Azure, including ones run by other customers, not only yours.",
		Fix:   []string{"Remove the rule and use a private endpoint, or allow only your own outbound addresses."},
		Azure: []Ref{ns2, azPrivate},
	},
	"Password or key written in the code":      secretInCode,
	"Secret written in the code":               secretInCode,
	"Password has a default value in the code": secretInCode,
	"Secret values are stored in the file":     secretInCode,
	"Password has a fallback value in the code": {
		Story: "When the variable is missing, for example because a .env file was not copied, the weak password written in the file is used in silence. Nobody notices until someone logs in with it.",
		Fix:   []string{"Remove the fallback, or write ${NAME:?} so the start fails loudly when the value is missing."},
		Azure: []Ref{im8},
		More:  []Ref{owaspSecrets},
	},
	"Password parameter is not hidden": {
		Story: "The password is shown in plain text in the CloudFormation console, its events and the stack's parameters, to everyone who can view the stack.",
		Fix:   []string{"Add NoEcho: true, or better, use a dynamic reference to Secrets Manager: {{resolve:secretsmanager:name}}."},
		AWS:   []Ref{awsSecrets},
	},
	"Password parameter is not marked secure": {
		Story: "The value ends up in the deployment history and logs, readable by everyone who can see the deployment.",
		Fix:   []string{"Use type securestring (ARM) or @secure() (Bicep), and fill it from Key Vault."},
		Azure: []Ref{im8, doc("Bicep: secure parameters", "https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/parameters#secure-parameters")},
	},
	"Private key is saved in the Terraform state": {
		Story: "Terraform writes the private key in plain text into terraform.tfstate. That file is often shared with a team, stored in a bucket or even committed to Git, and whoever can read it can log in to the server.",
		Fix:   []string{"Create the key yourself with ssh-keygen and give Terraform only the public key, or keep the state encrypted with tight access."},
		More:  []Ref{tfState},
	},
	"Creates a long-lived access key": {
		Story: "Access keys never expire by themselves. They are copied into scripts and config files and are among the most leaked credentials there are.",
		Fix:   []string{"Use roles (instance profiles, task roles) for machines and IAM Identity Center for people, and rotate or delete keys you keep."},
		AWS:   []Ref{fsbp("IAM.3", "IAM users' access keys should be rotated every 90 days or less"), awsIAMBest},
	},
	"Data is not encrypted": {
		Story: "If a disk, snapshot or backup is copied or leaked, everything on it can be read directly. Encryption at rest costs nothing extra on AWS and Azure.",
		Fix:   []string{"Turn encryption at rest on; the cloud provider handles the keys for you unless you choose your own."},
		AWS:   []Ref{fsbp("RDS.3", "RDS DB instances should have encryption at-rest enabled"), fsbp("EC2.3", "Attached Amazon EBS volumes should be encrypted at-rest"), fsbp("EFS.1", "Elastic File System should be configured to encrypt file data at-rest using AWS KMS")},
		Azure: []Ref{dp4},
	},
	"Unencrypted traffic is allowed": {
		Story: "Data can travel over plain HTTP, where anyone on the network path, such as a public Wi-Fi, can read or change it.",
		Fix:   []string{"Require HTTPS only (supportsHttpsTrafficOnly / https_traffic_only_enabled = true)."},
		Azure: []Ref{dp3, azStorageTLS},
		More:  []Ref{owaspTLS},
	},
	"Old TLS version allowed": {
		Story: "TLS 1.0 and 1.1 have known weaknesses and are switched off by browsers. Allowing them lets an attacker push a connection down to the weak version.",
		Fix:   []string{"Require TLS 1.2 or newer."},
		AWS:   []Ref{fsbp("ELB.17", "Application and Network Load Balancers with listeners should use recommended security policies")},
		Azure: []Ref{dp3, ns8, azStorageTLS},
		More:  []Ref{owaspTLS},
	},
	"No HTTPS": {
		Story: "Visitors' traffic, including passwords and cookies, travels unencrypted and can be read or changed on the way.",
		Fix:   []string{"Serve HTTPS with a certificate (AWS Certificate Manager and Azure-managed certificates are free), and redirect HTTP to HTTPS."},
		AWS:   []Ref{fsbp("ELB.1", "Application Load Balancer should be configured to redirect all HTTP requests to HTTPS"), fsbp("CloudFront.3", "CloudFront distributions should require encryption in transit")},
		Azure: []Ref{dp3},
		More:  []Ref{owaspTLS},
	},
	"Unencrypted connection": {
		Story: "The code talks to this address without encryption, so anyone on the network path can read or change what is sent, including passwords and tokens.",
		Fix:   []string{"Use https:// (or wss://, sftp://) instead."},
		Azure: []Ref{dp3},
		More:  []Ref{owaspTLS},
	},
	"Password login is allowed": {
		Story: "Passwords can be guessed, and login ports are attacked with password lists all day long. Keys cannot be guessed.",
		Fix:   []string{"Turn password login off and log in with SSH keys only."},
		Azure: []Ref{mcsb("IM-6", "Use strong authentication controls")},
	},
	"Kubernetes API is reachable from the internet": {
		Story: "The cluster's control interface answers everyone on the internet. It still asks for credentials, but leaked kubeconfig files and new weaknesses then lead straight to the whole cluster.",
		Fix:   []string{"Limit the API to your own addresses (public_access_cidrs / authorized IP ranges), or make the endpoint private."},
		AWS:   []Ref{fsbp("EKS.1", "EKS cluster endpoints should not be publicly accessible"), doc("Amazon EKS: cluster endpoint access", "https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html")},
		Azure: []Ref{ns2},
	},
	"Downloads code and runs it":                      downloadRun,
	"Runs a download or shell command when installed": downloadRun,
	"Hidden code is decoded and run": {
		Story: "The code hides what it runs by encoding it. Legitimate software has no reason to do that; malware does it to get past people and scanners.",
		Fix:   []string{"Do not run it. Decode the text separately and read it first, or ask where the code comes from."},
		More:  []Ref{mitreObfusc},
	},
	"Runs text as code": {
		Story: "eval and exec turn text into code while the program runs. If any part of that text comes from a user, a file or the network, an attacker can make the program run anything.",
		Fix:   []string{"Avoid eval/exec; parse data with a proper parser (json, ast.literal_eval) instead."},
		More:  []Ref{owaspCmd},
	},
	"Command built from text": {
		Story: "A shell command is glued together from text. A value such as \"; rm -rf ~\" in that text becomes a second command (command injection).",
		Fix:   []string{"Pass the program and its arguments as a list (subprocess.run([...]), execFile) without a shell."},
		More:  []Ref{owaspCmd},
	},
	"SQL built from text": {
		Story: "The database query is glued together from text. A value such as ' OR 1=1 -- changes what the query does and can read or delete every row (SQL injection).",
		Fix:   []string{"Use parameters (placeholders) for every value in a query."},
		More:  []Ref{owaspSQLi},
	},
	"Loads data in an unsafe way": {
		Story: "pickle and yaml.load can run code that is hidden in the data. Loading a file from someone else is then the same as running their program.",
		Fix:   []string{"Use json or yaml.safe_load for data you did not create yourself."},
		More:  []Ref{owaspDeser},
	},
	"Reads secrets and talks to the internet": {
		Story: "The code reads files that hold keys or logins and also sends data to the internet. That is exactly what credential-stealing malware does.",
		Fix:   []string{"Find out why it needs those files. Do not run it until you know where the data goes."},
		More:  []Ref{mitreCreds},
	},
	"Touches sensitive files": {
		Story: "The code refers to files that hold keys, logins or passwords. A tool may have a good reason, but stealing these files is also the first thing malware does.",
		Fix:   []string{"Check why it needs them, and that nothing it reads is sent anywhere."},
		More:  []Ref{mitreCreds},
	},
	"Talks to a suspicious service": {
		Story: "Webhooks, paste sites, anonymous upload services and tunnels are favourite ways for malware to send stolen data out or fetch its next step.",
		Fix:   []string{"Make sure you know why the code contacts this service before you run it."},
		More:  []Ref{doc("MITRE ATT&CK TA0010: Exfiltration", "https://attack.mitre.org/tactics/TA0010/")},
	},
	"Talks to a bare IP address": {
		Story: "Legitimate code almost always uses names such as api.example.com. Connecting straight to an address is typical of malware talking to its control server.",
		Fix:   []string{"Find out whose address it is before running the code."},
		More:  []Ref{doc("MITRE ATT&CK TA0011: Command and control", "https://attack.mitre.org/tactics/TA0011/")},
	},
	"Makes something start automatically": {
		Story: "Something is set to run every time the machine starts or you log in. Installers do this for services you asked for; malware does it to stay on the machine.",
		Fix:   []string{"Check exactly what is added, and that you want it to run at every start."},
		More:  []Ref{mitrePersist},
	},
	"Turns off security protection": {
		Story: "Antivirus, the firewall or another protection is switched off. Whatever runs afterwards, including anything downloaded, runs unchecked.",
		Fix:   []string{"Do not run it. If a tool really needs an exception, add a narrow exception instead of switching protection off."},
		More:  []Ref{mitreDefense},
	},
	"Certificate checks are turned off": {
		Story: "The code accepts any certificate, so anyone in the network path can pretend to be the server and read or change the traffic (man in the middle).",
		Fix:   []string{"Turn certificate checks back on. For an internal certificate, add its CA instead."},
		More:  []Ref{owaspTLS},
	},
	"PowerShell safety check is bypassed": {
		Story: "The execution policy is switched off for this run so that unsigned scripts can run. Malware does this to run its scripts without warnings.",
		Fix:   []string{"Run only scripts you have read, and sign the ones you keep."},
		More:  []Ref{mitreDefense},
	},
	"Can delete everything": {
		Story: "If the variable is empty or wrong, the command deletes far more than intended, such as / or your whole home folder. This has destroyed many machines.",
		Fix:   []string{"Write ${DIR:?} so the command stops when the variable is empty, and check the path before deleting."},
	},
	"Destructive command": {
		Story: "This line deletes or overwrites real things, such as a whole resource group, cluster or database table.",
		Fix:   []string{"Make sure it points at the right place, and never run it with values you have not checked."},
	},
	"Runs with admin rights": {
		Story: "The lines run as root, with full power over the machine. A mistake, or a malicious download in the same script, can change anything.",
		Fix:   []string{"Run as root only the lines that need it, and read what they do first."},
	},
	"User can take over the machine through Docker": {
		Story: "Members of the docker group can start a container that mounts the whole disk, and so become root without a password.",
		Fix:   []string{"Add only users who may be root anyway, or use rootless Docker."},
		More:  []Ref{dockerRoot, dockerSec},
	},
	"Container runs privileged": {
		Story: "A privileged container can do nearly everything the host can. Breaking out of it to take over the host is easy.",
		Fix:   []string{"Remove privileged and add only the specific capabilities the container needs."},
		AWS:   []Ref{fsbp("ECS.4", "ECS containers should run as non-privileged")},
		More:  []Ref{k8sPSS, dockerSec},
	},
	"Container runs as root": {
		Story: "If an attacker breaks into the program in the container, they are root inside it, which makes breaking out to the host much easier.",
		Fix:   []string{"Add a USER line (Dockerfile) or runAsNonRoot (Kubernetes) with an unprivileged user."},
		AWS:   []Ref{fsbp("ECS.20", "ECS Task Definitions should configure non-root users in Linux container definitions")},
		More:  []Ref{k8sPSS},
	},
	"The host's whole disk is mounted": {
		Story: "The container can read and change every file on the host, including passwords and system settings.",
		Fix:   []string{"Mount only the folder the container needs, read-only if it can."},
		More:  []Ref{dockerSec},
	},
	"Image version is not pinned": {
		Story: "\"latest\" can mean a different image tomorrow. A new version can break your app, and a hijacked image is picked up without anyone noticing.",
		Fix:   []string{"Pin a version (image:1.2.3), or better, a digest (image@sha256:…)."},
		AWS:   []Ref{fsbp("ECR.2", "ECR private repositories should have tag immutability configured")},
	},
	"Base image version is not pinned": {
		Story: "FROM image:latest, or no tag at all, builds on whatever the image is that day. A new version can break the build, and a hijacked image is picked up without anyone noticing.",
		Fix:   []string{"Pin a version, or better a digest: FROM python:3.12-slim@sha256:…"},
		More:  []Ref{slsa},
	},
	"Package version is not pinned": {
		Story: "Every install can pick a newer version than the one you tested, including one an attacker published after taking over the package.",
		Fix:   []string{"Pin exact versions, and commit the lock file (package-lock.json, poetry.lock, requirements with hashes)."},
		Azure: []Ref{ds},
		More:  []Ref{slsa},
	},
	"Image exposes SSH (port 22)": {
		Story: "A container that runs an SSH server is another login door to attack, and containers are rarely patched like servers.",
		Fix:   []string{"Remove the SSH server; use docker exec or kubectl exec to get into a container when you must."},
		More:  []Ref{dockerSec},
	},
	"Debug mode is on": {
		Story: "Debug mode shows stack traces, settings and sometimes an interactive console to whoever triggers an error. In Flask and Django that can mean running code on the server.",
		Fix:   []string{"Turn debug off outside your own computer, for example from an environment variable."},
		Azure: []Ref{mcsb("PV-2", "Audit and enforce secure configurations")},
	},
	"Gives everyone full access to files": {
		Story: "chmod 777 lets every user and every program on the machine read, change and run the files, including a web server that has been broken into.",
		Fix:   []string{"Give only the owner write access (755 for folders, 644 for files), and the right owner with chown."},
	},
	"Deletes files": {
		Story: "The code deletes files. That may be exactly what it should do, but check which files, and that the path cannot be empty or point somewhere unexpected.",
		Fix:   []string{"Check the path, and print it before deleting while you test."},
	},
	"Downloads a file without checking it": {
		Story: "The file is fetched at build time from an address, and nothing checks that it is the file you expect. If the address changes hands, the build takes whatever is there.",
		Fix:   []string{"Download with curl and check a published checksum (sha256sum -c), or copy a file you have checked into the build."},
		Azure: []Ref{ds},
		More:  []Ref{slsa},
	},
	"Runs a script when installed": {
		Story: "The package runs its own script when it is installed, before you have used it. That is how most malicious npm and PyPI packages do their harm.",
		Fix:   []string{"Check what the script does, or install with --ignore-scripts."},
		Azure: []Ref{ds},
		More:  []Ref{slsa, doc("OWASP: npm security", "https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html")},
	},
	"Opens a raw network listener": {
		Story: "The code waits for connections on a bare network port. Remote-control tools and backdoors work this way.",
		Fix:   []string{"Find out who is meant to connect, and bind to 127.0.0.1 if only this machine should."},
		More:  []Ref{doc("MITRE ATT&CK TA0011: Command and control", "https://attack.mitre.org/tactics/TA0011/")},
	},
	"Makes a program run as its owner": {
		Story: "setuid lets anyone run the program with its owner's rights, often root. A flaw in that program then gives everyone root.",
		Fix:   []string{"Remove the setuid bit (chmod u-s) unless the program is built for it."},
		More:  []Ref{doc("MITRE ATT&CK T1548: Abuse elevation control mechanism", "https://attack.mitre.org/techniques/T1548/")},
	},
	"Port opened on every node": {
		Story: "A NodePort service opens the port on every machine in the cluster, so it can be reached wherever those machines can.",
		Fix:   []string{"Use ClusterIP inside the cluster, and an ingress or load balancer with HTTPS for what must be public."},
		More:  []Ref{k8sPSS},
	},
	"File skipped": {
		Story: "LookFirst did not read this file, so anything in it is not in the picture or the findings.",
		Fix:   []string{"Read it yourself, or split it into smaller files."},
	},
	"Bicep file could not be read": {
		Story: "Bicep needs Microsoft's Bicep compiler, and LookFirst could not run it here, so this file is not in the picture or the findings.",
		Fix:   []string{"Install it with az bicep install, or compile the file to JSON with az bicep build and check the JSON file."},
	},
	"Ports are opened without being named": {
		Story: "The command opens login ports to the whole internet by default, even though no port is written in the script. It is easy to miss, and robots find such ports within minutes.",
		Fix: []string{
			"Name only the ports you need, and allow them only from your own address.",
			"Better: open no login port and use Azure Bastion.",
		},
		Azure: []Ref{ns1, azBastion},
	},
	"Open to every network": {
		Story: "The service answers on its public address to the whole internet, so only its login or keys protect it. Leaked keys, connection strings or a weak password are then enough, from anywhere in the world.",
		Fix: []string{
			"Allow only your own networks (a firewall with default action Deny, plus the virtual networks or IP addresses that need it).",
			"Better: turn public network access off and reach the service through a private endpoint.",
		},
		Azure: []Ref{ns2, azPrivate},
	},
	"Resource type Azure does not have": {
		Story: "The template asks Azure for a kind of resource that is not in Microsoft's list. The deployment then stops with an error, perhaps halfway, after other parts are already built. Code from an AI assistant sometimes contains types that sound right but do not exist.",
		Fix: []string{
			"Look the type up in Microsoft's template reference and use the exact name it gives, including the parent type for child resources.",
			"If the type is new, check that it is offered in your region and subscription (az provider show).",
		},
		Azure: []Ref{doc("Azure template reference: every resource type", "https://learn.microsoft.com/en-us/azure/templates/"), doc("Azure resource providers and types", "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types")},
	},
	"Resource type AWS does not have": {
		Story: "The template asks AWS for a kind of resource that is not in Amazon's list. CloudFormation then rolls the stack back. Code from an AI assistant sometimes contains types that sound right but do not exist.",
		Fix:   []string{"Look the type up in Amazon's resource type reference and use the exact name it gives."},
		AWS:   []Ref{doc("AWS CloudFormation: resource and property type reference", "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-template-resource-type-ref.html")},
	},
	"Old API version": {
		Story: "Each Azure API version fixes which settings exist and what their defaults are. A version several years old can lack settings that newer ones have, and the template then cannot ask for them, or gets older, less safe defaults.",
		Fix: []string{
			"Move the resource to a recent API version, ideally less than two years old as Microsoft's own linter recommends.",
			"Read what changed between the versions before you deploy, as names and defaults can differ.",
		},
		Azure: []Ref{doc("Bicep linter: use recent API versions", "https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/linter-rule-use-recent-api-versions"), doc("Azure template reference: every resource type", "https://learn.microsoft.com/en-us/azure/templates/")},
	},
	"Deleted secrets can be lost for good": {
		Story: "Without purge protection, a key vault or a secret can be deleted and purged at once, by mistake or by an attacker. Everything encrypted with a lost key stays unreadable for good.",
		Fix:   []string{"Turn purge protection on (enablePurgeProtection / purge_protection_enabled). It cannot be turned off again, which is the point."},
		Azure: []Ref{dp8, doc("Azure Key Vault: soft-delete and purge protection", "https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview")},
	},
	"Files can be uploaded over unencrypted FTP": {
		Story: "Plain FTP sends the deployment user name and password unencrypted. Whoever reads them can upload their own code to your app.",
		Fix:   []string{"Set FTP to FtpsOnly, or Disabled if you deploy another way."},
		Azure: []Ref{dp3, ns8},
	},
	"Remote debugging is on": {
		Story: "Remote debugging opens an extra door into the running app, meant for a developer for a short while. Left on, it is one more way in.",
		Fix:   []string{"Turn remote debugging off, and on only for a short debugging session."},
		Azure: []Ref{mcsb("PV-2", "Audit and enforce secure configurations")},
	},
	"Registry admin account is on": {
		Story: "The registry gets one shared user name and password with full rights. It ends up in build scripts and laptops, and whoever has it can push their own images that your apps then run.",
		Fix:   []string{"Turn the admin user off and use Microsoft Entra identities, managed identities or repository-scoped tokens."},
		Azure: []Ref{mcsb("IM-1", "Centralize identity and authentication while ensuring isolation"), im8},
	},
	"Kubernetes access control is off": {
		Story: "Without role-based access control, everyone who can log in to the cluster can do everything in it, including reading every secret.",
		Fix:   []string{"Turn RBAC on, and give people and apps only the roles they need."},
		Azure: []Ref{pa7, doc("AKS: access and identity", "https://learn.microsoft.com/en-us/azure/aks/concepts-identity")},
	},
	"Full control in Azure is handed out": {
		Story: "Owner, Contributor and User Access Administrator can change or delete everything in their scope, and Owner can hand out rights to others. If the identity that has it is ever taken over, so is everything it reaches.",
		Fix: []string{
			"Give a narrower built-in role, such as Reader or a role for one service.",
			"Give it at the smallest scope that works (one resource, not the subscription), and use Privileged Identity Management for people.",
		},
		Azure: []Ref{pa7, mcsb("PA-1", "Separate and limit highly privileged/administrative users"), azRBACBest},
	},
	"Placeholder left in the code": {
		Story: "A value such as YOUR_IP_ADDRESS was meant to be replaced. Until it is, the code fails, or worse, half works in a way nobody chose.",
		Fix:   []string{"Fill in the real value, preferably from a variable or parameter."},
	},
	"Syntax error": {
		Story: "The file cannot be read as it is, so it will not run either, and LookFirst may have missed parts of it.",
		Fix:   []string{"Fix the error first, then check the file again."},
	},
	"Package installed straight from an address": {
		Story: "The package comes from a URL instead of the package registry, so nothing checks who made it or that it has not changed since you looked.",
		Fix:   []string{"Install a published version from the registry, or pin the address to an exact commit or checksum."},
		Azure: []Ref{ds},
		More:  []Ref{slsa},
	},
	"Packages may come from another server": {
		Story: "An extra package server can serve its own version of any package name, including names of your internal packages (dependency confusion).",
		Fix:   []string{"Use one trusted registry, or scope extra servers to your own package names."},
		Azure: []Ref{ds},
		More:  []Ref{slsa},
	},
}

// patterns cover titles that carry a value, such as a port or a package.
var patterns = []struct {
	re     *regexp.Regexp
	advice Advice
}{
	{regexp.MustCompile(`^(SSH|Remote Desktop|Telnet|WinRM|VNC)\b.*is open to the internet$`), openLoginPort},
	{regexp.MustCompile(`^(MySQL|PostgreSQL|SQL Server|MongoDB|Redis|Elasticsearch|Oracle|Cassandra|CouchDB|Memcached|Docker API|Kubernetes|etcd)\b.*(open to the internet|published on every network interface)$`), openDatabasePort},
	{regexp.MustCompile(`^Web traffic \(port \d+\) is allowed from the internet$`), webPort},
	{regexp.MustCompile(`is open to the internet$|is published on every network interface$|^Opens port .* to the network$`), openPort},
	{regexp.MustCompile(`^Package name looks like a misspelling of `), Advice{
		Story: "Attackers publish packages with names one letter away from popular ones (typosquatting). Installing the wrong one runs their code on your machine.",
		Fix:   []string{"Check the spelling against the real package name before installing."},
		More:  []Ref{slsa},
	}},
	{regexp.MustCompile(`^(Container|Pod)\b`), Advice{
		Story: "The container gets more power over the machine it runs on than it needs, which makes breaking out of it easier.",
		Fix:   []string{"Remove the extra rights and run with the restricted Pod Security Standard."},
		More:  []Ref{k8sPSS, dockerSec},
	}},
	{regexp.MustCompile(`^Sensitive host folder is mounted`), Advice{
		Story: "The container can read or change system files or keys on the host.",
		Fix:   []string{"Mount only what the container needs, read-only where possible."},
		More:  []Ref{dockerSec},
	}},
	{regexp.MustCompile(` adds a resource the code does not name$`), Advice{
		Story: "The cloud would create something that is not written in your file, through a default, a module or a transform such as SAM. It is part of what you pay for and what can be attacked.",
		Fix:   []string{"Look at what it is and whether you want it; name it in the code if you keep it, so it is reviewed like the rest."},
		Azure: []Ref{mcsb("AM-1", "Track asset inventory and their risks")},
	}},
	{regexp.MustCompile(`^Not seen in `), Advice{
		Story: "The code shows this risk, but the cloud's answer does not. A policy, a default or a value only known at deployment may have changed it.",
		Fix:   []string{"Check before you rely on it either way."},
	}},
}
