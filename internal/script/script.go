// Package script reads programs (Python, JavaScript/TypeScript, shell,
// PowerShell and Dockerfiles) without running them, and shows where they
// would send data, which files they touch, which ports they open, which
// packages they pull in and which secrets are written into them.
package script

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/risk"
	"github.com/Idris1980/lookfirst/internal/source"
)

// Titles fit scripts better than the infrastructure column names.
var Titles = map[model.Category]string{
	model.Internet: "Internet",
	model.Compute:  "Your code",
	model.Network:  "In the cloud",
	model.Security: "Programs it runs",
	model.Data:     "Files",
	model.Other:    "Packages",
}

// Order puts the code next to the internet and the things it touches.
var Order = []model.Category{model.Internet, model.Compute, model.Network, model.Data, model.Security, model.Other}

var friendly = map[source.Kind]string{
	source.Python: "Python script", source.JavaScript: "JavaScript", source.Shell: "shell script",
	source.PowerShell: "PowerShell script", source.Dockerfile: "Dockerfile",
	source.NpmManifest: "npm package list", source.PipRequirements: "pip package list",
}

func Read(files []source.File) *model.Graph {
	g := &model.Graph{Titles: Titles}
	local := localModules(files)
	for _, f := range files {
		g.Sources = append(g.Sources, f.Path)
		s := &scan{g: g, f: f, me: "script." + f.Path, local: local}
		g.AddNode(&model.Node{
			ID: s.me, Name: filepath.Base(f.Path), Kind: "code", Friendly: friendly[f.Kind],
			Category: model.Compute, File: f.Path, Line: 1,
		})
		s.run()
	}
	return g
}

type line struct {
	n    int
	code string // comments removed
}

type scan struct {
	g     *model.Graph
	f     source.File
	me    string
	lines []line
	local map[string]bool

	destinations []string // hosts it talks to
	sensitive    []string // sensitive files it reads
	packages     map[string]int
	programs     int
}

func (s *scan) run() {
	code := stripComments(s.f.Data, s.f.Kind)
	for i, l := range strings.Split(string(code), "\n") {
		s.lines = append(s.lines, line{i + 1, strings.TrimRight(l, "\r")})
	}
	s.packages = map[string]int{}

	if s.f.Kind == source.NpmManifest || s.f.Kind == source.PipRequirements {
		s.manifest()
		return
	}
	s.network()
	s.downloadAndRun()
	s.files()
	s.listening()
	s.programsRun()
	s.azureCLI()
	s.packagesUsed()
	s.secrets()
	s.weakening()
	if s.f.Kind == source.Dockerfile {
		s.dockerfile()
	}
	s.combined()
	syntax(s.g, s.f)
}

// each calls fn for every line where re matches.
func (s *scan) each(re *regexp.Regexp, fn func(l line, m []string)) {
	for _, l := range s.lines {
		for _, m := range re.FindAllStringSubmatch(l.code, -1) {
			fn(l, m)
		}
	}
}

func (s *scan) has(re *regexp.Regexp) bool {
	for _, l := range s.lines {
		if re.MatchString(l.code) {
			return true
		}
	}
	return false
}

func (s *scan) add(sev model.Severity, title, detail string, ln int) {
	s.g.Add(sev, s.me, title, detail, s.f.Path, ln)
}

// --- Network -----------------------------------------------------------

var (
	urlRe      = regexp.MustCompile(`\b(?:https?|wss?|ftp)://[^\s'"` + "`" + `<>(){}\[\],;|]+`)
	sendsData  = regexp.MustCompile(`(?i)(\.post\(|\.put\(|method\s*[:=]\s*['"](post|put)|-X\s*(POST|PUT)|--data|-d\s|-F\s|Invoke-RestMethod.*-Method\s+(Post|Put)|sendall\(|\.send\()`)
	socketDial = regexp.MustCompile(`(?:connect|create_connection)\(\s*\(\s*['"]([^'"]+)['"]\s*,\s*(\d+)`)
	bareIP     = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
)

// suspicious hosts are often used to steal data or deliver malware.
var suspicious = []struct{ host, why string }{
	{"discord.com/api/webhooks", "a Discord webhook, a common way for malware to send stolen data"},
	{"discordapp.com/api/webhooks", "a Discord webhook, a common way for malware to send stolen data"},
	{"api.telegram.org/bot", "a Telegram bot, a common way for malware to send stolen data"},
	{"pastebin.com", "a paste site, often used to host malware or collect stolen data"},
	{"hastebin", "a paste site, often used to host malware or collect stolen data"},
	{"transfer.sh", "an anonymous file upload service"},
	{"file.io", "an anonymous file upload service"},
	{"webhook.site", "a public request collector"},
	{"requestbin", "a public request collector"},
	{"pipedream.net", "a public request collector"},
	{"ngrok", "a tunnel to someone's own machine"},
	{"trycloudflare.com", "a temporary tunnel to someone's own machine"},
	{".onion", "a Tor hidden service"},
	{"bit.ly", "a link shortener that hides where it really goes"},
	{"tinyurl.com", "a link shortener that hides where it really goes"},
}

func (s *scan) network() {
	seen := map[string]bool{}
	s.each(urlRe, func(l line, m []string) {
		u, err := url.Parse(strings.TrimRight(m[0], ".:'\""))
		if err != nil || u.Hostname() == "" {
			return
		}
		host := strings.ToLower(u.Hostname())
		if host == "localhost" || strings.HasPrefix(host, "127.") || host == "0.0.0.0" || host == "::1" || strings.Contains(host, "${") || strings.Contains(host, "{") {
			return
		}
		// Links in help texts and schema URLs are not traffic.
		if host == "www.w3.org" || host == "schemas.microsoft.com" || host == "json-schema.org" {
			return
		}
		label := "connects"
		if sendsData.MatchString(l.code) {
			label = "sends data"
		}
		s.destination(host, label, l.n)

		if !seen[host+"|why"] {
			full := host + u.Path
			for _, sus := range suspicious {
				if strings.Contains(full, sus.host) {
					s.add(model.High, "Talks to a suspicious service", fmt.Sprintf("%s is %s. Make sure you know why this code needs it.", host, sus.why), l.n)
					s.g.Connect(s.me, "host."+host, "", true)
					break
				}
			}
			if bareIP.MatchString(host) && !privateIP(host) {
				s.add(model.Medium, "Talks to a bare IP address", fmt.Sprintf("The code connects straight to %s instead of a named service. Legitimate code rarely does this; malware often does.", host), l.n)
			}
			if u.Scheme == "http" || u.Scheme == "ws" || u.Scheme == "ftp" {
				s.add(model.Low, "Unencrypted connection", fmt.Sprintf("%s://%s is not encrypted, so anyone on the way can read or change the traffic. Use https.", u.Scheme, host), l.n)
			}
			seen[host+"|why"] = true
		}
	})
	s.each(socketDial, func(l line, m []string) {
		if m[1] == "localhost" || strings.HasPrefix(m[1], "127.") {
			return
		}
		s.destination(m[1], "port "+m[2], l.n)
	})
}

func (s *scan) destination(host, label string, ln int) {
	id := "host." + host
	kind := "globe"
	s.g.AddNode(&model.Node{ID: id, Name: host, Kind: kind, Friendly: "on the internet", Category: model.Internet, File: s.f.Path, Line: ln})
	s.g.Connect(s.me, id, label, false)
	for _, d := range s.destinations {
		if d == host {
			return
		}
	}
	s.destinations = append(s.destinations, host)
}

func privateIP(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

// --- Download and run ---------------------------------------------------

var downloadRun = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`(curl|wget)\b[^|]*\|\s*(sudo(\s+-\S+)*\s+)?(ba|z|da)?sh\b`), "downloads a script and pipes it straight into the shell"},
	{regexp.MustCompile(`(curl|wget)\b[^|]*\|\s*(sudo(\s+-\S+)*\s+)?(python3?|node|perl|ruby)\b`), "downloads code and pipes it straight into an interpreter"},
	{regexp.MustCompile(`(ba)?sh\s+<\(\s*(curl|wget)`), "downloads a script and runs it"},
	{regexp.MustCompile(`(?i)\b(iex|Invoke-Expression)\b.*\b(DownloadString|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b`), "downloads a script and runs it"},
	{regexp.MustCompile(`(?i)\b(DownloadString|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b.*\|\s*(iex|Invoke-Expression)\b`), "downloads a script and runs it"},
	{regexp.MustCompile(`\bexec\(\s*(requests\.get|urlopen|urllib\.request\.urlopen)\(`), "downloads Python code and runs it"},
	{regexp.MustCompile(`\beval\(\s*await\s+\(?\s*(await\s+)?fetch\(`), "downloads JavaScript and runs it"},
}

var obfuscated = []*regexp.Regexp{
	regexp.MustCompile(`\b(exec|eval)\(\s*(base64\.b64decode|codecs\.decode|zlib\.decompress|bytes\.fromhex|marshal\.loads)`),
	regexp.MustCompile(`\b(eval|Function)\(\s*(atob\(|Buffer\.from\()`),
	regexp.MustCompile(`(?i)-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}`),
	regexp.MustCompile(`(?i)\[System\.Convert\]::FromBase64String.*\b(iex|Invoke-Expression)\b|\b(iex|Invoke-Expression)\b.*FromBase64String`),
	regexp.MustCompile(`base64\s+(-d|--decode)\s*\|\s*(ba)?sh`),
}

// In Python exec() runs code; in JavaScript exec() usually runs a program,
// which programsRun covers.
var dynamicCode = map[source.Kind]*regexp.Regexp{
	source.Python:     regexp.MustCompile(`(^|[^.\w])(eval|exec)\(`),
	source.JavaScript: regexp.MustCompile(`(^|[^.\w])eval\(|new Function\(`),
}

func (s *scan) downloadAndRun() {
	for _, d := range downloadRun {
		s.each(d.re, func(l line, _ []string) {
			s.add(model.High, "Downloads code and runs it",
				fmt.Sprintf("This line %s. Whoever controls that address decides what runs on your machine, and it can change at any time. Download the file, read it, then run it.", d.what), l.n)
		})
	}
	s.downloadThenRun()
	for _, re := range obfuscated {
		s.each(re, func(l line, _ []string) {
			s.add(model.High, "Hidden code is decoded and run",
				"The code decodes text and runs it as a program. This hides what really runs, and is a typical sign of malware. Decode it separately and read it before running anything.", l.n)
		})
	}
	if re, ok := dynamicCode[s.f.Kind]; ok {
		s.each(re, func(l line, _ []string) {
			s.add(model.Medium, "Runs text as code",
				"eval/exec turns text into code at run time. If any of that text comes from a user, a file or the network, an attacker can run anything.", l.n)
		})
	}
}

// savedTo finds a download written to a file: curl -o name, wget -O name.
var savedTo = regexp.MustCompile(`\b(?:curl\b.*\s(?:-o|--output)|wget\b.*\s(?:-O|--output-document))[\s=]+['"]?([\w./-]+)`)

// downloadThenRun finds the same thing in two steps: a script is saved to a
// file and run on a later line, as in "curl … -o get-docker.sh" followed by
// "sudo sh get-docker.sh". Nobody reads the file in between.
func (s *scan) downloadThenRun() {
	lines := s.logicalLines() // "curl … \" with "-o file" on the next line
	for i, l := range lines {
		m := savedTo.FindStringSubmatch(l.code)
		if m == nil {
			continue
		}
		name := filepath.Base(m[1])
		runs := regexp.MustCompile(`(?:^|[;&|(]\s*)(?:sudo(?:\s+-\S+)*\s+)?(?:(?:(?:ba|z|da)?sh|python3?|node|perl|ruby)\s+)?['"]?(?:\.?/|[\w.-]+/)*` + regexp.QuoteMeta(name) + `['"]?(?:\s|$)`)
		for _, later := range lines[i+1:] {
			if runs.MatchString(strings.TrimSpace(later.code)) {
				s.add(model.High, "Downloads code and runs it",
					fmt.Sprintf("This line runs %s, which line %d downloads, without anyone reading it first. Whoever controls that address decides what runs on your machine, and it can change at any time. Download the file, read it, then run it.", name, l.n), later.n)
				break
			}
		}
	}
}

// --- Azure CLI ----------------------------------------------------------

var (
	azCommand = regexp.MustCompile(`(?:^|[;&|({=]\s*)az\s+(.*)`)

	// azCreates are the az commands that build something, and how to draw it.
	azCreates = []struct {
		cmd            *regexp.Regexp
		kind, friendly string
	}{
		{regexp.MustCompile(`^vm\s+create\b`), "vm", "virtual machine in Azure"},
		{regexp.MustCompile(`^(postgres|mysql)\s+(flexible-server\s+|server\s+)?create\b`), "database", "database in Azure"},
		{regexp.MustCompile(`^sql\s+server\s+create\b`), "database", "SQL server in Azure"},
		{regexp.MustCompile(`^storage\s+account\s+create\b`), "storage", "storage account in Azure"},
		{regexp.MustCompile(`^(webapp|functionapp)\s+create\b`), "webapp", "web app in Azure"},
		{regexp.MustCompile(`^aks\s+create\b`), "kubernetes", "Kubernetes in Azure"},
		{regexp.MustCompile(`^keyvault\s+create\b`), "key", "key vault in Azure"},
		{regexp.MustCompile(`^(containerapp|container)\s+create\b`), "container", "container in Azure"},
		{regexp.MustCompile(`^network\s+vnet\s+create\b`), "network", "virtual network in Azure"},
	}
	azFirewallRule = regexp.MustCompile(`^((postgres|mysql)\s+(flexible-server\s+|server\s+)?|sql\s+server\s+)firewall-rule\s+create\b`)
	windowsImage   = regexp.MustCompile(`(?i)win`)
)

// logicalLines joins commands split over several lines with a trailing
// backslash (shell) or backtick (PowerShell), so their flags are read together.
func (s *scan) logicalLines() []line {
	var out []line
	var cur strings.Builder
	start := 0
	for _, l := range s.lines {
		t := strings.TrimRight(l.code, " \t")
		if cur.Len() == 0 {
			start = l.n
		}
		if strings.HasSuffix(t, `\`) || (s.f.Kind == source.PowerShell && strings.HasSuffix(t, "`")) {
			cur.WriteString(t[:len(t)-1] + " ")
			continue
		}
		cur.WriteString(t)
		out = append(out, line{start, cur.String()})
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, line{start, cur.String()})
	}
	return out
}

// azFlag returns the value of the first of names given on an az command line.
func azFlag(args string, names ...string) (string, bool) {
	for _, n := range names {
		re := regexp.MustCompile(`(?:^|\s)` + regexp.QuoteMeta(n) + `(?:\s+|=)("[^"]*"|'[^']*'|\S+)`)
		if m := re.FindStringSubmatch(args); m != nil {
			return strings.Trim(m[1], `"'`), true
		}
	}
	return "", false
}

// azureCLI draws what az commands in a script would create in Azure, and
// checks the settings that open it to the internet. Some of them are az's
// defaults, so the risk is there even though the code does not name it.
func (s *scan) azureCLI() {
	if s.f.Kind != source.Shell && s.f.Kind != source.PowerShell {
		return
	}
	for _, l := range s.logicalLines() {
		m := azCommand.FindStringSubmatch(l.code)
		if m == nil {
			continue
		}
		args := m[1]
		if azFirewallRule.MatchString(args) {
			start, _ := azFlag(args, "--start-ip-address")
			end, _ := azFlag(args, "--end-ip-address")
			s.databaseAccess(s.me, start+"-"+end, l.n)
			continue
		}
		for _, c := range azCreates {
			if !c.cmd.MatchString(args) {
				continue
			}
			var verb []string
			for _, w := range strings.Fields(args) {
				if strings.HasPrefix(w, "-") {
					break
				}
				verb = append(verb, w)
			}
			name, _ := azFlag(args, "--name", "-n")
			if name == "" {
				name = c.friendly
			}
			id := "azure." + c.kind + "." + name
			s.g.AddNode(&model.Node{ID: id, Name: name, Kind: c.kind, Friendly: c.friendly, Code: "az " + strings.Join(verb, " "),
				Category: model.Network, File: s.f.Path, Line: l.n})
			s.g.Connect(s.me, id, "", false)

			switch c.kind {
			case "database":
				if v, ok := azFlag(args, "--public-access"); ok {
					s.databaseAccess(id, v, l.n)
				}
			case "storage":
				if v, ok := azFlag(args, "--allow-blob-public-access"); ok && strings.EqualFold(v, "true") {
					s.g.Expose(id, "public read", true)
					s.g.Add(model.High, id, "Files can be made public",
						"--allow-blob-public-access true lets containers in this account be opened to anyone on the internet. Leave it out, or set it to false.", s.f.Path, l.n)
				}
			case "vm":
				rule, named := azFlag(args, "--nsg-rule")
				if strings.EqualFold(rule, "none") {
					break
				}
				if v, ok := azFlag(args, "--public-ip-address"); ok && v == "" {
					break // no public address
				}
				port := 22
				if image, _ := azFlag(args, "--image"); strings.EqualFold(rule, "rdp") || (!named && windowsImage.MatchString(image)) {
					port = 3389
				}
				portName, _ := risk.PortName(port)
				why := fmt.Sprintf("az vm create opens port %d to every address by default, even though no port is named here", port)
				if named {
					why = fmt.Sprintf("--nsg-rule %s opens port %d to every address, not just yours", rule, port)
				}
				s.g.Expose(id, fmt.Sprintf("port %d", port), true)
				s.g.Add(model.High, id, fmt.Sprintf("%s (port %d) is open to the internet", portName, port),
					why+", and bots find open login ports within minutes. Use --nsg-rule NONE, then allow the port only from your own IP address with az network nsg rule create … --source-address-prefixes.", s.f.Path, l.n)
			}
		}
	}
}

// databaseAccess checks which addresses may reach a database: "all" or a
// range over every address is the whole internet, "0.0.0.0" all of Azure.
func (s *scan) databaseAccess(id, value string, ln int) {
	switch v := strings.ToLower(strings.TrimSpace(value)); v {
	case "all", "0.0.0.0-255.255.255.255":
		if id != s.me {
			s.g.Expose(id, "all addresses", true)
		}
		s.g.Add(model.High, id, "Database open to the whole internet",
			"This lets every IP address in the world try to connect to the database. Allow only the addresses that need it, such as your own, or use private access in a virtual network.", s.f.Path, ln)
	case "0.0.0.0", "0.0.0.0-0.0.0.0", "azureservices":
		s.g.Add(model.Medium, id, "Database open to all of Azure",
			"This allows every Azure service to connect, including services owned by other customers. Prefer private access in a virtual network.", s.f.Path, ln)
	}
}

// --- Files --------------------------------------------------------------

var sensitiveFiles = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`\.ssh[/\\]|id_rsa|id_ed25519|id_ecdsa`), "your SSH keys"},
	{regexp.MustCompile(`\.aws[/\\]credentials|\.aws[/\\]config`), "your AWS credentials"},
	{regexp.MustCompile(`\.azure[/\\]|msal_token_cache|accessTokens\.json`), "your Azure login"},
	{regexp.MustCompile(`\.config[/\\]gcloud`), "your Google Cloud login"},
	{regexp.MustCompile(`\.kube[/\\]config`), "your Kubernetes credentials"},
	{regexp.MustCompile(`\.docker[/\\]config\.json`), "your Docker registry login"},
	{regexp.MustCompile(`\.git-credentials|\.netrc|\.npmrc|\.pypirc`), "saved passwords for Git or package registries"},
	{regexp.MustCompile(`/etc/shadow|/etc/passwd|/etc/sudoers`), "the system's user and password files"},
	{regexp.MustCompile(`(?i)Login Data|Cookies|Local State|Web Data|logins\.json|key4\.db|cookies\.sqlite`), "saved browser passwords or cookies"},
	{regexp.MustCompile(`(?i)wallet\.dat|Exodus|Electrum|MetaMask|keystore[/\\]UTC--`), "a cryptocurrency wallet"},
	{regexp.MustCompile(`(?i)\.env['"]|['"]\.env\b`), "your .env file with secrets"},
	{regexp.MustCompile(`(?i)Microsoft[/\\]Credentials|Windows[/\\]Vault|\bvaultcmd\b`), "Windows saved credentials"},
	{regexp.MustCompile(`(?i)\bkeychain\b|security\s+find-generic-password`), "the macOS keychain"},
}

var (
	deleteDangerous = regexp.MustCompile(`\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f?|-[a-zA-Z]*f[a-zA-Z]*r)[a-zA-Z]*\s+(--no-preserve-root\s+)?("?(/|~|\$HOME|\$\{HOME\})"?/?\*?(\s|$)|"?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"?/?\*?(\s|$))`)
	deleteAny       = regexp.MustCompile(`\brm\s+-[a-zA-Z]*r|shutil\.rmtree\(|os\.(remove|unlink|rmdir)\(|\.unlink\(|fs\.(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\(|(?i)Remove-Item\b.*-Recurse|\bdel\s+/[sq]|\brmdir\s+/s|\bformat\s+[a-z]:`)
	persistence     = []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`\.bashrc|\.zshrc|\.bash_profile|\.profile\b`), "your shell start-up file"},
		{regexp.MustCompile(`\bcrontab\b|/etc/cron`), "the scheduled tasks (cron)"},
		{regexp.MustCompile(`/etc/systemd/|systemctl\s+enable`), "the system services"},
		{regexp.MustCompile(`(?i)CurrentVersion\\+Run|Start Menu\\+Programs\\+Startup|schtasks\s+/create|Register-ScheduledTask|New-ScheduledTask`), "the programs Windows starts automatically"},
		{regexp.MustCompile(`LaunchAgents|LaunchDaemons`), "the programs macOS starts automatically"},
		{regexp.MustCompile(`\.ssh/authorized_keys`), "the list of keys allowed to log in over SSH"},
	}
	writesFile = regexp.MustCompile(`>>?\s*\S|,\s*['"][wa][b+]*['"]|writeFile|appendFile|Add-Content|Set-Content|Out-File|\btee\b|\.write\(|New-ItemProperty|Set-ItemProperty|\breg\s+add\b`)
)

func (s *scan) files() {
	reported := map[string]bool{}
	for _, sf := range sensitiveFiles {
		s.each(sf.re, func(l line, _ []string) {
			if s.f.Kind == source.Dockerfile || reported[sf.what] {
				return
			}
			reported[sf.what] = true
			s.fileNode(sf.what, "reads", l.n)
			s.sensitive = append(s.sensitive, sf.what)
			s.add(model.Medium, "Touches sensitive files", fmt.Sprintf("The code refers to %s. Make sure it has a good reason to.", sf.what), l.n)
		})
	}
	// Autostart is reported once per kind, at its first line: an installer
	// that sets up a service does it on several lines, and it may be exactly
	// what was asked for. It is how malware stays, too, so it is never left out.
	for _, p := range persistence {
		var at []int
		s.each(p.re, func(l line, _ []string) {
			if !writesFile.MatchString(l.code) && !strings.Contains(l.code, "crontab") && !strings.Contains(strings.ToLower(l.code), "schtasks") &&
				!strings.Contains(l.code, "systemctl") && !strings.Contains(l.code, "Register-ScheduledTask") && !strings.Contains(l.code, "New-ScheduledTask") {
				return
			}
			at = append(at, l.n)
		})
		if len(at) == 0 {
			continue
		}
		s.fileNode(p.what, "changes", at[0])
		where := ""
		if len(at) > 1 {
			where = fmt.Sprintf(" It does so on %d lines, starting here.", len(at))
		}
		s.add(model.Medium, "Makes something start automatically",
			fmt.Sprintf("The code changes %s, so something runs again every time you log in or the machine starts.%s That is normal for an installer that sets up a service you asked for, and it is also how malware stays on a machine. Check that you know exactly what is added.", p.what, where), at[0])
	}
	s.each(deleteDangerous, func(l line, _ []string) {
		s.fileNode("everything in a folder", "deletes", l.n)
		s.add(model.High, "Can delete everything",
			"This rm -rf deletes a whole home folder or disk, or a path taken from a variable. If the variable is empty, it can wipe far more than intended. Quote variables and check that they are set (${VAR:?}).", l.n)
	})
	s.each(deleteAny, func(l line, _ []string) {
		if deleteDangerous.MatchString(l.code) {
			return
		}
		s.fileNode("files", "deletes", l.n)
		s.add(model.Low, "Deletes files", "Check which files this line deletes, and that the path cannot be empty or point somewhere else.", l.n)
	})
}

func (s *scan) fileNode(what, label string, ln int) {
	id := "file." + what
	s.g.AddNode(&model.Node{ID: id, Name: what, Kind: "folder", Friendly: "on your computer", Category: model.Data, File: s.f.Path, Line: ln})
	s.g.Connect(s.me, id, label, label != "reads")
}

// --- Listening ports ----------------------------------------------------

var (
	pyHostAll    = regexp.MustCompile(`host\s*=\s*['"](0\.0\.0\.0|::)['"]`)
	pyPort       = regexp.MustCompile(`port\s*=\s*(\d{2,5})`)
	bindAll      = regexp.MustCompile(`\.bind\(\s*\(\s*['"](0\.0\.0\.0|::|)['"]\s*,\s*(\d{2,5})`)
	jsListen     = regexp.MustCompile(`\.listen\(\s*(\d{2,5})\s*(,\s*['"]([^'"]+)['"])?`)
	httpServer   = regexp.MustCompile(`-m\s+http\.server(\s+(\d{2,5}))?`)
	ncListen     = regexp.MustCompile(`\b(nc|ncat|netcat)\b[^|]*\s-[a-zA-Z]*l[a-zA-Z]*\b.*?(\d{2,5})?`)
	dockerPublic = regexp.MustCompile(`docker\s+run\b.*?(-p|--publish)[ =](\d{2,5}):(\d{2,5})`)
	flaskDebug   = regexp.MustCompile(`\.run\([^)]*debug\s*=\s*True`)
)

func (s *scan) listening() {
	for _, l := range s.lines {
		if pyHostAll.MatchString(l.code) {
			port := "?"
			if m := pyPort.FindStringSubmatch(l.code); m != nil {
				port = m[1]
			}
			s.listen(port, "listens on every network interface (0.0.0.0)", l.n)
		}
	}
	s.each(bindAll, func(l line, m []string) { s.listen(m[2], "binds a socket to every network interface", l.n) })
	s.each(jsListen, func(l line, m []string) {
		if h := m[3]; h == "127.0.0.1" || h == "localhost" || h == "::1" {
			return
		}
		s.listen(m[1], "listens without naming an address, which in Node.js means every network interface", l.n)
	})
	s.each(httpServer, func(l line, m []string) {
		port := m[2]
		if port == "" {
			port = "8000"
		}
		s.listen(port, "starts a web server that shares the current folder with every machine that can reach yours", l.n)
	})
	s.each(ncListen, func(l line, m []string) {
		s.add(model.High, "Opens a raw network listener",
			"netcat in listen mode accepts any connection. Combined with -e or a shell, it gives remote control of the machine.", l.n)
		s.g.Expose(s.me, "netcat", true)
	})
	s.each(dockerPublic, func(l line, m []string) {
		s.listen(m[2], "publishes a container port on every network interface (Docker also bypasses firewalls such as ufw)", l.n)
	})
	s.each(flaskDebug, func(l line, _ []string) {
		s.add(model.High, "Debug mode is on",
			"The Flask/Werkzeug debugger lets anyone who can open the page run code on your machine. Never use debug=True outside your own computer.", l.n)
		// Open to the network, the debugger makes that line the dangerous one.
		if pyHostAll.MatchString(l.code) {
			s.g.Expose(s.me, "debugger", true)
		}
	})
}

func (s *scan) listen(port, what string, ln int) {
	p := 0
	fmt.Sscan(port, &p)
	sev, risky := model.Medium, false
	title := fmt.Sprintf("Opens port %s to the network", port)
	if name, ok := risk.PortName(p); ok {
		sev, risky = model.High, true
		title = fmt.Sprintf("Opens %s (port %d) to the network", name, p)
	}
	s.add(sev, title, fmt.Sprintf("The code %s. Other machines on the network, or the internet if the machine is public, can connect. Use 127.0.0.1 if only you need it.", what), ln)
	s.g.Expose(s.me, "port "+port, risky)
}

// --- Programs it runs ---------------------------------------------------

var (
	runsProgram = regexp.MustCompile(`subprocess\.(run|call|check_call|check_output|Popen)\(|os\.(system|popen|exec\w*)\(|child_process|\b(exec|execSync|spawn|spawnSync|execFile)\(|Start-Process|\bInvoke-Command\b`)
	firstWord   = regexp.MustCompile(`(?:subprocess\.\w+|os\.system|os\.popen|exec|execSync|spawn|spawnSync|execFile|Start-Process)\(?\s*\[?\s*(?:f?['"` + "`" + `])([A-Za-z0-9_.\-/]+)`)
	shellTrue   = regexp.MustCompile(`shell\s*=\s*True`)
	jsShellExec = regexp.MustCompile(`(^|[^.\w])(exec|execSync)\(`)
	importLine  = regexp.MustCompile(`\brequire\(\s*['"]|^\s*import\b|^\s*from\s+\S+\s+import\b`)
	openPort    = regexp.MustCompile(`\baz\s+vm\s+open-port\b.*--port\s+['"]?([0-9*,-]+)`)
	interesting = set(`curl wget ssh scp rsync sftp ftp nc ncat netcat socat nmap az aws gcloud kubectl helm terraform
	docker podman git sudo su chmod chown chattr mount useradd usermod passwd crontab systemctl powershell pwsh
	cmd reg regsvr32 rundll32 mshta certutil bitsadmin wmic schtasks netsh iptables ufw setenforce openssl gpg base64 python python3 node npm pip pip3 npx
	sh bash zsh dash apt apt-get dnf yum apk snap brew choco winget`)
	destructiveCLI = []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`\baz\s+group\s+delete\b`), "deletes a whole Azure resource group and everything in it"},
		{regexp.MustCompile(`\baws\s+s3\s+rb\b.*--force|\baws\s+s3\s+rm\b.*--recursive`), "deletes an S3 bucket's contents"},
		{regexp.MustCompile(`\bkubectl\s+delete\b`), "deletes Kubernetes resources"},
		{regexp.MustCompile(`\bterraform\s+destroy\b`), "destroys everything Terraform manages"},
		{regexp.MustCompile(`\bterraform\s+apply\b.*-auto-approve`), "changes real infrastructure without asking first"},
		{regexp.MustCompile(`\bgit\s+push\b.*(--force|-f\b)`), "overwrites history on the remote repository"},
		{regexp.MustCompile(`(?i)\bDROP\s+(DATABASE|TABLE)\b`), "deletes a database or table"},
	}
	cliSecretFlag = regexp.MustCompile(`--(admin-password|password|client-secret|secret|token|access-key|secret-key|sas-token|account-key)[= ]+['"]?([^\s'"]+)`)
)

func (s *scan) programsRun() {
	shellLike := s.f.Kind == source.Shell || s.f.Kind == source.PowerShell || s.f.Kind == source.Dockerfile
	for _, l := range s.lines {
		var tools []string
		if strings.HasPrefix(l.code, "#!") {
			continue // the shebang names the shell that reads the file; it runs nothing itself
		}
		if shellLike {
			for _, part := range regexp.MustCompile(`&&|\|\||;|\||\$\(|\bRUN\b`).Split(l.code, -1) {
				f := strings.Fields(part)
				for len(f) > 0 && (f[0] == "sudo" || f[0] == "exec" || f[0] == "then" || f[0] == "do" || strings.Contains(f[0], "=")) {
					if f[0] == "sudo" {
						tools = append(tools, "sudo")
						// Skip sudo's own options, so "sudo -E bash" runs bash.
						for len(f) > 1 && strings.HasPrefix(f[1], "-") {
							if opt := f[1]; (opt == "-u" || opt == "-g") && len(f) > 2 {
								f = f[1:]
							}
							f = f[1:]
						}
					}
					f = f[1:]
				}
				if len(f) > 0 {
					tools = append(tools, filepath.Base(strings.Trim(f[0], `"'(`)))
				}
			}
		} else if runsProgram.MatchString(l.code) && !importLine.MatchString(l.code) {
			if m := firstWord.FindStringSubmatch(l.code); m != nil {
				tools = append(tools, filepath.Base(m[1]))
			} else {
				tools = append(tools, "other programs")
			}
			glued := strings.Contains(l.code, "f\"") || strings.Contains(l.code, "f'") || strings.Contains(l.code, "+") ||
				strings.Contains(l.code, "format(") || strings.Contains(l.code, "${")
			if glued && (shellTrue.MatchString(l.code) || (s.f.Kind == source.JavaScript && jsShellExec.MatchString(l.code))) {
				s.add(model.Medium, "Command built from text",
					"A shell command is glued together from text. If any part comes from a user or a file, an attacker can add their own commands. Pass the program and its arguments as a list instead (execFile, or subprocess without shell=True).", l.n)
			}
		}
		for _, t := range tools {
			name := strings.ToLower(strings.TrimSuffix(t, ".exe"))
			// In a shell script every line runs a program; show the notable
			// ones. Elsewhere running a program is notable in itself.
			if shellLike && !interesting[name] {
				continue
			}
			s.programs++
			id := "program." + name
			s.g.AddNode(&model.Node{ID: id, Name: name, Kind: "terminal", Friendly: "program it runs", Category: model.Security, File: s.f.Path, Line: l.n})
			s.g.Connect(s.me, id, "", false)
		}
		for _, d := range destructiveCLI {
			if d.re.MatchString(l.code) {
				s.add(model.High, "Destructive command", fmt.Sprintf("This line %s. Make sure it points at the right place before running it, and never run it in a loop or with a variable you have not checked.", d.what), l.n)
			}
		}
		if m := openPort.FindStringSubmatch(l.code); m != nil {
			// az vm open-port allows the port from any address.
			risk.OpenPorts(s.g, s.me, strings.Split(m[1], ","), s.f.Path, l.n)
		}
		if m := cliSecretFlag.FindStringSubmatch(l.code); m != nil && !strings.HasPrefix(m[2], "$") {
			risk.CheckSecret(s.g, s.me, m[1], m[2], s.f.Path, l.n, "read it from an environment variable or a key vault, and avoid passing secrets on the command line where they end up in shell history")
		}
	}
}

// --- Packages -----------------------------------------------------------

var (
	pyImport    = regexp.MustCompile(`^\s*(?:import\s+([A-Za-z_][\w]*)|from\s+([A-Za-z_][\w]*)[\w.]*\s+import\b)`)
	pyImportCSV = regexp.MustCompile(`^\s*import\s+(.+)$`)
	jsImport    = regexp.MustCompile(`(?:require\(\s*|import\s*\(\s*|\bfrom\s+|^\s*import\s+)['"]([^'"]+)['"]`)
	pipInstall  = regexp.MustCompile(`\bpip3?\s+install\s+([^|;&\n]+)`)
	npmInstall  = regexp.MustCompile(`\b(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install|i)|npx)\s+([^|;&\n]+)`)
)

func (s *scan) packagesUsed() {
	switch s.f.Kind {
	case source.Python:
		for _, l := range s.lines {
			if m := pyImportCSV.FindStringSubmatch(l.code); m != nil && strings.Contains(m[1], ",") {
				for _, part := range strings.Split(m[1], ",") {
					name := strings.Fields(strings.TrimSpace(part) + " ")[0]
					s.pyPackage(strings.Split(name, ".")[0], l.n)
				}
				continue
			}
			if m := pyImport.FindStringSubmatch(l.code); m != nil {
				s.pyPackage(m[1]+m[2], l.n)
			}
		}
	case source.JavaScript:
		s.each(jsImport, func(l line, m []string) {
			name := m[1]
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "node:") || strings.HasPrefix(name, "http") {
				return
			}
			parts := strings.Split(name, "/")
			if strings.HasPrefix(name, "@") && len(parts) > 1 {
				name = parts[0] + "/" + parts[1]
			} else {
				name = parts[0]
			}
			if nodeBuiltins[name] {
				return
			}
			s.pkg(name, "npm", "uses", l.n)
		})
	}
	s.each(pipInstall, func(l line, m []string) {
		for _, name := range PipInstallArgs(m[1]) {
			s.pkg(name, "pip", "installs", l.n)
		}
	})
	s.each(npmInstall, func(l line, m []string) {
		for _, name := range NpmInstallArgs(m[1], strings.HasPrefix(strings.TrimSpace(m[0]), "npx")) {
			s.pkg(name, "npm", "installs", l.n)
		}
	})
}

// pipOptionWithValue are pip options whose next word is not a package.
var pipOptionWithValue = map[string]bool{
	"-r": true, "--requirement": true, "-c": true, "--constraint": true, "-e": true, "--editable": true,
	"-i": true, "--index-url": true, "--extra-index-url": true, "-f": true, "--find-links": true,
	"-t": true, "--target": true, "--prefix": true, "--root": true, "--platform": true,
	"--python-version": true, "--trusted-host": true, "--proxy": true, "--cache-dir": true,
}

var versionSpec = regexp.MustCompile(`[<>=!~\[;@].*`)

// PipInstallArgs returns the package names in the words after "pip install".
func PipInstallArgs(args string) []string {
	var out []string
	words := strings.Fields(args)
	for i := 0; i < len(words); i++ {
		w := words[i]
		if pipOptionWithValue[w] {
			i++ // skip the option's value, e.g. -r requirements.txt
			continue
		}
		if strings.HasPrefix(w, "-") || strings.ContainsAny(w, "/\\$") || strings.HasSuffix(w, ".txt") || strings.HasSuffix(w, ".whl") {
			continue
		}
		if name := strings.Trim(versionSpec.ReplaceAllString(w, ""), `"'`); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// NpmInstallArgs returns the package names in the words after "npm install",
// "yarn add" and the like. npx runs a single package: the first word that
// is not an option; the words after it are that program's own arguments.
func NpmInstallArgs(args string, npx bool) []string {
	var out []string
	for _, w := range strings.Fields(args) {
		if strings.HasPrefix(w, "-") {
			continue
		}
		if strings.HasPrefix(w, ".") || strings.HasPrefix(w, "$") || strings.Contains(w, "://") || strings.HasPrefix(w, "git+") {
			if npx {
				break
			}
			continue
		}
		name := strings.Trim(w, `"'`)
		if i := strings.LastIndex(name, "@"); i > 0 {
			name = name[:i] // drop a version, keep a scope: @scope/pkg@1.2 -> @scope/pkg
		}
		out = append(out, name)
		if npx {
			break
		}
	}
	return out
}

func (s *scan) pyPackage(module string, ln int) {
	if module == "" || pythonStdlib[strings.ToLower(module)] || s.local[module] {
		return
	}
	name := module
	if pip, ok := pythonImportToPip[module]; ok {
		name = pip
	}
	s.pkg(name, "pip", "uses", ln)
}

func (s *scan) pkg(name, registry, label string, ln int) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	key := registry + ":" + strings.ToLower(name)
	if _, done := s.packages[key]; done {
		return
	}
	s.packages[key] = ln

	popular := pythonPopular
	site := "pypi.org/project/" + name
	if registry == "npm" {
		popular = npmPopular
		site = "npmjs.com/package/" + name
	}
	friendly := registry + " package"
	known := popular[strings.ToLower(name)] || popular[normalize(name)]
	if like, ok := lookalike(name, popular); ok && !known {
		friendly = "looks like " + like
		s.add(model.Medium, fmt.Sprintf("Package name looks like a misspelling of %q", like),
			fmt.Sprintf("%q is one or two letters away from the well-known package %q. Attackers publish packages with names like this, hoping for typos. Check the name, then look it up on %s before installing.", name, like, site), ln)
	} else if !known {
		friendly = "not on our well-known list"
	}
	id := "pkg." + key
	s.g.AddNode(&model.Node{ID: id, Name: name, Kind: "package", Friendly: friendly, Category: model.Other, File: s.f.Path, Line: ln})
	s.g.Connect(s.me, id, label, false)
}

// localModules are Python files next to each other, which are imported by
// name but are not packages.
func localModules(files []source.File) map[string]bool {
	m := map[string]bool{}
	for _, f := range files {
		base := filepath.Base(f.Path)
		m[strings.TrimSuffix(base, filepath.Ext(base))] = true
	}
	return m
}

// --- Secrets ------------------------------------------------------------

var (
	assignment  = regexp.MustCompile(`(?:^|[\s,{(;])\$?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*(?::|=|:=|\?\?=)\s*[rbfu]?(['"` + "`" + `])([^'"` + "`" + `\n]{4,})['"` + "`" + `]`)
	shellAssign = regexp.MustCompile(`^\s*(?:export\s+|ENV\s+|ARG\s+)?([A-Za-z_][A-Za-z0-9_]*)[= ]([^\s'"$][^\s]*)\s*$`)
	anyString   = regexp.MustCompile(`['"` + "`" + `]([^'"` + "`" + `\n]{16,})['"` + "`" + `]`)
)

func (s *scan) secrets() {
	fix := "read it from an environment variable or a secret store, and keep it out of Git"
	for _, l := range s.lines {
		found := false
		for _, m := range assignment.FindAllStringSubmatch(l.code, -1) {
			if risk.CheckSecret(s.g, s.me, m[1], m[3], s.f.Path, l.n, fix) {
				found = true
			}
		}
		if !found && (s.f.Kind == source.Shell || s.f.Kind == source.Dockerfile || s.f.Kind == source.PowerShell) {
			if m := shellAssign.FindStringSubmatch(l.code); m != nil && risk.CheckSecret(s.g, s.me, m[1], m[2], s.f.Path, l.n, fix) {
				found = true
			}
		}
		if found {
			continue
		}
		for _, m := range anyString.FindAllStringSubmatch(l.code, -1) {
			if what, ok := risk.SecretValue(m[1]); ok {
				s.add(model.High, "Secret written in the code",
					fmt.Sprintf("A string on this line looks like %s. Anyone who can see this code can use it. Remove it, revoke it, and %s.", what, fix), l.n)
				break
			}
		}
	}
}

// --- Turning protection off ---------------------------------------------

var weakening = []struct {
	re         *regexp.Regexp
	sev        model.Severity
	title, why string
}{
	{regexp.MustCompile(`verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|InsecureSkipVerify\s*:\s*true|ssl\._create_unverified_context|CERT_NONE|(?i)-SkipCertificateCheck|\bcurl\b.*\s(-k|--insecure)\b|\bwget\b.*--no-check-certificate`),
		model.Medium, "Certificate checks are turned off", "Without certificate checks, anyone on the network can pretend to be the server and read or change the traffic, including passwords."},
	{regexp.MustCompile(`(?i)Set-MpPreference\b.*-Disable|Add-MpPreference\b.*-ExclusionPath|DisableAntiSpyware|\bsetenforce\s+0\b|\bufw\s+disable\b|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|systemctl\s+(stop|disable)\s+(firewalld|apparmor|ufw)`),
		model.High, "Turns off security protection", "The code switches off antivirus, the firewall or another protection. Malware does this first. Legitimate setup scripts almost never need to."},
	{regexp.MustCompile(`(?i)Set-ExecutionPolicy\s+(Bypass|Unrestricted)|-ExecutionPolicy\s+Bypass`),
		model.Medium, "PowerShell safety check is bypassed", "This lets any PowerShell script run, signed or not. Prefer RemoteSigned, and only for the current user."},
	{regexp.MustCompile(`\bchmod\s+(-R\s+)?(0?777|a\+rwx|o\+w)\b`),
		model.Medium, "Gives everyone full access to files", "chmod 777 lets every user and process on the machine change these files. Give only the access that is needed, such as 755 or 644."},
	{regexp.MustCompile(`\bchmod\s+[ugo]*\+s\b|\bchmod\s+[0-7]?[4-7][0-7]{3}\b`),
		model.High, "Makes a program run as its owner", "The setuid bit lets anyone run this program with its owner's rights, often root."},
	{regexp.MustCompile(`(?i)(execute|query|raw)\(\s*f['"]|(execute|query)\(\s*['"][^'"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^'"]*['"]\s*(\+|%|\.format)|\b(query|execute)\(\s*` + "`" + `[^` + "`" + `]*\$\{`),
		model.Medium, "SQL built from text", "The database query is glued together from text. If any part comes from a user, they can change the query (SQL injection). Use parameters instead."},
	{regexp.MustCompile(`(?i)\bpickle\.loads?\(|yaml\.load\((?:[^)]*Loader\s*=\s*yaml\.(Unsafe)?Loader|[^,)]*\))`),
		model.Medium, "Loads data in an unsafe way", "pickle and yaml.load can run code hidden in the data. Only load data you created yourself, or use json / yaml.safe_load."},
}

var (
	sudoRe      = regexp.MustCompile(`^\s*sudo\b|[;&|]\s*sudo\b`)
	dockerGroup = regexp.MustCompile(`\busermod\b[^;&|]*\s-\w*G\w*\s+(?:\S+,)*docker\b|\bgpasswd\s+-a\s+\S+\s+docker\b|\badduser\s+\S+\s+docker\b`)
)

func (s *scan) weakening() {
	for _, w := range weakening {
		s.each(w.re, func(l line, _ []string) {
			if w.title == "Loads data in an unsafe way" && strings.Contains(l.code, "safe_load") {
				return
			}
			s.add(w.sev, w.title, w.why, l.n)
		})
	}
	if s.f.Kind == source.Shell {
		// One finding for the whole script: install scripts use sudo on
		// almost every line, and one note per line drowns the real risks.
		var sudoLines []int
		for _, l := range s.lines {
			if sudoRe.MatchString(l.code) {
				sudoLines = append(sudoLines, l.n)
			}
		}
		switch len(sudoLines) {
		case 0:
		case 1:
			s.add(model.Low, "Runs with admin rights", "sudo runs this line as root, so a mistake here can affect the whole machine.", sudoLines[0])
		default:
			s.add(model.Low, "Runs with admin rights",
				fmt.Sprintf("sudo runs %d lines as root, starting here, so a mistake in any of them can affect the whole machine.", len(sudoLines)), sudoLines[0])
		}
		s.each(dockerGroup, func(l line, _ []string) {
			s.add(model.Medium, "User can take over the machine through Docker",
				"Members of the docker group can start a container that mounts the whole disk, and so become root without a password. Only add users who may be root anyway, or use rootless Docker.", l.n)
		})
	}
}

// --- Dockerfile ---------------------------------------------------------

var (
	fromLine   = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)`)
	userLine   = regexp.MustCompile(`(?i)^\s*USER\s+(\S+)`)
	exposeLine = regexp.MustCompile(`(?i)^\s*EXPOSE\s+(.+)`)
	addURL     = regexp.MustCompile(`(?i)^\s*ADD\s+https?://`)
)

func (s *scan) dockerfile() {
	lastUser := ""
	for _, l := range s.lines {
		if m := fromLine.FindStringSubmatch(l.code); m != nil {
			img := m[1]
			if img != "scratch" && !strings.Contains(img, "@sha256:") && (!strings.Contains(img[strings.LastIndex(img, "/")+1:], ":") || strings.HasSuffix(img, ":latest")) {
				s.add(model.Low, "Base image version is not pinned", fmt.Sprintf("%q can change under you on the next build. Pin a version.", img), l.n)
			}
			lastUser = ""
		}
		if m := userLine.FindStringSubmatch(l.code); m != nil {
			lastUser = m[1]
		}
		if m := exposeLine.FindStringSubmatch(l.code); m != nil {
			for _, p := range strings.Fields(m[1]) {
				p = strings.Split(p, "/")[0]
				n := 0
				fmt.Sscan(p, &n)
				if name, ok := risk.PortName(n); ok {
					s.add(model.Medium, fmt.Sprintf("Image exposes %s (port %d)", name, n), risk.PortAdvice(n), l.n)
				}
			}
		}
		if addURL.MatchString(l.code) {
			s.add(model.Low, "Downloads a file without checking it", "ADD with a URL downloads whatever is there at build time. Use curl with a checksum, or COPY a file you have checked.", l.n)
		}
	}
	if lastUser == "" || lastUser == "root" || lastUser == "0" {
		s.add(model.Medium, "Container runs as root", "The image never switches to a normal user, so everything in the container runs as root. Add a USER line with an unprivileged user.", len(s.lines))
	}
}

// --- Combined patterns ----------------------------------------------------

func (s *scan) combined() {
	if len(s.sensitive) == 0 || len(s.destinations) == 0 {
		return
	}
	what := unique(s.sensitive)
	sort.Strings(what)
	s.add(model.High, "Reads secrets and talks to the internet",
		fmt.Sprintf("The same code reads %s and connects to %s. That is exactly what programs that steal passwords and keys do. Do not run it until you understand both parts.", strings.Join(what, ", "), strings.Join(s.destinations, ", ")), 1)
}

func unique(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range list {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
