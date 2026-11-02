package script

import (
	"path"
	"regexp"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// What a script does on the computer or server it runs on: installs
// software, downloads and runs things, starts services, adds users, opens
// ports in the firewall, writes system files, starts containers. Scripts
// written by AI assistants to "set up a server" are mostly this, so it is
// part of the chain as much as what is built in a cloud.

var (
	localAsk        = regexp.MustCompile(`(?i)\bRead-Host\s+(?:-Prompt\s+)?("[^"]*"|'[^']*')|\bread\s+(?:-\S+\s+)*-p\s+("[^"]*"|'[^']*')`)
	localPkgInstall = regexp.MustCompile(`(?i)\b(apt-get|apt|yum|dnf|zypper|apk|brew|choco|winget|scoop|snap|pacman)\s+(?:-\S+\s+)*(install|add|-S)\s+(.*)`)
	localUpgrade    = regexp.MustCompile(`(?i)\b(apt-get|apt|yum|dnf)\s+(?:-\S+\s+)*(upgrade|dist-upgrade|full-upgrade)\b`)
	localNpmGlobal  = regexp.MustCompile(`\bnpm\s+(?:install|i)\s+(?:-g|--global)\s+(.*)`)
	localPip        = regexp.MustCompile(`\bpip3?\s+install\s+(.*)`)
	localPipe       = regexp.MustCompile(`(?i)\b(curl|wget|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b[^|]*?(https?://\S+)[^|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(bash|sh|zsh|python3?|iex|Invoke-Expression)`)
	localDownload   = regexp.MustCompile(`(?i)\b(curl|wget|Invoke-WebRequest|iwr)\b.*?(https?://[^\s"']+)`)
	localOutFile    = regexp.MustCompile(`(?i)(?:-o|-O|--output|-OutFile)\s+["']?([^\s"']+)`)
	localGitClone   = regexp.MustCompile(`\bgit\s+clone\s+(?:-\S+\s+)*(\S+)`)
	localService    = regexp.MustCompile(`(?i)\bsystemctl\s+(enable\s+--now|enable|start|restart)\s+(\S+)`)
	localUser       = regexp.MustCompile(`(?i)\b(useradd|adduser|New-LocalUser)\s+(?:-\S+\s+\S+\s+)*["']?([\w.-]+)`)
	localUsermod    = regexp.MustCompile(`(?i)\busermod\s+.*-aG\s+(\S+)\s+(\S+)`)
	localFirewall   = regexp.MustCompile(`(?i)\b(?:ufw\s+allow\s+(\S+)|firewall-cmd\s+.*--add-port=(\S+)|New-NetFirewallRule\b.*-LocalPort\s+(\S+)|iptables\s+.*--dport\s+(\d+))`)
	localCompose    = regexp.MustCompile(`\bdocker[ -]compose\s+(?:-f\s+(\S+)\s+)?up\b`)
	localRun        = regexp.MustCompile(`\bdocker\s+run\b(.*)`)
	localCron       = regexp.MustCompile(`(?i)\bcrontab\b|\bschtasks\s+/create\b|\bRegister-ScheduledTask\b`)
	localChmod      = regexp.MustCompile(`\bchmod\s+(?:-R\s+)?(777|666|a\+w|o\+w)\s+(\S+)`)
	localWriteSys   = regexp.MustCompile(`(?:>>?|\btee\s+(?:-a\s+)?)\s*(/etc/\S+|/usr/\S+|/var/\S+|~/\.\S+)`)
	localRemove     = regexp.MustCompile(`^\s*(?:sudo\s+)?(?:rm\s+(-\S+\s+)*(\S+)|Remove-Item\s+(?:-\S+\s+)*["']?([^\s"']+))`)
	localPolicy     = regexp.MustCompile(`(?i)\bSet-ExecutionPolicy\s+(\S+)`)
	localPM2        = regexp.MustCompile(`\bpm2\s+start\s+(\S+)`)
	localRunFile    = regexp.MustCompile(`^\s*(?:sudo\s+(?:-\S+\s+)*)?(?:sh|bash)\s+(\S+\.sh)\b`)
)

// localStep says what one line does on the machine, or returns false when
// it does nothing worth a step.
func localStep(code, here string, resolve func(string) string) (model.Step, bool) {
	st := model.Step{}
	clean := func(s string) string { return strings.Trim(strings.TrimSpace(s), `"'`) }
	words := func(s string) string {
		var out []string
		for _, w := range strings.Fields(s) {
			if strings.HasPrefix(w, "-") || strings.ContainsAny(w, "&|;>") {
				if strings.ContainsAny(w, "&|;>") {
					break
				}
				continue
			}
			out = append(out, clean(w))
		}
		return strings.Join(out, ", ")
	}
	switch {
	case localAsk.MatchString(code):
		m := localAsk.FindStringSubmatch(code)
		st.Says = "Asks you: " + clean(firstNonEmpty(m[1], m[2]))
	case compressArchive.MatchString(code):
		m := compressArchive.FindStringSubmatch(code)
		st.Says = "Packs " + strings.TrimSuffix(resolve(clean(m[1])), "/*") + " into the zip file " + path.Base(resolve(clean(m[2])))
	case localPipe.MatchString(code):
		m := localPipe.FindStringSubmatch(code)
		st.Says = "Downloads " + clean(m[2]) + " and runs it straight away, without saving or checking it"
	case localUpgrade.MatchString(code):
		st.Says = "Updates every installed package on the machine"
	case localPkgInstall.MatchString(code):
		m := localPkgInstall.FindStringSubmatch(code)
		st.Says = "Installs " + words(m[3]) + " on the machine (" + strings.ToLower(m[1]) + ")"
	case localNpmGlobal.MatchString(code):
		st.Says = "Installs " + words(localNpmGlobal.FindStringSubmatch(code)[1]) + " for everyone on the machine (npm)"
	case localPip.MatchString(code):
		st.Says = "Installs the Python packages " + words(localPip.FindStringSubmatch(code)[1])
	case localGitClone.MatchString(code):
		st.Says = "Downloads the code in " + clean(localGitClone.FindStringSubmatch(code)[1])
	case localDownload.MatchString(code):
		m := localDownload.FindStringSubmatch(code)
		st.Says = "Downloads " + clean(m[2])
		if o := localOutFile.FindStringSubmatch(code); o != nil {
			st.Says += " to " + clean(o[1])
		}
	case localRunFile.MatchString(code):
		f := clean(localRunFile.FindStringSubmatch(code)[1])
		st.Runs = resolve(f)
		st.Says = "Runs the script " + f
	case localCompose.MatchString(code):
		m := localCompose.FindStringSubmatch(code)
		f := "docker-compose.yml"
		if m[1] != "" {
			f = clean(m[1])
		}
		st.Template = path.Join(here, resolve(f))
		st.Says = "Starts the containers described in " + st.Template
	case localRun.MatchString(code):
		args := strings.Fields(localRun.FindStringSubmatch(code)[1])
		image := lastPositional(args)
		st.Says = "Starts a container from the image " + image
		for i, a := range args {
			if (a == "-p" || a == "--publish") && i+1 < len(args) {
				st.Says += ", reachable on port " + strings.Split(args[i+1], ":")[0]
			}
		}
	case localService.MatchString(code):
		m := localService.FindStringSubmatch(code)
		st.Says = "Starts the service " + clean(m[2])
		if strings.Contains(m[1], "enable") {
			st.Says += " and makes it start every time the machine starts"
		}
	case localUser.MatchString(code):
		i := localUser.FindStringIndex(code)
		name := ""
		for _, w := range strings.Fields(code[i[0]:])[1:] {
			if strings.ContainsAny(w, "&|;") {
				break
			}
			if !strings.HasPrefix(w, "-") {
				name = clean(w)
			}
		}
		st.Says = "Creates the user " + name + " on the machine"
	case localUsermod.MatchString(code):
		m := localUsermod.FindStringSubmatch(code)
		st.Says = "Adds " + clean(m[2]) + " to the group " + clean(m[1])
		if m[1] == "docker" || m[1] == "sudo" || m[1] == "wheel" {
			st.Says += ", which gives it full control of the machine"
		}
	case localFirewall.MatchString(code):
		m := localFirewall.FindStringSubmatch(code)
		st.Says = "Opens " + firstNonEmpty(m[1], m[2], m[3], m[4]) + " in the machine's firewall"
	case localCron.MatchString(code):
		st.Says = "Schedules something to run by itself, again and again"
	case localChmod.MatchString(code):
		m := localChmod.FindStringSubmatch(code)
		st.Says = "Lets everyone on the machine change " + clean(m[2])
	case localWriteSys.MatchString(code) && !strings.Contains(code, "echo \"") || localWriteSys.MatchString(code) && strings.Contains(code, "tee"):
		st.Says = "Writes to " + clean(localWriteSys.FindStringSubmatch(code)[1])
	case localPolicy.MatchString(code):
		st.Says = "Changes PowerShell's execution policy to " + localPolicy.FindStringSubmatch(code)[1]
	case localPM2.MatchString(code):
		st.Says = "Starts " + clean(localPM2.FindStringSubmatch(code)[1]) + " with pm2, which keeps it running"
	case localRemove.MatchString(code):
		m := localRemove.FindStringSubmatch(code)
		target := clean(firstNonEmpty(m[2], m[3]))
		if target == "" || strings.HasPrefix(target, "-") {
			return st, false
		}
		st.Says = "Deletes " + path.Base(resolve(target))
		st.Deletes = strings.Contains(m[1], "r") || strings.Contains(code, "-Recurse")
	default:
		return st, false
	}
	return st, true
}
