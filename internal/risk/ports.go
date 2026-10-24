// Package risk holds the rules that every reader shares: which ports are
// dangerous to open, and what a secret looks like.
package risk

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

var anywhere = map[string]bool{"*": true, "0.0.0.0/0": true, "::/0": true, "internet": true, "any": true}

// FromAnywhere reports whether any of the source addresses means "everyone".
func FromAnywhere(sources []string) bool {
	for _, s := range sources {
		if anywhere[strings.ToLower(strings.TrimSpace(s))] {
			return true
		}
	}
	return false
}

// knownPorts are risky to open, named by what usually listens on them.
var knownPorts = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB file sharing", 1433: "SQL Server",
	2375: "Docker API", 2376: "Docker API", 3306: "MySQL", 3389: "Remote Desktop (RDP)",
	5432: "PostgreSQL", 5985: "WinRM", 5986: "WinRM", 6379: "Redis", 9200: "Elasticsearch",
	11211: "Memcached", 27017: "MongoDB",
}

// PortName returns what usually listens on a risky port.
func PortName(p int) (string, bool) {
	name, ok := knownPorts[p]
	return name, ok
}

// OpenPorts reports ports that a rule opens to the whole internet and draws
// the line from the internet to the node. A spec is "22", "8000-8010", "*"
// for every port, or "?" when the value comes from somewhere we cannot see.
func OpenPorts(g *model.Graph, nodeID string, specs []string, file string, line int) {
	risky := false
	for _, spec := range specs {
		lo, hi, ok := PortRange(spec)
		switch {
		case spec == "?":
			g.Add(model.Medium, nodeID, "A port is open to the internet",
				"Traffic from anywhere is allowed, but the port comes from a variable we cannot see. Check which value it gets.", file, line)
		case !ok || (lo <= 1 && hi >= 65535):
			risky = true
			g.Add(model.High, nodeID, "Every port is open to the internet",
				"Anyone on the internet can reach every service here. Open only the ports you need, and only to the addresses that need them.", file, line)
		default:
			named := false
			for p := lo; p <= hi; p++ {
				if name, isKnown := knownPorts[p]; isKnown {
					named, risky = true, true
					g.Add(model.High, nodeID, fmt.Sprintf("%s (port %d) is open to the internet", name, p), PortAdvice(p), file, line)
				}
			}
			if named {
				continue
			}
			if lo == hi && (lo == 80 || lo == 443) {
				g.Add(model.Low, nodeID, fmt.Sprintf("Web traffic (port %d) is allowed from the internet", lo),
					"This is normal for a public website. Make sure that is what you want.", file, line)
				continue
			}
			g.Add(model.Medium, nodeID, fmt.Sprintf("Port %s is open to the internet", spec),
				"Anyone on the internet can reach whatever listens on this port. Limit the source to the addresses that need it.", file, line)
		}
	}
	g.Expose(nodeID, PortLabel(specs), risky)
}

func PortAdvice(p int) string {
	switch p {
	case 22, 3389, 5985, 5986, 23:
		return "Anyone on the internet can try to log in, and bots find open login ports within minutes. Allow only your own IP address, or use a bastion host or VPN."
	case 1433, 3306, 5432, 6379, 27017, 9200, 11211:
		return "A database should never be reachable from the whole internet. Allow only the addresses that need it, or use a private endpoint."
	case 2375, 2376:
		return "Whoever reaches the Docker API controls every container on the machine, and the machine itself."
	default:
		return "This service is a common target for attacks and should not face the internet. Remove the rule or limit the source address."
	}
}

// PortRange parses "22" or "8000-8010". It returns false for "*" and for
// anything it cannot read.
func PortRange(spec string) (lo, hi int, ok bool) {
	if spec == "*" || spec == "" {
		return 0, 0, false
	}
	a, b, isRange := strings.Cut(spec, "-")
	lo, err := strconv.Atoi(strings.TrimSpace(a))
	if err != nil {
		return 0, 0, false
	}
	hi = lo
	if isRange {
		if hi, err = strconv.Atoi(strings.TrimSpace(b)); err != nil {
			return 0, 0, false
		}
	}
	return lo, hi, true
}

func PortLabel(specs []string) string {
	var out []string
	for _, s := range specs {
		switch s {
		case "*":
			out = append(out, "all ports")
		case "?":
			out = append(out, "port ?")
		default:
			out = append(out, "port "+s)
		}
	}
	return strings.Join(out, ", ")
}
