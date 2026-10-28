package script

import (
	"regexp"
	"strings"
)

// boto3 is AWS from Python. Each call on a boto3 client is turned into the
// aws command line it corresponds to, so the AWS rules for scripts read both:
//
//	db = rds.create_db_instance(DBInstanceIdentifier="shop", PubliclyAccessible=True)
//
// becomes
//
//	$db = aws rds create-db-instance --db-instance-identifier shop --publicly-accessible
//
// The call's own text follows at the end, for the rules that look for
// policies and ARNs inside it.

var (
	// ec2 = boto3.client("ec2"), s3 = session.resource('s3', region_name=…)
	boto3Client = regexp.MustCompile(`(\w+)\s*=\s*[\w.]*\b(?:client|resource)\(\s*(?:service_name\s*=\s*)?['"]([\w-]+)['"]`)
	boto3Call   = regexp.MustCompile(`(?:\b(\w+)\s*=\s*)?\b(\w+)\.(\w+)\(`)
	camelWord   = regexp.MustCompile(`([a-z0-9])([A-Z])|([A-Z]+)([A-Z][a-z])`)
	identStart  = regexp.MustCompile(`^[A-Za-z_]\w*`)
	pyNameTag   = regexp.MustCompile(`['"]Key['"]\s*:\s*['"]Name['"]\s*,\s*['"]Value['"]\s*:\s*['"]([^'"]+)['"]`)
	pyProto     = regexp.MustCompile(`['"]IpProtocol['"]\s*:\s*['"]([\w-]+)['"]`)
	pyFromPort  = regexp.MustCompile(`['"]FromPort['"]\s*:\s*(-?\d+)`)
	pyToPort    = regexp.MustCompile(`['"]ToPort['"]\s*:\s*(-?\d+)`)
	pyCidr      = regexp.MustCompile(`['"]CidrIp(?:v6)?['"]\s*:\s*['"]([^'"]+)['"]`)
)

func (s *scan) boto3Lines() []line {
	// The code as one text, with where each line starts, since calls often
	// span several lines.
	var b strings.Builder
	starts := make([]int, len(s.lines))
	for i, l := range s.lines {
		starts[i] = b.Len()
		b.WriteString(l.code)
		b.WriteByte('\n')
	}
	text := b.String()
	lineAt := func(pos int) int {
		n := 1
		for i, st := range starts {
			if st <= pos {
				n = s.lines[i].n
			}
		}
		return n
	}

	clients := map[string]string{} // variable -> service
	for _, m := range boto3Client.FindAllStringSubmatch(text, -1) {
		clients[m[1]] = m[2]
	}
	if len(clients) == 0 {
		return nil
	}

	var out []line
	for _, idx := range boto3Call.FindAllStringSubmatchIndex(text, -1) {
		client := text[idx[4]:idx[5]]
		service, ok := clients[client]
		if !ok {
			continue
		}
		open := idx[1] - 1
		end := closing(text, open)
		if end < 0 {
			continue
		}
		args := text[open+1 : end]
		method := text[idx[6]:idx[7]]
		if service == "s3" {
			service = "s3api" // boto3's s3 client is the aws s3api command
		}
		cmd := "aws " + service + " " + strings.ReplaceAll(method, "_", "-") + " " + flags(args) + " " + strings.Join(strings.Fields(args), " ")
		if idx[2] >= 0 {
			cmd = "$" + text[idx[2]:idx[3]] + " = " + cmd
		}
		out = append(out, line{lineAt(idx[0]), cmd})
	}
	return out
}

// closing finds the parenthesis that closes the one at open, skipping
// strings, or -1.
func closing(text string, open int) int {
	depth := 0
	var quote byte
	for i := open; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// topLevel splits call arguments at the commas that are not inside
// brackets or strings.
func topLevel(args string) []string {
	var parts []string
	depth, last := 0, 0
	var quote byte
	for i := 0; i < len(args); i++ {
		c := args[i]
		switch {
		case quote != 0:
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, args[last:i])
			last = i + 1
		}
	}
	return append(parts, args[last:])
}

// flags turns Python keyword arguments into aws command line options.
func flags(args string) string {
	var out []string
	for _, part := range topLevel(args) {
		key, value, ok := strings.Cut(part, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || !identStart.MatchString(key) || strings.HasPrefix(value, "=") {
			continue
		}
		flag := "--" + kebab(key)
		switch {
		case value == "True":
			out = append(out, flag)
		case value == "False":
			out = append(out, "--no-"+kebab(key))
		case strings.HasPrefix(value, "'") || strings.HasPrefix(value, `"`):
			v := strings.Trim(value, `'"`)
			if strings.ContainsAny(v, " \t") {
				v = `"` + v + `"`
			}
			out = append(out, flag, v)
		case strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{"):
			out = append(out, nested(flag, value)...)
		default:
			// A number, or a variable such as vpc["Vpc"]["VpcId"]: the
			// rules follow variables by their name.
			if id := identStart.FindString(value); id != "" && id != "None" {
				out = append(out, flag, "$"+id)
			} else {
				out = append(out, flag, value)
			}
		}
	}
	return strings.Join(out, " ")
}

// nested writes the parts of lists and dicts that the rules look at in the
// aws command line's shorthand.
func nested(flag, value string) []string {
	switch flag {
	case "--ip-permissions":
		var perms []string
		for _, seg := range strings.Split(value, "IpProtocol")[1:] {
			seg = "'IpProtocol" + seg
			p := pyProto.FindStringSubmatch(seg)
			if p == nil {
				continue
			}
			from, to := "", ""
			if m := pyFromPort.FindStringSubmatch(seg); m != nil {
				from = ",FromPort=" + m[1]
			}
			if m := pyToPort.FindStringSubmatch(seg); m != nil {
				to = ",ToPort=" + m[1]
			}
			for _, c := range pyCidr.FindAllStringSubmatch(seg, -1) {
				perms = append(perms, "IpProtocol="+p[1]+from+to+",IpRanges=[{CidrIp="+c[1]+"}]")
			}
		}
		return append([]string{flag}, perms...)
	case "--tag-specifications", "--tags":
		if m := pyNameTag.FindStringSubmatch(value); m != nil {
			return []string{flag, "Key=Name,Value=" + m[1]}
		}
	case "--resources", "--security-group-ids", "--subnet-ids":
		inner := strings.TrimSpace(strings.Trim(value, "[]"))
		if id := identStart.FindString(inner); id != "" {
			return []string{flag, "$" + id}
		}
	}
	return nil
}

// kebab turns PubliclyAccessible into publicly-accessible and
// DBInstanceIdentifier into db-instance-identifier.
func kebab(s string) string {
	s = camelWord.ReplaceAllString(s, "$1$3-$2$4")
	s = camelWord.ReplaceAllString(s, "$1$3-$2$4")
	return strings.ToLower(s)
}
