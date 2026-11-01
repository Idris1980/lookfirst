package advice

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

func all() []Advice {
	var out []Advice
	for _, a := range exact {
		out = append(out, a)
	}
	for _, p := range patterns {
		out = append(out, p.advice)
	}
	return out
}

func TestEveryAdviceIsComplete(t *testing.T) {
	for _, a := range all() {
		if a.Story == "" || len(a.Fix) == 0 {
			t.Errorf("advice without story or fix: %+v", a)
		}
		for _, r := range append(append(append([]Ref{}, a.AWS...), a.Azure...), a.More...) {
			if r.Label == "" || !strings.HasPrefix(r.URL, "https://") {
				t.Errorf("bad reference %+v", r)
			}
		}
	}
}

func TestTitlesWithValuesAreFound(t *testing.T) {
	for _, title := range []string{
		"SSH (port 22) is open to the internet",
		"Remote Desktop (RDP) (port 3389) is open to the internet (only in AWS)",
		"PostgreSQL is published on every network interface",
		"Port 8080 is published on every network interface",
		"Web traffic (port 443) is allowed from the internet",
		`Package name looks like a misspelling of "requests"`,
		"AWS adds a resource the code does not name",
	} {
		if _, ok := For(title); !ok {
			t.Errorf("no advice for %q", title)
		}
	}
	if a, _ := For("SSH (port 22) is open to the internet"); len(a.Refs("aws")) == 0 || a.Refs("aws")[0].URL != "https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-19" {
		t.Errorf("SSH should point at AWS control EC2.19 first: %+v", a.Refs("aws"))
	}
}

// LOOKFIRST_PRINT_REFS=1 go test ./internal/advice -run TestPrintRefs -v
// lists every link, so they can be checked against the live sites.
func TestPrintRefs(t *testing.T) {
	if os.Getenv("LOOKFIRST_PRINT_REFS") == "" {
		t.Skip("set LOOKFIRST_PRINT_REFS=1 to list the links")
	}
	seen := map[string]bool{}
	for _, a := range all() {
		for _, r := range append(append(append([]Ref{}, a.AWS...), a.Azure...), a.More...) {
			seen[r.URL] = true
		}
	}
	var urls []string
	for u := range seen {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	for _, u := range urls {
		fmt.Println("URL", u)
	}
}
