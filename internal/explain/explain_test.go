package explain

import "testing"

func TestPlural(t *testing.T) {
	cases := map[string]string{
		"virtual machine":       "2 virtual machines",
		"public IP address":     "2 public IP addresses",
		"Application Insights":  "2 Application Insights",
		"SQL connection policy": "2 SQL connection policies",
		"folder on the host":    "2 folders on the host",
		"gateway":               "2 gateways",
	}
	for word, want := range cases {
		if got := plural(2, word); got != want {
			t.Errorf("plural(2, %q) = %q, want %q", word, got, want)
		}
	}
	if got := plural(1, "virtual machine"); got != "1 virtual machine" {
		t.Errorf("plural(1) = %q", got)
	}
}
