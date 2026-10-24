package azuretry

import (
	"os"
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/arm"
	"github.com/Idris1980/lookfirst/internal/model"
	"github.com/Idris1980/lookfirst/internal/source"
)

func TestNameFromID(t *testing.T) {
	cases := []struct{ id, typ, want string }{
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/sql-demo/firewallRules/AllowAll", "Microsoft.Sql/servers/firewallRules", "sql-demo/AllowAll"},
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st1", "Microsoft.Storage/storageAccounts", "st1"},
		{"not-an-id", "Microsoft.Storage/storageAccounts", "fallback"},
	}
	for _, c := range cases {
		if got := NameFromID(c.id, c.typ, "fallback"); got != c.want {
			t.Errorf("NameFromID(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

func TestWhatIfSkipsDeletes(t *testing.T) {
	data, err := os.ReadFile("testdata/whatif.json")
	if err != nil {
		t.Fatal(err)
	}
	res, err := WhatIf(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Fatalf("got %d resources, want 2 (the delete is left out)", len(res))
	}
	if _, err := WhatIf([]byte(`{"error": {"code": "InvalidTemplate", "message": "bad"}}`)); err == nil || !strings.Contains(err.Error(), "InvalidTemplate") {
		t.Errorf("an error answer should become an error, got %v", err)
	}
}

// TestCompareFindsWhatOnlyAzureShows uses a template that says nothing about
// public access, and an answer from Azure where its defaults make the
// account public and add a firewall rule the file does not name.
func TestCompareFindsWhatOnlyAzureShows(t *testing.T) {
	tmpl, err := os.ReadFile("testdata/storage.json")
	if err != nil {
		t.Fatal(err)
	}
	code := arm.Read([]source.File{{Path: "storage.json", Kind: source.ARM, Data: tmpl}})

	answer, _ := os.ReadFile("testdata/whatif.json")
	res, err := WhatIf(answer)
	if err != nil {
		t.Fatal(err)
	}
	built, err := Template(res)
	if err != nil {
		t.Fatal(err)
	}
	azure := arm.Read([]source.File{{Path: "Azure", Kind: source.ARM, Data: built}})

	diff := Compare(code, azure, "Azure")
	titles := map[string]model.Severity{}
	for _, f := range diff.Findings {
		titles[f.Title] = f.Severity
	}
	for _, want := range []string{
		"Files can be made public (only in Azure)",
		"Old TLS version allowed (only in Azure)",
		"Database open to the whole internet (only in Azure)",
		"Azure adds a resource the code does not name",
	} {
		if _, ok := titles[want]; !ok {
			t.Errorf("missing %q; got %v", want, titles)
		}
	}
	if len(code.Findings) != 0 {
		t.Errorf("the template alone should look clean, got %v", code.Findings)
	}
}
