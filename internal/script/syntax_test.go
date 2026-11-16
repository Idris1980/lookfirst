package script

import (
	"testing"

	"github.com/Idris1980/lookfirst/internal/source"
)

// The parsers get the text that was read, not the file on disk, and as
// UTF-8: a PowerShell script with a byte order mark and å, ä and ö in it is
// fine, and a script that is not on disk at all is checked too.
func TestSyntaxReadsTheTextAsUTF8(t *testing.T) {
	ok := "\xef\xbb\xbf# Bygger miljön åt kunden, på svenska\n" +
		"param([string]$Kund = \"hellas\")\n" +
		"Write-Host \"Klart. Sov den när du är klar: .\\sova.ps1 -Kund $Kund\"\n"
	g := Read([]source.File{{Path: "finns-inte-på-disken.ps1", Kind: source.PowerShell, Data: []byte(ok)}})
	for _, f := range g.Findings {
		if f.Title == "Syntax error" {
			t.Errorf("a correct script with å, ä and ö got: %s (line %d)", f.Detail, f.Line)
		}
	}
	if firstFound("bash") == "" {
		return
	}
	broken := "#!/bin/bash\nif [ -f x ]; then\n  echo hej\n"
	g = Read([]source.File{{Path: "finns-inte.sh", Kind: source.Shell, Data: []byte(broken)}})
	found := false
	for _, f := range g.Findings {
		found = found || f.Title == "Syntax error"
	}
	if !found {
		t.Error("an unfinished if in a script that is not on disk should be a syntax error")
	}
}
