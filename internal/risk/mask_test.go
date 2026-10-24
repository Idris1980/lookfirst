package risk

import (
	"strings"
	"testing"
)

func TestMask(t *testing.T) {
	cases := []struct {
		in      string
		gone    []string // must not be in the masked text
		kept    []string // must still be there
		secrets int
	}{
		{
			in:      `admin_password = "P@ssw0rd1234!"` + "\n" + `admin_username = "azureuser"`,
			gone:    []string{"P@ssw0rd1234!"},
			kept:    []string{"admin_password", "azureuser"},
			secrets: 1,
		},
		{
			in:      "export DB_PASSWORD=Sup3rS3cret!\naz vm create --admin-password \"Winter2026!\" -n vm1",
			gone:    []string{"Sup3rS3cret!", "Winter2026!"},
			kept:    []string{"DB_PASSWORD", "--admin-password", "vm1"},
			secrets: 2,
		},
		{
			in:      `provider "aws" { access_key = "AKIAIOSFODNN7EXAMPLE" }`,
			gone:    []string{"AKIAIOSFODNN7EXAMPLE"},
			secrets: 1,
		},
		{
			in:      "DATABASE_URL: postgres://app:hunter2@db:5432/app\nPOSTGRES_PASSWORD: hunter2",
			gone:    []string{"hunter2"},
			kept:    []string{"db:5432/app"},
			secrets: 2,
		},
		{
			in:      "variable \"sql_admin_password\" {\n  type    = string\n  default = \"SuperSecret123!\"\n}",
			gone:    []string{"SuperSecret123!"},
			kept:    []string{"sql_admin_password", "default"},
			secrets: 1,
		},
		{
			in:      "env:\n  - name: DB_PASSWORD\n    value: \"P@ssw0rd!\"\n  - name: LOG_LEVEL\n    value: debug",
			gone:    []string{"P@ssw0rd!"},
			kept:    []string{"DB_PASSWORD", "debug"},
			secrets: 1,
		},
		{
			// References and placeholders are not secrets and must stay, so
			// the model can see how the code gets its values.
			in:      "admin_password = var.admin_password\nPOSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\napi_key = os.environ[\"API_KEY\"]\npassword_min_length = 16",
			kept:    []string{"var.admin_password", "${POSTGRES_PASSWORD}", `os.environ["API_KEY"]`, "16"},
			secrets: 0,
		},
	}
	for _, c := range cases {
		out, originals := Mask(c.in)
		for _, g := range c.gone {
			if strings.Contains(out, g) {
				t.Errorf("Mask(%q) kept %q:\n%s", c.in, g, out)
			}
		}
		for _, k := range c.kept {
			if !strings.Contains(out, k) {
				t.Errorf("Mask(%q) lost %q:\n%s", c.in, k, out)
			}
		}
		if len(originals) != c.secrets {
			t.Errorf("Mask(%q) found %d secrets, want %d: %v", c.in, len(originals), c.secrets, originals)
		}
		// Putting the originals back gives the text we started with.
		back := out
		for tok, v := range originals {
			back = strings.ReplaceAll(back, tok, v)
		}
		if back != c.in {
			t.Errorf("unmasking does not give the original:\n%s\n%s", back, c.in)
		}
	}
}

func TestMaskUnknownAndMultiLineKeys(t *testing.T) {
	in := "key = \"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBxZ3JhbmRvbWtleWRhdGFmb3J0ZXN0aW5nb25seQAAAJgAAAAAAAAAAA==\n-----END OPENSSH PRIVATE KEY-----\"\n" +
		"webhook = \"T09ABCDEF/B01GHIJKLM/xYz7Qw3Er5Ty9Ui1Op4As6Df\"\n" +
		"image = \"mcr.microsoft.com/azure-cli:2.65.0\"\nhelp = \"https://learn.microsoft.com/azure/storage\""
	out, _ := Mask(in)
	for _, gone := range []string{"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "QyNTUxOQAAACBxZ3JhbmRvbWtleWRhdGFmb3J0ZXN0", "xYz7Qw3Er5Ty9Ui1Op4As6Df"} {
		if strings.Contains(out, gone) {
			t.Errorf("kept %q:\n%s", gone, out)
		}
	}
	for _, kept := range []string{"mcr.microsoft.com/azure-cli:2.65.0", "https://learn.microsoft.com/azure/storage"} {
		if !strings.Contains(out, kept) {
			t.Errorf("lost %q:\n%s", kept, out)
		}
	}
}

func TestMaskSameValueSameToken(t *testing.T) {
	out, originals := Mask("A_PASSWORD=hunter22\nB_PASSWORD=hunter22")
	if len(originals) != 1 || strings.Count(out, "«SECRET_1»") != 2 {
		t.Errorf("one value should get one token: %q %v", out, originals)
	}
}
