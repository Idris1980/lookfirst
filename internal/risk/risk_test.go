package risk

import "testing"

func TestSecretName(t *testing.T) {
	secret := []string{"password", "admin_password", "DB_PASSWORD", "api_key", "apiKey", "client_secret",
		"GITHUB_TOKEN", "connection_string", "administratorLoginPassword", "sas_token", "private_key"}
	notSecret := []string{"storageAccountConnectionStringName", "password_hint", "key_vault_secret_id",
		"tokenType", "token_type", "password_min_length", "secret_name", "admin_username", "public_key",
		"TOKEN_TTL", "POSTGRES_PASSWORD_FILE", "next_token", "password_policy", "location", "sassy"}
	for _, n := range secret {
		if !SecretName(n) {
			t.Errorf("SecretName(%q) = false, want true", n)
		}
	}
	for _, n := range notSecret {
		if SecretName(n) {
			t.Errorf("SecretName(%q) = true, want false", n)
		}
	}
}

func TestSecretValue(t *testing.T) {
	for _, v := range []string{"AKIAIOSFODNN7EXAMPLE", "-----BEGIN RSA PRIVATE KEY-----",
		"postgres://app:hunter2@db:5432/app", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"} {
		if _, ok := SecretValue(v); !ok {
			t.Errorf("SecretValue(%q) found nothing", v)
		}
	}
	for _, v := range []string{"hello world", "https://example.com", "postgres://db:5432/app"} {
		if what, ok := SecretValue(v); ok {
			t.Errorf("SecretValue(%q) = %q, want nothing", v, what)
		}
	}
}

func TestPlaceholder(t *testing.T) {
	for _, v := range []string{"", "${DB_PASSWORD}", "$TOKEN", "<your-key>", "xxxx", "{{ .Values.pw }}"} {
		if !Placeholder(v) {
			t.Errorf("Placeholder(%q) = false", v)
		}
	}
	if Placeholder("hunter2") {
		t.Error(`Placeholder("hunter2") = true`)
	}
}

func TestPortRange(t *testing.T) {
	cases := []struct {
		in     string
		lo, hi int
		ok     bool
	}{
		{"22", 22, 22, true},
		{"8000-8010", 8000, 8010, true},
		{"*", 0, 0, false},
		{"abc", 0, 0, false},
	}
	for _, c := range cases {
		lo, hi, ok := PortRange(c.in)
		if lo != c.lo || hi != c.hi || ok != c.ok {
			t.Errorf("PortRange(%q) = %d, %d, %v; want %d, %d, %v", c.in, lo, hi, ok, c.lo, c.hi, c.ok)
		}
	}
}

func TestFromAnywhere(t *testing.T) {
	if !FromAnywhere([]string{"10.0.0.0/8", "0.0.0.0/0"}) || !FromAnywhere([]string{"Internet"}) {
		t.Error("everyone was not recognised")
	}
	if FromAnywhere([]string{"10.0.0.0/8", "VirtualNetwork"}) {
		t.Error("a private range was taken for everyone")
	}
}
