package source

import "testing"

func TestDetect(t *testing.T) {
	cases := []struct {
		path, data string
		want       Kind
	}{
		{"main.tf", "", Terraform},
		{"infra/main.bicep", "", Bicep},
		{"azuredeploy.json", `{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"}`, ARM},
		{"settings.json", `{"a": 1}`, ""},
		{"docker-compose.yml", "", Compose},
		{"compose.prod.yaml", "", Compose},
		{"stack.yml", "services:\n  web:\n    image: x\n", Compose},
		{"deploy.yaml", "apiVersion: v1\nkind: Service\n", Kubernetes},
		{"config.yaml", "a: 1\n", ""},
		{"Dockerfile", "", Dockerfile},
		{"api.Dockerfile", "", Dockerfile},
		{"package.json", "{}", NpmManifest},
		{"requirements-dev.txt", "", PipRequirements},
		{"notes.txt", "", ""},
		{"run", "#!/usr/bin/env python3\n", Python},
		{"deploy", "#!/bin/bash\n", Shell},
		{"README", "hello", ""},
	}
	for _, c := range cases {
		if got := Detect(c.path, []byte(c.data)); got != c.want {
			t.Errorf("Detect(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}
