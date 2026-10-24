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

func TestGuessName(t *testing.T) {
	cases := map[string]string{
		"resource \"azurerm_resource_group\" \"rg\" {\n  name = \"x\"\n}":                        "main.tf",
		"param location string\nresource sa 'Microsoft.Storage/storageAccounts@2023-05-01' = {}": "main.bicep",
		"services:\n  web:\n    image: nginx\n":                                                  "docker-compose.yml",
		"apiVersion: v1\nkind: Service\n":                                                        "manifest.yaml",
		"FROM node:22\nRUN npm ci\n":                                                             "Dockerfile",
		"#!/bin/bash\necho hi":                                                                   "script.sh",
		"curl -fsSL https://x.sh | sudo bash\n":                                                  "script.sh",
		"import os\nprint(os.getcwd())":                                                          "script.py",
		"const express = require('express');":                                                    "script.js",
		"Write-Host 'hello'":                                                                     "script.ps1",
		"{\n  \"name\": \"x\",\n  \"dependencies\": {}\n}":                                       "package.json",
		"requests==2.32.3\nflask>=3.0\n":                                                         "requirements.txt",
		"hello there":                                                                            "",
	}
	for text, want := range cases {
		if got := GuessName(text); got != want {
			t.Errorf("GuessName(%q) = %q, want %q", text, got, want)
		}
	}
}
