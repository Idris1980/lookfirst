// Package azuretry compares what a Bicep or ARM template says with what
// Azure would actually build, or did build, from it. The code alone does
// not show Azure's own defaults, what modules add, or values that are only
// known when the template is deployed; Azure's answer does.
//
// The calls to Azure go through the az command line with the user's own
// login. This package only shapes and compares the answers.
package azuretry

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Resource is one resource as Azure describes it, from what-if or from
// "az resource show".
type Resource struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Location   string         `json:"location"`
	Kind       string         `json:"kind,omitempty"`
	Properties map[string]any `json:"properties"`
}

// Template turns resources into an ARM template, so the same rules that
// read the code can read what Azure answered.
func Template(resources []Resource) ([]byte, error) {
	type res struct {
		Type       string         `json:"type"`
		APIVersion string         `json:"apiVersion"`
		Name       string         `json:"name"`
		Location   string         `json:"location,omitempty"`
		Kind       string         `json:"kind,omitempty"`
		Properties map[string]any `json:"properties"`
	}
	t := struct {
		Schema         string `json:"$schema"`
		ContentVersion string `json:"contentVersion"`
		Resources      []res  `json:"resources"`
	}{
		Schema:         "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		ContentVersion: "1.0.0.0",
	}
	for _, r := range resources {
		if r.Type == "" {
			continue
		}
		props := r.Properties
		if props == nil {
			props = map[string]any{}
		}
		t.Resources = append(t.Resources, res{
			Type: r.Type, APIVersion: "2023-01-01", Name: NameFromID(r.ID, r.Type, r.Name),
			Location: r.Location, Kind: r.Kind, Properties: props,
		})
	}
	return json.MarshalIndent(t, "", "  ")
}

// NameFromID gives a resource's full name as a template writes it: "sql-demo"
// for a server, "sql-demo/AllowAll" for its firewall rule. Azure sometimes
// returns only the last part in "name", so the ID is the safer source.
//
//	/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/sql-demo/firewallRules/AllowAll
func NameFromID(id, typ, fallback string) string {
	_, rest, ok := strings.Cut(id, "/providers/")
	if !ok {
		return fallback
	}
	parts := strings.Split(rest, "/")
	types := strings.Split(typ, "/") // e.g. Microsoft.Sql, servers, firewallRules
	if len(types) < 2 || len(parts) < 2*len(types)-1 {
		return fallback
	}
	// parts: Microsoft.Sql, servers, sql-demo, firewallRules, AllowAll
	var names []string
	for i := 2; i < len(parts) && i < 2*len(types); i += 2 {
		names = append(names, parts[i])
	}
	if len(names) == 0 {
		return fallback
	}
	return strings.Join(names, "/")
}

// WhatIf reads the JSON from "az deployment group what-if --no-pretty-print"
// and returns the resources as they would be after the deployment.
func WhatIf(data []byte) ([]Resource, error) {
	var w struct {
		Status  string `json:"status"`
		Changes []struct {
			ResourceID string    `json:"resourceId"`
			ChangeType string    `json:"changeType"`
			After      *Resource `json:"after"`
		} `json:"changes"`
		Properties *struct {
			Changes []struct {
				ResourceID string    `json:"resourceId"`
				ChangeType string    `json:"changeType"`
				After      *Resource `json:"after"`
			} `json:"changes"`
		} `json:"properties"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("could not read Azure's what-if answer: %v", err)
	}
	if w.Error != nil {
		return nil, fmt.Errorf("Azure could not preview the template: %s: %s", w.Error.Code, w.Error.Message)
	}
	changes := w.Changes
	if len(changes) == 0 && w.Properties != nil {
		changes = w.Properties.Changes
	}
	var out []Resource
	for _, c := range changes {
		if c.After == nil || c.ChangeType == "Delete" {
			continue
		}
		r := *c.After
		if r.ID == "" {
			r.ID = c.ResourceID
		}
		out = append(out, r)
	}
	return out, nil
}

// Resources reads the JSON from "az resource show --ids ..." (one object,
// or a list when several IDs are given).
func Resources(data []byte) ([]Resource, error) {
	var list []Resource
	if err := json.Unmarshal(data, &list); err == nil {
		return list, nil
	}
	var one Resource
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, fmt.Errorf("could not read Azure's list of resources: %v", err)
	}
	return []Resource{one}, nil
}
