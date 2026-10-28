// Package awstry turns CloudFormation's answer to a change set into a
// template, so it can be read with the same rules as the code. A change set
// for a new stack builds nothing and costs nothing; it says what
// CloudFormation would create, after parameters are filled in and transforms
// such as SAM have added their own resources.
package awstry

import (
	"encoding/json"
	"fmt"
)

// Resource is one resource the change set would create.
type Resource struct {
	Name       string
	Type       string
	Properties map[string]any
}

type changeSet struct {
	Status       string
	StatusReason string
	Changes      []struct {
		Type           string
		ResourceChange struct {
			Action            string
			LogicalResourceId string
			ResourceType      string
			// With --include-property-values: {"Properties": {...}} as a string.
			AfterContext string
		}
	}
}

// ChangeSet reads the answer of
// aws cloudformation describe-change-set --include-property-values --output json.
func ChangeSet(data []byte) ([]Resource, error) {
	var cs changeSet
	if err := json.Unmarshal(data, &cs); err != nil {
		return nil, fmt.Errorf("CloudFormation's answer could not be read: %w", err)
	}
	if cs.Status == "FAILED" {
		return nil, fmt.Errorf("CloudFormation could not make a change set: %s", cs.StatusReason)
	}
	var out []Resource
	for _, c := range cs.Changes {
		rc := c.ResourceChange
		if c.Type != "Resource" || rc.Action == "Remove" || rc.ResourceType == "" {
			continue
		}
		r := Resource{Name: rc.LogicalResourceId, Type: rc.ResourceType}
		if rc.AfterContext != "" {
			var after struct{ Properties map[string]any }
			if err := json.Unmarshal([]byte(rc.AfterContext), &after); err == nil {
				r.Properties = after.Properties
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// Template writes the resources as a CloudFormation template in JSON.
func Template(resources []Resource) ([]byte, error) {
	res := map[string]any{}
	for _, r := range resources {
		body := map[string]any{"Type": r.Type}
		if r.Properties != nil {
			body["Properties"] = r.Properties
		}
		res[r.Name] = body
	}
	return json.MarshalIndent(map[string]any{"AWSTemplateFormatVersion": "2010-09-09", "Resources": res}, "", "  ")
}
