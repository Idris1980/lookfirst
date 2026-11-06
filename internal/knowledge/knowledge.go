// Package knowledge is what LookFirst knows about every resource type in
// Azure and AWS, taken from Microsoft's and Amazon's own published lists
// and refreshed by `go run ./internal/knowledge/gen` (every week, by a
// scheduled workflow). It is built into the program, so reading code never
// goes on the internet.
package knowledge

import (
	_ "embed"
	"encoding/json"
	"strings"
	"sync"
)

//go:embed azure.json
var azureJSON []byte

//go:embed aws.json
var awsJSON []byte

type list struct {
	Updated string            `json:"updated"`
	Version string            `json:"version"`
	Types   map[string]string `json:"types"`
	lower   map[string]string // lower-case type -> as written in the list
}

var (
	once       sync.Once
	azure, aws list
)

func load() {
	once.Do(func() {
		for _, l := range []struct {
			data []byte
			into *list
		}{{azureJSON, &azure}, {awsJSON, &aws}} {
			_ = json.Unmarshal(l.data, l.into)
			l.into.lower = map[string]string{}
			for t := range l.into.Types {
				l.into.lower[strings.ToLower(t)] = t
			}
		}
	})
}

// Updated is the day the lists were last taken from Microsoft and Amazon.
func Updated() (azureDay, awsDay string) {
	load()
	return azure.Updated, aws.Updated
}

// AzureType reports whether Azure has a resource type, and its newest API
// version.
func AzureType(t string) (newest string, ok bool) {
	load()
	name, ok := azure.lower[strings.ToLower(t)]
	if !ok {
		return "", false
	}
	return azure.Types[name], true
}

// AzureDocs is Microsoft's reference page for a resource type.
func AzureDocs(t string) string {
	return "https://learn.microsoft.com/en-us/azure/templates/" + strings.ToLower(t)
}

// AWSType reports whether AWS has a CloudFormation resource type, and its
// page in Amazon's documentation.
func AWSType(t string) (docs string, ok bool) {
	load()
	name, ok := aws.lower[strings.ToLower(t)]
	if !ok {
		return "", false
	}
	return strings.Replace(aws.Types[name], "http://", "https://", 1), true
}

// Counts are how many types each list holds, for the report to say.
func Counts() (azureTypes, awsTypes int) {
	load()
	return len(azure.Types), len(aws.Types)
}
