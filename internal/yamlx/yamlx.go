// Package yamlx reads YAML into nodes that keep their line numbers, with a
// few helpers for walking them.
package yamlx

import (
	"bytes"
	"errors"
	"io"

	"go.yaml.in/yaml/v3"
)

// Documents parses every document in a YAML stream. The parser refuses
// alias bombs on its own; the caller has already limited the file size.
func Documents(data []byte) ([]*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []*yaml.Node
	for {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, err
		}
		if len(n.Content) > 0 {
			docs = append(docs, n.Content[0])
		}
	}
}

// Get returns the value under key in a mapping, or nil.
func Get(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// Path follows several keys in turn.
func Path(n *yaml.Node, keys ...string) *yaml.Node {
	for _, k := range keys {
		n = Get(n, k)
	}
	return n
}

// Str returns a scalar's text, or "".
func Str(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func True(n *yaml.Node) bool {
	return Str(n) == "true"
}

// Items returns a sequence's items, or nil.
func Items(n *yaml.Node) []*yaml.Node {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	return n.Content
}

// Pairs calls fn for each key and value in a mapping, in file order.
func Pairs(n *yaml.Node, fn func(key, value *yaml.Node)) {
	if n == nil || n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		fn(n.Content[i], n.Content[i+1])
	}
}

// Line returns the node's line, or fallback for a missing node.
func Line(n *yaml.Node, fallback int) int {
	if n == nil {
		return fallback
	}
	return n.Line
}
