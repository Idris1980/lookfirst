package render

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/model"
)

// Every icon a rule names exists, and every icon file is safe to inline.
func TestCloudIcons(t *testing.T) {
	names := []string{"aws-subnet", "aws-subnet-private"}
	for _, r := range cloudIconRules {
		if r.icon != "" {
			names = append(names, r.icon)
		}
	}
	for _, n := range names {
		if _, ok := iconSymbol(n); !ok {
			t.Errorf("icon %q is missing or unreadable", n)
		}
	}
	fs.WalkDir(cloudIconFiles, "cloudicons", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}
		data, _ := cloudIconFiles.ReadFile(path)
		lower := strings.ToLower(string(data))
		for _, bad := range []string{"<script", "javascript:", "onload=", "onclick=", `href="http`, "<foreignobject"} {
			if strings.Contains(lower, bad) {
				t.Errorf("%s contains %q", path, bad)
			}
		}
		return nil
	})
}

func TestCloudIconChoice(t *testing.T) {
	cases := []struct {
		node model.Node
		want string
	}{
		{model.Node{Cloud: "aws", Kind: "vm", Friendly: "EC2 server"}, "aws-ec2"},
		{model.Node{Cloud: "aws", Kind: "database", Friendly: "DynamoDB table"}, "aws-dynamodb"},
		{model.Node{Cloud: "aws", Kind: "subnet", Name: "novatrix-private-a"}, "aws-subnet-private"},
		{model.Node{Cloud: "aws", Kind: "subnet", Name: "PublicSubnet"}, "aws-subnet"},
		{model.Node{Cloud: "azure", Kind: "firewall", Friendly: "SQL firewall rule"}, ""},
		{model.Node{Cloud: "azure", Kind: "plan", Friendly: "App Service plan"}, "azure-appserviceplan"},
		{model.Node{Kind: "vm", Friendly: "virtual machine"}, ""}, // no cloud: LookFirst's own icon
	}
	for _, c := range cases {
		if got := cloudIconFor(&c.node); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.node, got, c.want)
		}
	}
}
