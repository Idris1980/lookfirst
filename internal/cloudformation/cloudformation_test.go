package cloudformation

import (
	"strings"
	"testing"

	"github.com/Idris1980/lookfirst/internal/source"
)

// The JSON form, with the long way of referring ({"Ref": …}, Fn::GetAtt),
// a security group rule of its own, and a SAM function with a public URL.
func TestJSONAndSAM(t *testing.T) {
	text := `{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Transform": "AWS::Serverless-2016-10-31",
  "Resources": {
    "Sg": { "Type": "AWS::EC2::SecurityGroup", "Properties": { "GroupDescription": "x" } },
    "Rdp": {
      "Type": "AWS::EC2::SecurityGroupIngress",
      "Properties": { "GroupId": { "Fn::GetAtt": ["Sg", "GroupId"] }, "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "CidrIp": "0.0.0.0/0" }
    },
    "Server": { "Type": "AWS::EC2::Instance", "Properties": { "SecurityGroupIds": [{ "Ref": "Sg" }] } },
    "Fn": {
      "Type": "AWS::Serverless::Function",
      "Properties": { "Runtime": "python3.12", "FunctionUrlConfig": { "AuthType": "NONE" } }
    },
    "Queue": { "Type": "AWS::SQS::Queue" },
    "QueuePolicy": {
      "Type": "AWS::SQS::QueuePolicy",
      "Properties": {
        "Queues": [{ "Ref": "Queue" }],
        "PolicyDocument": { "Statement": [{ "Effect": "Allow", "Principal": { "AWS": "*" }, "Action": "sqs:SendMessage", "Resource": "*" }] }
      }
    },
    "Admin": {
      "Type": "AWS::IAM::Policy",
      "Properties": { "PolicyDocument": { "Statement": { "Effect": "Allow", "Action": "*", "Resource": "*" } } }
    }
  }
}`
	g := Read([]source.File{{Path: "template.json", Kind: source.CloudFormation, Data: []byte(text)}})
	found := map[string]string{}
	for _, f := range g.Findings {
		found[f.Title] = f.NodeID
	}
	want := map[string]string{
		"Remote Desktop (RDP) (port 3389) is open to the internet": "cfn.Sg",    // the rule's own group
		"Function is open on the internet without login":           "cfn.Fn",    // SAM
		"Anyone can access it":                                     "cfn.Queue", // the queue the policy is for
		"Permission to do everything":                              "cfn.Admin",
	}
	for title, node := range want {
		if got, ok := found[title]; !ok || got != node {
			t.Errorf("%q on %q, want on %q (found: %v)", title, got, node, found)
		}
	}
	linked := false
	for _, e := range g.Edges {
		linked = linked || (e.From == "cfn.Server" && e.To == "cfn.Sg")
	}
	if !linked {
		t.Errorf("no line from the server to its security group: %v", g.Edges)
	}
	for _, hidden := range []string{"cfn.Rdp", "cfn.QueuePolicy"} {
		if g.Node(hidden) != nil {
			t.Errorf("%s is plumbing and should not be drawn", hidden)
		}
	}
}

// The YAML short forms !Ref, !GetAtt and !Sub, and a type the catalog does
// not know, which is still drawn with a name made from its type.
func TestShortFormsAndUnknownTypes(t *testing.T) {
	text := "Resources:\n" +
		"  Stream:\n    Type: AWS::Kinesis::Stream\n" +
		"  Pipe:\n    Type: AWS::Pipes::Pipe\n    Properties:\n      Source: !GetAtt Stream.Arn\n      Target: !Sub \"arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:${Queue}\"\n" +
		"  Queue:\n    Type: AWS::SQS::Queue\n"
	g := Read([]source.File{{Path: "t.yaml", Kind: source.CloudFormation, Data: []byte(text)}})
	if n := g.Node("cfn.Pipe"); n == nil || n.Friendly != "Pipes pipe" {
		t.Errorf("unknown type drawn as %+v, want \"Pipes pipe\"", n)
	}
	edges := map[string]bool{}
	for _, e := range g.Edges {
		edges[e.From+">"+e.To] = true
	}
	if !edges["cfn.Pipe>cfn.Stream"] || !edges["cfn.Pipe>cfn.Queue"] {
		t.Errorf("!GetAtt and !Sub did not give lines: %v", g.Edges)
	}
}

// What happens to data when the stack is deleted, the old metadata service,
// and the script a server runs when it starts.
func TestDeletionMetadataAndUserData(t *testing.T) {
	text := `AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  OldAmi:
    Type: String
    Default: ami-123
Resources:
  GoneDb:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties: {Engine: mysql}
  SafeDb:
    Type: AWS::RDS::DBInstance
    Properties: {Engine: mysql}
  Files:
    Type: AWS::EFS::FileSystem
  OpenTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        ImageId: !Ref OldAmi
        MetadataOptions: {HttpTokens: optional}
  OldServer:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: !Ref OldAmi
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          curl -sS https://example.com/x
`
	f := source.File{Path: "t.yaml", Kind: source.CloudFormation, Data: []byte(text)}
	g := Read([]source.File{f})
	count := map[string]int{}
	for _, x := range g.Findings {
		count[x.Title+"|"+x.NodeID]++
	}
	for _, want := range []string{
		"Database is deleted without a final copy|cfn.GoneDb",
		"Old metadata service is on|cfn.OpenTemplate",
		"Old metadata service may be on|cfn.OldServer",
	} {
		if count[want] != 1 {
			t.Errorf("want one %q, got %v", want, count)
		}
	}
	if count["Database is deleted without a final copy|cfn.SafeDb"] != 0 {
		t.Error("a database with AWS's default keeps a final snapshot")
	}
	for id, want := range map[string]string{"cfn.GoneDb": "lost", "cfn.SafeDb": "snapshot", "cfn.Files": "lost"} {
		if n := g.Node(id); n == nil || n.OnDelete != want {
			t.Errorf("%s: want OnDelete %q, got %+v", id, want, n)
		}
	}
	st := Startups(f)
	if len(st) != 1 || st[0].Node != "cfn.OldServer" || !strings.Contains(st[0].Text, "curl -sS https://example.com/x") {
		t.Fatalf("user data: %+v", st)
	}
	// The script's second line is line 30 of the template.
	if lines := strings.Split(text, "\n"); !strings.Contains(lines[st[0].Offset+2-1], "curl") {
		t.Errorf("offset %d does not point at the script's lines", st[0].Offset)
	}
}
