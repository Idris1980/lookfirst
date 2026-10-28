package cloudformation

import (
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
