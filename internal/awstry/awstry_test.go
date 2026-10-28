package awstry

import (
	"testing"

	"github.com/Idris1980/lookfirst/internal/azuretry"
	"github.com/Idris1980/lookfirst/internal/cloudformation"
	"github.com/Idris1980/lookfirst/internal/source"
)

// A SAM template names one function; the change set shows the role and the
// URL the transform adds, and the parameter filled in.
const answer = `{
  "Status": "CREATE_COMPLETE",
  "Changes": [
    {"Type": "Resource", "ResourceChange": {"Action": "Add", "LogicalResourceId": "Api", "ResourceType": "AWS::Lambda::Function",
      "AfterContext": "{\"Properties\":{\"Runtime\":\"python3.12\",\"Role\":\"{{changeSet:KNOWN_AFTER_APPLY}}\"}}"}},
    {"Type": "Resource", "ResourceChange": {"Action": "Add", "LogicalResourceId": "ApiRole", "ResourceType": "AWS::IAM::Role",
      "AfterContext": "{\"Properties\":{\"ManagedPolicyArns\":[\"arn:aws:iam::aws:policy/AdministratorAccess\"]}}"}},
    {"Type": "Resource", "ResourceChange": {"Action": "Add", "LogicalResourceId": "ApiUrl", "ResourceType": "AWS::Lambda::Url",
      "AfterContext": "{\"Properties\":{\"AuthType\":\"NONE\",\"TargetFunctionArn\":\"x\"}}"}},
    {"Type": "Resource", "ResourceChange": {"Action": "Remove", "LogicalResourceId": "Old", "ResourceType": "AWS::S3::Bucket"}}
  ]
}`

func TestChangeSetIsReadWithTheSameRules(t *testing.T) {
	resources, err := ChangeSet([]byte(answer))
	if err != nil {
		t.Fatal(err)
	}
	if len(resources) != 3 {
		t.Fatalf("got %d resources, want 3 (the removal is left out)", len(resources))
	}
	tpl, err := Template(resources)
	if err != nil {
		t.Fatal(err)
	}
	aws := cloudformation.Read([]source.File{{Path: "AWS", Kind: source.CloudFormation, Data: tpl}})

	code := cloudformation.Read([]source.File{{Path: "template.yaml", Kind: source.CloudFormation, Data: []byte(
		"Transform: AWS::Serverless-2016-10-31\nResources:\n  Api:\n    Type: AWS::Lambda::Function\n    Properties:\n      Runtime: python3.12\n")}})

	diff := azuretry.CompareIn("AWS", code, aws, "CloudFormation's preview")
	titles := map[string]bool{}
	for _, f := range diff.Findings {
		titles[f.Title] = true
	}
	for _, want := range []string{
		"AWS adds a resource the code does not name",
		"Full control of the AWS account (only in AWS)",
		"Function is open on the internet without login (only in AWS)",
	} {
		if !titles[want] {
			t.Errorf("missing %q; got %v", want, titles)
		}
	}
}

func TestFailedChangeSet(t *testing.T) {
	if _, err := ChangeSet([]byte(`{"Status": "FAILED", "StatusReason": "Template format error"}`)); err == nil {
		t.Error("a failed change set should be an error")
	}
}
