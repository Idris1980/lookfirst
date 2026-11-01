package relate

import (
	"testing"

	"github.com/Idris1980/lookfirst/internal/model"
)

func TestMeaning(t *testing.T) {
	for _, c := range []struct{ setting, from, to, label, kind string }{
		{"depends_on", "aws_instance", "aws_s3_bucket", "", model.Order},
		{"DependsOn", "AWS::EC2::Instance", "AWS::EC2::VPC", "", model.Order},
		{"subnet_id", "aws_instance", "aws_subnet", "in subnet", model.Hosting},
		{"VpcId", "AWS::EC2::Subnet", "AWS::EC2::VPC", "in network", model.Hosting},
		{"vpc_security_group_ids", "aws_instance", "aws_security_group", "protected by", model.Hosting},
		{"Role", "AWS::Lambda::Function", "AWS::IAM::Role", "runs as", model.Hosting},
		{"service_plan_id", "azurerm_linux_web_app", "azurerm_service_plan", "runs on", model.Hosting},
		{"bucket", "aws_s3_bucket_acl", "aws_s3_bucket", "settings for", model.Hosting},
		{"Bucket", "AWS::S3::BucketPolicy", "AWS::S3::Bucket", "settings for", model.Hosting},
		{"policy", "aws_iam_policy", "aws_s3_bucket", "may use", model.Access},
		{"variables", "aws_lambda_function", "aws_s3_bucket", "reads and writes data in", model.Flow},
		{"Environment", "AWS::Lambda::Function", "AWS::SQS::Queue", "sends messages to", model.Flow},
		{"Environment", "AWS::Lambda::Function", "AWS::DynamoDB::Table", "uses data in", model.Flow},
		{"app_settings", "azurerm_linux_function_app", "azurerm_key_vault", "reads secrets from", model.Flow},
		{"TargetFunctionArn", "AWS::Lambda::Url", "AWS::Lambda::Function", "calls", model.Flow},
		{"x", "aws_thing", "aws_other_thing", "uses", model.Flow},
	} {
		label, kind := Meaning(c.setting, c.from, c.to)
		if label != c.label || kind != c.kind {
			t.Errorf("%s in %s to %s: got %q %s, want %q %s", c.setting, c.from, c.to, label, kind, c.label, c.kind)
		}
	}
}
