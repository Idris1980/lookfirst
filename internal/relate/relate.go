// Package relate says what a reference from one cloud resource to another
// means: one calls or reads the other (a flow), may use it through a role
// or policy (access), runs on or sits in it (hosting), or must only be
// created after it (order). Every reader of infrastructure code uses it, so
// a line means the same in a Terraform, CloudFormation or ARM picture, for
// AWS and for Azure.
package relate

import (
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// Meaning returns the label and kind of a line, from the setting that holds
// the reference (such as "subnet_id", "Role" or "DependsOn") and the cloud
// types of what it is in and what it points at (such as "aws_s3_bucket" or
// "AWS::SQS::Queue"). An unknown reference gives "uses", a flow.
func Meaning(setting, fromType, toType string) (string, string) {
	s := strings.ToLower(setting)
	f := strings.ToLower(fromType)
	t := strings.ToLower(toType)
	has := func(text string, words ...string) bool {
		for _, w := range words {
			if strings.Contains(text, w) {
				return true
			}
		}
		return false
	}
	switch {
	case s == "depends_on" || s == "dependson":
		return "", model.Order
	// A part that only holds settings of another, such as aws_s3_bucket_acl
	// or AWS::S3::BucketPolicy for a bucket.
	case t != "" && f != t && strings.HasPrefix(f, t):
		return "settings for", model.Hosting

	// Where a thing runs, what it sits in, who it runs as.
	case has(t, "subnet") && !has(t, "association", "group"):
		return "in subnet", model.Hosting
	case has(t, "_vpc", "::vpc", "virtual_network", "virtualnetworks") && !has(t, "endpoint", "peering", "attachment"):
		return "in network", model.Hosting
	case has(t, "security_group", "securitygroup", "network_security_group", "networksecuritygroups"):
		return "protected by", model.Hosting
	case has(t, "service_plan", "app_service_plan", "serverfarms"):
		return "runs on", model.Hosting
	case has(t, "iam_role", "::iam::role", "instance_profile", "instanceprofile"):
		return "runs as", model.Hosting
	case has(t, "user_assigned_identity", "userassignedidentities", "managedidentity"):
		return "signs in as", model.Hosting
	case has(t, "kms_key", "::kms::key", "key_vault_key"):
		return "encrypted with", model.Hosting
	case has(t, "network_interface", "networkinterface"):
		return "network card", model.Hosting
	case has(t, "public_ip", "eip", "publicipaddress"):
		return "public address", model.Hosting
	case has(t, "route_table", "routetable", "nat_gateway", "natgateway", "internet_gateway", "internetgateway"):
		return "routes through", model.Hosting
	case has(t, "cluster") && has(t, "ecs", "eks", "kubernetes", "aks"):
		return "runs in", model.Hosting

	// A policy or permission that names a thing gives access to it.
	case has(s, "policy", "permission", "principal") || has(t, "iam_policy", "::iam::policy", "role_assignment", "roleassignment"):
		return "may use", model.Access

	// What it talks to at run time.
	case has(t, "s3_bucket", "::s3::bucket", "storage_account", "storageaccounts", "storage_container", "efs", "file_system"):
		return "reads and writes data in", model.Flow
	case has(t, "db_instance", "rds", "dynamodb", "sql", "postgres", "mysql", "cosmos", "documentdb", "elasticache", "redis", "docdb", "neptune", "aurora"):
		return "uses data in", model.Flow
	case has(t, "sqs", "sns", "servicebus", "service_bus", "eventhub", "event_hub", "kinesis", "eventgrid", "event_grid", "eventbridge", "msk"):
		return "sends messages to", model.Flow
	case has(t, "secretsmanager", "secrets_manager", "ssm_parameter", "::ssm::parameter", "key_vault", "keyvault"):
		return "reads secrets from", model.Flow
	case has(t, "cloudwatch", "log_group", "loggroup", "log_analytics", "operationalinsights", "application_insights", "insights", "monitor"):
		return "sends logs to", model.Flow
	case has(t, "ecr", "container_registry", "containerregistry"):
		return "pulls its image from", model.Flow
	case has(t, "target_group", "targetgroup", "backend"):
		return "forwards to", model.Flow
	case has(t, "lambda_function", "::lambda::function", "function_app", "functionapp", "linux_web_app", "windows_web_app", "web/sites", "app_service", "instance", "container", "ecs_service", "::ecs::service"):
		return "calls", model.Flow
	}
	return "uses", model.Flow
}
