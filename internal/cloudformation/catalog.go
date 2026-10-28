package cloudformation

import (
	"regexp"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

type entry struct {
	kind     string
	friendly string
	category model.Category
}

// catalog maps the common resource types to an icon, a plain name and a
// column. Every other AWS type is still drawn, with a name made from its
// type, such as "AWS::Kinesis::Stream" -> "Kinesis stream".
var catalog = map[string]entry{
	// Network
	"AWS::EC2::VPC":                             {"network", "VPC", model.Network},
	"AWS::EC2::Subnet":                          {"subnet", "subnet", model.Network},
	"AWS::EC2::InternetGateway":                 {"globe", "internet gateway", model.Network},
	"AWS::EC2::NatGateway":                      {"globe", "NAT gateway", model.Network},
	"AWS::EC2::EIP":                             {"publicip", "public IP address", model.Network},
	"AWS::EC2::NetworkInterface":                {"nic", "network interface", model.Network},
	"AWS::EC2::VPCEndpoint":                     {"nic", "VPC endpoint", model.Network},
	"AWS::EC2::TransitGateway":                  {"network", "transit gateway", model.Network},
	"AWS::EC2::VPNGateway":                      {"network", "VPN gateway", model.Network},
	"AWS::ElasticLoadBalancingV2::LoadBalancer": {"loadbalancer", "load balancer", model.Network},
	"AWS::ElasticLoadBalancingV2::Listener":     {"loadbalancer", "load balancer listener", model.Network},
	"AWS::ElasticLoadBalancingV2::TargetGroup":  {"loadbalancer", "target group", model.Network},
	"AWS::ElasticLoadBalancing::LoadBalancer":   {"loadbalancer", "classic load balancer", model.Network},
	"AWS::CloudFront::Distribution":             {"globe", "CloudFront CDN", model.Network},
	"AWS::ApiGateway::RestApi":                  {"webapp", "API Gateway", model.Network},
	"AWS::ApiGatewayV2::Api":                    {"webapp", "API Gateway", model.Network},
	"AWS::Serverless::Api":                      {"webapp", "API Gateway", model.Network},
	"AWS::Serverless::HttpApi":                  {"webapp", "API Gateway", model.Network},
	"AWS::Route53::HostedZone":                  {"dns", "DNS zone", model.Network},
	"AWS::Route53::RecordSet":                   {"dns", "DNS record", model.Network},
	"AWS::GlobalAccelerator::Accelerator":       {"globe", "Global Accelerator", model.Network},
	"AWS::EC2::ClientVpnEndpoint":               {"network", "client VPN", model.Network},
	"AWS::AppSync::GraphQLApi":                  {"webapp", "AppSync API", model.Network},
	"AWS::Serverless::GraphQLApi":               {"webapp", "AppSync API", model.Network},
	"AWS::Lambda::Url":                          {"globe", "Lambda function URL", model.Network},

	// Security
	"AWS::EC2::SecurityGroup":              {"shield", "security group", model.Security},
	"AWS::EC2::NetworkAcl":                 {"firewall", "network ACL", model.Security},
	"AWS::WAFv2::WebACL":                   {"firewall", "web application firewall", model.Security},
	"AWS::NetworkFirewall::Firewall":       {"firewall", "network firewall", model.Security},
	"AWS::IAM::Role":                       {"identity", "IAM role", model.Security},
	"AWS::IAM::User":                       {"identity", "IAM user", model.Security},
	"AWS::IAM::Group":                      {"identity", "IAM group", model.Security},
	"AWS::IAM::Policy":                     {"identity", "IAM policy", model.Security},
	"AWS::IAM::ManagedPolicy":              {"identity", "IAM policy", model.Security},
	"AWS::IAM::InstanceProfile":            {"identity", "instance profile", model.Security},
	"AWS::IAM::AccessKey":                  {"key", "IAM access key", model.Security},
	"AWS::KMS::Key":                        {"key", "KMS key", model.Security},
	"AWS::SecretsManager::Secret":          {"key", "stored secret", model.Security},
	"AWS::SSM::Parameter":                  {"key", "Systems Manager parameter", model.Security},
	"AWS::CertificateManager::Certificate": {"key", "TLS certificate", model.Security},
	"AWS::Cognito::UserPool":               {"identity", "Cognito user pool", model.Security},
	"AWS::Cognito::IdentityPool":           {"identity", "Cognito identity pool", model.Security},
	"AWS::EC2::KeyPair":                    {"key", "SSH key pair", model.Security},
	"AWS::GuardDuty::Detector":             {"shield", "GuardDuty", model.Security},
	"AWS::CloudTrail::Trail":               {"monitor", "CloudTrail log", model.Security},

	// Compute
	"AWS::EC2::Instance":                    {"vm", "EC2 server", model.Compute},
	"AWS::EC2::LaunchTemplate":              {"vm", "launch template", model.Compute},
	"AWS::AutoScaling::AutoScalingGroup":    {"vm", "auto scaling group", model.Compute},
	"AWS::AutoScaling::LaunchConfiguration": {"vm", "launch configuration", model.Compute},
	"AWS::Lambda::Function":                 {"function", "Lambda function", model.Compute},
	"AWS::Serverless::Function":             {"function", "Lambda function", model.Compute},
	"AWS::ECS::Cluster":                     {"container", "ECS cluster", model.Compute},
	"AWS::ECS::Service":                     {"container", "ECS service", model.Compute},
	"AWS::ECS::TaskDefinition":              {"container", "ECS task", model.Compute},
	"AWS::EKS::Cluster":                     {"kubernetes", "EKS cluster", model.Compute},
	"AWS::EKS::Nodegroup":                   {"kubernetes", "EKS node group", model.Compute},
	"AWS::AppRunner::Service":               {"container", "App Runner service", model.Compute},
	"AWS::ElasticBeanstalk::Environment":    {"webapp", "Elastic Beanstalk app", model.Compute},
	"AWS::Lightsail::Instance":              {"vm", "Lightsail server", model.Compute},
	"AWS::Batch::ComputeEnvironment":        {"vm", "Batch compute", model.Compute},
	"AWS::StepFunctions::StateMachine":      {"function", "Step Functions workflow", model.Compute},
	"AWS::Serverless::StateMachine":         {"function", "Step Functions workflow", model.Compute},
	"AWS::Amplify::App":                     {"webapp", "Amplify app", model.Compute},
	"AWS::CodeBuild::Project":               {"terminal", "CodeBuild project", model.Compute},
	"AWS::SageMaker::NotebookInstance":      {"vm", "SageMaker notebook", model.Compute},
	"AWS::SageMaker::Endpoint":              {"function", "SageMaker endpoint", model.Compute},

	// Data
	"AWS::S3::Bucket":                      {"storage", "S3 bucket", model.Data},
	"AWS::S3::BucketPolicy":                {"storage", "S3 bucket policy", model.Data},
	"AWS::EC2::Volume":                     {"storage", "EBS disk", model.Data},
	"AWS::EFS::FileSystem":                 {"storage", "EFS file system", model.Data},
	"AWS::ECR::Repository":                 {"storage", "container registry", model.Data},
	"AWS::RDS::DBInstance":                 {"database", "RDS database", model.Data},
	"AWS::RDS::DBCluster":                  {"database", "Aurora cluster", model.Data},
	"AWS::DynamoDB::Table":                 {"database", "DynamoDB table", model.Data},
	"AWS::Serverless::SimpleTable":         {"database", "DynamoDB table", model.Data},
	"AWS::ElastiCache::CacheCluster":       {"database", "ElastiCache", model.Data},
	"AWS::ElastiCache::ReplicationGroup":   {"database", "ElastiCache", model.Data},
	"AWS::ElastiCache::ServerlessCache":    {"database", "ElastiCache", model.Data},
	"AWS::Redshift::Cluster":               {"database", "Redshift cluster", model.Data},
	"AWS::DocDB::DBCluster":                {"database", "DocumentDB cluster", model.Data},
	"AWS::Neptune::DBCluster":              {"database", "Neptune cluster", model.Data},
	"AWS::OpenSearchService::Domain":       {"database", "OpenSearch domain", model.Data},
	"AWS::Elasticsearch::Domain":           {"database", "Elasticsearch domain", model.Data},
	"AWS::SQS::Queue":                      {"relay", "SQS queue", model.Data},
	"AWS::SNS::Topic":                      {"relay", "SNS topic", model.Data},
	"AWS::Events::Rule":                    {"relay", "EventBridge rule", model.Data},
	"AWS::Kinesis::Stream":                 {"relay", "Kinesis stream", model.Data},
	"AWS::KinesisFirehose::DeliveryStream": {"relay", "Firehose stream", model.Data},
	"AWS::AmazonMQ::Broker":                {"relay", "message broker", model.Data},
	"AWS::Logs::LogGroup":                  {"monitor", "CloudWatch log group", model.Data},
	"AWS::CloudWatch::Alarm":               {"monitor", "CloudWatch alarm", model.Data},
	"AWS::Glue::Database":                  {"database", "Glue database", model.Data},
	"AWS::Backup::BackupVault":             {"storage", "backup vault", model.Data},
}

// plumbing types only wire other things together. They are read for risks
// but not drawn: one box per route or attachment would bury the rest.
var plumbing = regexp.MustCompile(`(Association|Attachment|::(Route|RouteTable|NetworkAclEntry|SecurityGroupIngress|SecurityGroupEgress|Permission|LayerVersionPermission|BasePathMapping|Deployment|Stage|Version|Alias|Method|Resource|Integration|ListenerRule|Policy|TopicPolicy|QueuePolicy))$`)

var words = regexp.MustCompile(`[A-Z]+[a-z0-9]*|[A-Z]+$`)

func lookup(typ string) (entry, bool) {
	if e, ok := catalog[typ]; ok {
		return e, true
	}
	if plumbing.MatchString(typ) || !strings.HasPrefix(typ, "AWS::") {
		return entry{}, false
	}
	// "AWS::Kinesis::Stream" -> "Kinesis stream"
	parts := strings.Split(typ, "::")
	friendly := parts[1]
	if len(parts) > 2 {
		var w []string
		for _, x := range words.FindAllString(parts[2], -1) {
			if len(x) > 1 && strings.ToUpper(x) == x {
				w = append(w, x) // keep acronyms such as ACL
			} else {
				w = append(w, strings.ToLower(x))
			}
		}
		friendly += " " + strings.Join(w, " ")
	}
	return entry{"generic", friendly, model.Other}, true
}
