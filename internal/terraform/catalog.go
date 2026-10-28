package terraform

import (
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

type entry struct {
	kind     string
	friendly string
	category model.Category
}

// catalog maps the most common resource types to an icon, a plain name and
// a column. Unknown types still show up, as a generic box under Other.
var catalog = map[string]entry{
	// Azure
	"azurerm_virtual_network":                          {"network", "virtual network", model.Network},
	"azurerm_subnet":                                   {"subnet", "subnet", model.Network},
	"azurerm_network_interface":                        {"nic", "network interface", model.Network},
	"azurerm_public_ip":                                {"publicip", "public IP address", model.Network},
	"azurerm_lb":                                       {"loadbalancer", "load balancer", model.Network},
	"azurerm_application_gateway":                      {"loadbalancer", "application gateway", model.Network},
	"azurerm_private_endpoint":                         {"nic", "private endpoint", model.Network},
	"azurerm_network_security_group":                   {"shield", "network security group", model.Security},
	"azurerm_network_security_rule":                    {"shield", "security rule", model.Security},
	"azurerm_firewall":                                 {"firewall", "firewall", model.Security},
	"azurerm_key_vault":                                {"key", "key vault", model.Security},
	"azurerm_key_vault_secret":                         {"key", "key vault secret", model.Security},
	"azurerm_user_assigned_identity":                   {"identity", "managed identity", model.Security},
	"azurerm_role_assignment":                          {"identity", "role assignment", model.Security},
	"azurerm_linux_virtual_machine":                    {"vm", "virtual machine", model.Compute},
	"azurerm_windows_virtual_machine":                  {"vm", "virtual machine", model.Compute},
	"azurerm_virtual_machine":                          {"vm", "virtual machine", model.Compute},
	"azurerm_kubernetes_cluster":                       {"kubernetes", "Kubernetes cluster", model.Compute},
	"azurerm_container_group":                          {"container", "container group", model.Compute},
	"azurerm_container_app":                            {"container", "container app", model.Compute},
	"azurerm_service_plan":                             {"plan", "App Service plan", model.Compute},
	"azurerm_linux_web_app":                            {"webapp", "web app", model.Compute},
	"azurerm_windows_web_app":                          {"webapp", "web app", model.Compute},
	"azurerm_linux_function_app":                       {"function", "function app", model.Compute},
	"azurerm_windows_function_app":                     {"function", "function app", model.Compute},
	"azurerm_storage_account":                          {"storage", "storage account", model.Data},
	"azurerm_storage_container":                        {"storage", "storage container", model.Data},
	"azurerm_mssql_server":                             {"database", "SQL server", model.Data},
	"azurerm_mssql_database":                           {"database", "SQL database", model.Data},
	"azurerm_mssql_firewall_rule":                      {"firewall", "SQL firewall rule", model.Data},
	"azurerm_postgresql_flexible_server":               {"database", "PostgreSQL server", model.Data},
	"azurerm_postgresql_flexible_server_firewall_rule": {"firewall", "PostgreSQL firewall rule", model.Data},
	"azurerm_mysql_flexible_server":                    {"database", "MySQL server", model.Data},
	"azurerm_cosmosdb_account":                         {"database", "Cosmos DB account", model.Data},
	"azurerm_redis_cache":                              {"database", "Redis cache", model.Data},

	// AWS: network
	"aws_vpc":                           {"network", "VPC", model.Network},
	"aws_subnet":                        {"subnet", "subnet", model.Network},
	"aws_internet_gateway":              {"globe", "internet gateway", model.Network},
	"aws_nat_gateway":                   {"globe", "NAT gateway", model.Network},
	"aws_eip":                           {"publicip", "public IP address", model.Network},
	"aws_network_interface":             {"nic", "network interface", model.Network},
	"aws_vpc_endpoint":                  {"nic", "VPC endpoint", model.Network},
	"aws_ec2_transit_gateway":           {"network", "transit gateway", model.Network},
	"aws_vpn_gateway":                   {"network", "VPN gateway", model.Network},
	"aws_lb":                            {"loadbalancer", "load balancer", model.Network},
	"aws_alb":                           {"loadbalancer", "load balancer", model.Network},
	"aws_elb":                           {"loadbalancer", "classic load balancer", model.Network},
	"aws_lb_listener":                   {"loadbalancer", "load balancer listener", model.Network},
	"aws_alb_listener":                  {"loadbalancer", "load balancer listener", model.Network},
	"aws_lb_target_group":               {"loadbalancer", "target group", model.Network},
	"aws_cloudfront_distribution":       {"globe", "CloudFront CDN", model.Network},
	"aws_api_gateway_rest_api":          {"webapp", "API Gateway", model.Network},
	"aws_apigatewayv2_api":              {"webapp", "API Gateway", model.Network},
	"aws_route53_zone":                  {"dns", "DNS zone", model.Network},
	"aws_route53_record":                {"dns", "DNS record", model.Network},
	"aws_globalaccelerator_accelerator": {"globe", "Global Accelerator", model.Network},
	"aws_appsync_graphql_api":           {"webapp", "AppSync API", model.Network},
	"aws_lambda_function_url":           {"globe", "Lambda function URL", model.Network},

	// AWS: security
	"aws_security_group":                  {"shield", "security group", model.Security},
	"aws_vpc_security_group_ingress_rule": {"shield", "security group rule", model.Security},
	"aws_network_acl":                     {"firewall", "network ACL", model.Security},
	"aws_wafv2_web_acl":                   {"firewall", "web application firewall", model.Security},
	"aws_networkfirewall_firewall":        {"firewall", "network firewall", model.Security},
	"aws_iam_role":                        {"identity", "IAM role", model.Security},
	"aws_iam_user":                        {"identity", "IAM user", model.Security},
	"aws_iam_group":                       {"identity", "IAM group", model.Security},
	"aws_iam_policy":                      {"identity", "IAM policy", model.Security},
	"aws_iam_role_policy":                 {"identity", "IAM policy", model.Security},
	"aws_iam_user_policy":                 {"identity", "IAM policy", model.Security},
	"aws_iam_instance_profile":            {"identity", "instance profile", model.Security},
	"aws_iam_access_key":                  {"key", "IAM access key", model.Security},
	"aws_kms_key":                         {"key", "KMS key", model.Security},
	"aws_secretsmanager_secret":           {"key", "stored secret", model.Security},
	"aws_ssm_parameter":                   {"key", "Systems Manager parameter", model.Security},
	"aws_acm_certificate":                 {"key", "TLS certificate", model.Security},
	"aws_key_pair":                        {"key", "SSH key pair", model.Security},
	"aws_cognito_user_pool":               {"identity", "Cognito user pool", model.Security},
	"aws_guardduty_detector":              {"shield", "GuardDuty", model.Security},
	"aws_cloudtrail":                      {"monitor", "CloudTrail log", model.Security},

	// AWS: compute
	"aws_instance":                      {"vm", "EC2 instance", model.Compute},
	"aws_launch_template":               {"vm", "launch template", model.Compute},
	"aws_autoscaling_group":             {"vm", "auto scaling group", model.Compute},
	"aws_lambda_function":               {"function", "Lambda function", model.Compute},
	"aws_ecs_cluster":                   {"container", "ECS cluster", model.Compute},
	"aws_ecs_service":                   {"container", "ECS service", model.Compute},
	"aws_ecs_task_definition":           {"container", "ECS task", model.Compute},
	"aws_eks_cluster":                   {"kubernetes", "EKS cluster", model.Compute},
	"aws_eks_node_group":                {"kubernetes", "EKS node group", model.Compute},
	"aws_apprunner_service":             {"container", "App Runner service", model.Compute},
	"aws_elastic_beanstalk_environment": {"webapp", "Elastic Beanstalk app", model.Compute},
	"aws_lightsail_instance":            {"vm", "Lightsail server", model.Compute},
	"aws_batch_compute_environment":     {"vm", "Batch compute", model.Compute},
	"aws_sfn_state_machine":             {"function", "Step Functions workflow", model.Compute},
	"aws_amplify_app":                   {"webapp", "Amplify app", model.Compute},
	"aws_codebuild_project":             {"terminal", "CodeBuild project", model.Compute},
	"aws_sagemaker_notebook_instance":   {"vm", "SageMaker notebook", model.Compute},

	// AWS: data
	"aws_s3_bucket":                        {"storage", "S3 bucket", model.Data},
	"aws_s3_bucket_acl":                    {"storage", "S3 bucket ACL", model.Data},
	"aws_s3_bucket_policy":                 {"storage", "S3 bucket policy", model.Data},
	"aws_s3_bucket_public_access_block":    {"storage", "S3 public access block", model.Data},
	"aws_ebs_volume":                       {"storage", "EBS disk", model.Data},
	"aws_efs_file_system":                  {"storage", "EFS file system", model.Data},
	"aws_ecr_repository":                   {"storage", "container registry", model.Data},
	"aws_db_instance":                      {"database", "RDS database", model.Data},
	"aws_rds_cluster":                      {"database", "Aurora cluster", model.Data},
	"aws_rds_cluster_instance":             {"database", "Aurora instance", model.Data},
	"aws_dynamodb_table":                   {"database", "DynamoDB table", model.Data},
	"aws_elasticache_cluster":              {"database", "ElastiCache", model.Data},
	"aws_elasticache_replication_group":    {"database", "ElastiCache", model.Data},
	"aws_redshift_cluster":                 {"database", "Redshift cluster", model.Data},
	"aws_docdb_cluster":                    {"database", "DocumentDB cluster", model.Data},
	"aws_neptune_cluster":                  {"database", "Neptune cluster", model.Data},
	"aws_opensearch_domain":                {"database", "OpenSearch domain", model.Data},
	"aws_elasticsearch_domain":             {"database", "Elasticsearch domain", model.Data},
	"aws_sqs_queue":                        {"relay", "SQS queue", model.Data},
	"aws_sns_topic":                        {"relay", "SNS topic", model.Data},
	"aws_cloudwatch_event_rule":            {"relay", "EventBridge rule", model.Data},
	"aws_kinesis_stream":                   {"relay", "Kinesis stream", model.Data},
	"aws_kinesis_firehose_delivery_stream": {"relay", "Firehose stream", model.Data},
	"aws_mq_broker":                        {"relay", "message broker", model.Data},
	"aws_cloudwatch_log_group":             {"monitor", "CloudWatch log group", model.Data},
	"aws_cloudwatch_metric_alarm":          {"monitor", "CloudWatch alarm", model.Data},
	"aws_backup_vault":                     {"storage", "backup vault", model.Data},
}

func lookup(resourceType string) entry {
	if e, ok := catalog[resourceType]; ok {
		return e
	}
	name := resourceType
	if i := strings.IndexByte(name, '_'); i >= 0 {
		name = name[i+1:]
	}
	return entry{"generic", strings.ReplaceAll(name, "_", " "), model.Other}
}

// hidden types are containers for everything else. Drawing them, and every
// line to them, would only add noise.
var hidden = map[string]bool{
	"azurerm_resource_group": true,
	// Rules and wiring, read for risks but reported on what they belong to.
	"aws_security_group_rule":         true,
	"aws_route":                       true,
	"aws_route_table":                 true,
	"aws_lambda_permission":           true,
	"aws_iam_role_policy_attachment":  true,
	"aws_iam_user_policy_attachment":  true,
	"aws_iam_group_policy_attachment": true,
	"aws_iam_policy_attachment":       true,
}

func isAssociation(resourceType string) bool {
	return strings.HasSuffix(resourceType, "_association")
}
