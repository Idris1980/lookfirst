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

	// AWS
	"aws_vpc":                             {"network", "VPC", model.Network},
	"aws_subnet":                          {"subnet", "subnet", model.Network},
	"aws_internet_gateway":                {"publicip", "internet gateway", model.Network},
	"aws_eip":                             {"publicip", "public IP address", model.Network},
	"aws_lb":                              {"loadbalancer", "load balancer", model.Network},
	"aws_security_group":                  {"shield", "security group", model.Security},
	"aws_vpc_security_group_ingress_rule": {"shield", "security group rule", model.Security},
	"aws_iam_role":                        {"identity", "IAM role", model.Security},
	"aws_iam_user":                        {"identity", "IAM user", model.Security},
	"aws_iam_access_key":                  {"key", "IAM access key", model.Security},
	"aws_instance":                        {"vm", "EC2 instance", model.Compute},
	"aws_lambda_function":                 {"function", "Lambda function", model.Compute},
	"aws_ecs_service":                     {"container", "ECS service", model.Compute},
	"aws_eks_cluster":                     {"kubernetes", "EKS cluster", model.Compute},
	"aws_s3_bucket":                       {"storage", "S3 bucket", model.Data},
	"aws_s3_bucket_acl":                   {"storage", "S3 bucket ACL", model.Data},
	"aws_s3_bucket_public_access_block":   {"storage", "S3 public access block", model.Data},
	"aws_db_instance":                     {"database", "RDS database", model.Data},
	"aws_dynamodb_table":                  {"database", "DynamoDB table", model.Data},
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
}

func isAssociation(resourceType string) bool {
	return strings.HasSuffix(resourceType, "_association")
}
