# A web app with a SQL database and file storage, as an AI assistant
# might write it when asked to "make it work quickly".

variable "sql_admin_password" {
  type    = string
  default = "SuperSecret123!"
}

resource "azurerm_resource_group" "main" {
  name     = "rg-shop"
  location = "swedencentral"
}

resource "azurerm_service_plan" "main" {
  name                = "plan-shop"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "B1"
}

resource "azurerm_linux_web_app" "main" {
  name                = "app-shop"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  service_plan_id     = azurerm_service_plan.main.id

  site_config {}

  connection_string {
    name  = "Database"
    type  = "SQLAzure"
    value = "Server=tcp:${azurerm_mssql_server.main.fully_qualified_domain_name};Database=${azurerm_mssql_database.main.name};User ID=sqladmin;Password=${var.sql_admin_password}"
  }

  app_settings = {
    STORAGE_ACCOUNT = azurerm_storage_account.main.name
  }
}

resource "azurerm_mssql_server" "main" {
  name                         = "sql-shop"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
  minimum_tls_version          = "1.0"
}

resource "azurerm_mssql_database" "main" {
  name      = "sqldb-shop"
  server_id = azurerm_mssql_server.main.id
  sku_name  = "Basic"
}

resource "azurerm_mssql_firewall_rule" "everyone" {
  name             = "AllowAll"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_storage_account" "main" {
  name                            = "stshop12345"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
}

resource "azurerm_storage_container" "images" {
  name                  = "images"
  storage_account_id    = azurerm_storage_account.main.id
  container_access_type = "blob"
}
