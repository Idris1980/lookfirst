variable "admin_password" {
  type      = string
  sensitive = true
}

variable "password_min_length" {
  type    = number
  default = 16
}

resource "azurerm_network_security_group" "main" {
  name                = "nsg-safe"
  location            = "swedencentral"
  resource_group_name = "rg-safe"

  security_rule {
    name                       = "SSH-from-office"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "203.0.113.10/32"
    destination_address_prefix = "*"
  }
}

resource "azurerm_linux_virtual_machine" "main" {
  name                            = "vm-safe"
  resource_group_name             = "rg-safe"
  location                        = "swedencentral"
  size                            = "Standard_B1s"
  admin_username                  = "azureuser"
  admin_password                  = var.admin_password
  disable_password_authentication = true
  network_interface_ids           = []
  key_vault_secret_id             = "https://kv-safe.vault.azure.net/secrets/x"
}

resource "azurerm_storage_account" "main" {
  name                            = "stsafe12345"
  resource_group_name             = "rg-safe"
  location                        = "swedencentral"
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = false
  min_tls_version                 = "TLS1_2"
}
