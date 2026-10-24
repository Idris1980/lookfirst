resource "azurerm_network_security_group" "web" {
  name                = "nsg-web"
  location            = "swedencentral"
  resource_group_name = "rg-test"

  security_rule {
    name                       = "RDP"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
