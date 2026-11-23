# Without the deny rules, Azure's default AllowVnetInBound rule would let every
# subnet in the VNet reach every port. Internet traffic is already denied by default.

resource "azurerm_network_security_group" "app-nsg" {
  name                = "${var.prefix}-app-nsg"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location

  security_rule {
    name                       = "allow-http-8000-from-gateway"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8000"
    source_address_prefix      = azurerm_subnet.subnet-gateway.address_prefixes[0]
    destination_address_prefix = azurerm_subnet.subnet-app.address_prefixes[0]
  }

  security_rule {
    name                       = "deny-other-vnet-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "subnet-app" {
  subnet_id                 = azurerm_subnet.subnet-app.id
  network_security_group_id = azurerm_network_security_group.app-nsg.id
}

resource "azurerm_network_security_group" "db-nsg" {
  name                = "${var.prefix}-db-nsg"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location

  security_rule {
    name                       = "allow-postgres-5432-from-app"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5432"
    source_address_prefix      = azurerm_subnet.subnet-app.address_prefixes[0]
    destination_address_prefix = azurerm_subnet.subnet-db.address_prefixes[0]
  }

  security_rule {
    name                       = "deny-other-vnet-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "subnet-db" {
  subnet_id                 = azurerm_subnet.subnet-db.id
  network_security_group_id = azurerm_network_security_group.db-nsg.id
}
