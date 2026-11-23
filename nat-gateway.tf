# Outbound-only internet for the VMs (apt packages at boot). Nothing can get in through it.

resource "azurerm_public_ip" "nat-pip" {
  name                = "${var.prefix}-nat-pip"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1"]
}

resource "azurerm_nat_gateway" "nat-gw" {
  name                = "${var.prefix}-nat-gw"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location
  sku_name            = "Standard"
  zones               = ["1"]
}

resource "azurerm_nat_gateway_public_ip_association" "nat-gw" {
  nat_gateway_id       = azurerm_nat_gateway.nat-gw.id
  public_ip_address_id = azurerm_public_ip.nat-pip.id
}

resource "azurerm_subnet_nat_gateway_association" "subnet-app" {
  subnet_id      = azurerm_subnet.subnet-app.id
  nat_gateway_id = azurerm_nat_gateway.nat-gw.id
}
