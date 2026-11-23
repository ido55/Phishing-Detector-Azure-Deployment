terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "=5.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}


provider "azurerm" {
  features {}

  # Azure services this project uses. New subscriptions (e.g. Azure for Students)
  # may not have them enabled yet, and creating their resources then fails.
  resource_providers_to_register = [
    "Microsoft.Compute",
    "Microsoft.DBforPostgreSQL",
    "Microsoft.ManagedIdentity",
    "Microsoft.Network",
    "Microsoft.Storage",
  ]
}


variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "Poland Central"
}

# The gateway DNS label and the PostgreSQL server name must be globally unique.
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_resource_group" "phishing-detector-rg" {
  name     = "phishing-detector-rg"
  location = var.location
  tags = {
    environment = "dev"
  }
}
resource "azurerm_virtual_network" "phishing-detector-vnet" {
  name                = "phishing-detector-vnet"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "subnet-gateway" {
  name                 = "subnet-gateway"
  resource_group_name  = azurerm_resource_group.phishing-detector-rg.name
  virtual_network_name = azurerm_virtual_network.phishing-detector-vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}
resource "azurerm_subnet" "subnet-app" {
  name                 = "subnet-app"
  resource_group_name  = azurerm_resource_group.phishing-detector-rg.name
  virtual_network_name = azurerm_virtual_network.phishing-detector-vnet.name
  address_prefixes     = ["10.0.2.0/24"]
}
resource "azurerm_subnet" "subnet-db" {
  name                 = "subnet-db"
  resource_group_name  = azurerm_resource_group.phishing-detector-rg.name
  virtual_network_name = azurerm_virtual_network.phishing-detector-vnet.name
  address_prefixes     = ["10.0.3.0/24"]

  delegation {
    name = "postgresql-flexible-server"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_public_ip" "AG-pip" {
  name                = "AG-pip"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  domain_name_label   = "${var.prefix}-${random_string.suffix.result}"
}


locals {
  vnet_name = azurerm_virtual_network.phishing-detector-vnet.name

  backend_address_pool_name      = "${local.vnet_name}-beap"
  frontend_port_name             = "${local.vnet_name}-feport"
  frontend_ip_configuration_name = "${local.vnet_name}-feip"
  http_setting_name              = "${local.vnet_name}-be-htst"
  listener_name                  = "${local.vnet_name}-httplstn"
  request_routing_rule_name      = "${local.vnet_name}-rqrt"
  redirect_configuration_name    = "${local.vnet_name}-rdrcfg"
  probe_name                     = "${local.vnet_name}-probe"
}


resource "azurerm_application_gateway" "GW" {
  name                = "AG"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location
  zones               = ["1", "2", "3"]

  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = 1
  }

  gateway_ip_configuration {
    name      = "AG-ip-config"
    subnet_id = azurerm_subnet.subnet-gateway.id
  }

  frontend_port {
    name = local.frontend_port_name
    port = 80
  }

  frontend_ip_configuration {
    name                 = local.frontend_ip_configuration_name
    public_ip_address_id = azurerm_public_ip.AG-pip.id
  }

  backend_address_pool {
    name = local.backend_address_pool_name
  }
  backend_http_settings {
    name                  = local.http_setting_name
    cookie_based_affinity = "Disabled"
    port                  = 8000
    protocol              = "Http"
    request_timeout       = 60
    probe_name            = local.probe_name
  }

  probe {
    name                = local.probe_name
    protocol            = "Http"
    host                = "127.0.0.1"
    path                = "/health"
    interval            = 15
    timeout             = 10
    unhealthy_threshold = 3
  }

  http_listener {
    name                           = local.listener_name
    frontend_ip_configuration_name = local.frontend_ip_configuration_name
    frontend_port_name             = local.frontend_port_name
    protocol                       = "Http"
  }

  request_routing_rule {
    name                       = local.request_routing_rule_name
    priority                   = 9
    rule_type                  = "Basic"
    http_listener_name         = local.listener_name
    backend_address_pool_name  = local.backend_address_pool_name
    backend_http_settings_name = local.http_setting_name
  }

  # Azure rejects the old default policy (TLS 1.0/1.1), so pin a current one.
  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101"
  }
}


variable "prefix" {
  default = "phishing-detector"
}


locals {
  vm_zones = ["1", "2"] # one VM per availability zone
}

# Required by Azure for Linux VMs; port 22 stays closed, so use Run Command instead of SSH.
resource "tls_private_key" "vm-ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Shared by both VMs to reach Azure services without passwords (see storage.tf for its access).
resource "azurerm_user_assigned_identity" "vm-identity" {
  name                = "${var.prefix}-vm-identity"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location
}

resource "azurerm_network_interface" "VM-nic" {
  count               = length(local.vm_zones)
  name                = format("%s-server-%02d-nic", var.prefix, count.index + 1)
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
  location            = azurerm_resource_group.phishing-detector-rg.location

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.subnet-app.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "VM" {
  count                 = length(local.vm_zones)
  name                  = format("%s-server-%02d", var.prefix, count.index + 1)
  resource_group_name   = azurerm_resource_group.phishing-detector-rg.name
  location              = azurerm_resource_group.phishing-detector-rg.location
  zone                  = local.vm_zones[count.index]
  size                  = var.vm_size
  admin_username        = var.vm_admin_username
  network_interface_ids = [azurerm_network_interface.VM-nic[count.index].id]

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.vm-identity.id]
  }

  admin_ssh_key {
    username   = var.vm_admin_username
    public_key = tls_private_key.vm-ssh.public_key_openssh
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  custom_data = base64encode(templatefile("${path.module}/cloud-init.yaml.tftpl", {
    app_blob_url       = azurerm_storage_blob.app.url
    identity_client_id = azurerm_user_assigned_identity.vm-identity.client_id
    database_url       = local.database_url
    instance_id        = format("%s-server-%02d", var.prefix, count.index + 1)
    availability_zone  = local.vm_zones[count.index]
  }))

  # At first boot cloud-init downloads packages and the app, so outbound internet
  # and read access to the app container must exist first.
  depends_on = [
    azurerm_subnet_nat_gateway_association.subnet-app,
    azurerm_role_assignment.vm-read-app,
  ]
}

resource "azurerm_network_interface_application_gateway_backend_address_pool_association" "VM" {
  count                   = length(local.vm_zones)
  network_interface_id    = azurerm_network_interface.VM-nic[count.index].id
  ip_configuration_name   = "internal"
  backend_address_pool_id = tolist(azurerm_application_gateway.GW.backend_address_pool)[0].id
}
