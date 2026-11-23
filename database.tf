# Private access only: the server lives in the delegated subnet-db, and its name
# resolves to a private IP through a private DNS zone linked to the VNet.

resource "azurerm_private_dns_zone" "db-dns" {
  name                = "${var.prefix}.private.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.phishing-detector-rg.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "db-dns" {
  name                = "${var.prefix}-db-dns-link"
  private_dns_zone_id = azurerm_private_dns_zone.db-dns.id
  virtual_network_id  = azurerm_virtual_network.phishing-detector-vnet.id
}

resource "random_password" "db-admin" {
  length      = 24
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
  min_special = 2
  # Characters that are safe in a connection URL and in the VM's environment file
  override_special = "-_."
}

resource "azurerm_postgresql_flexible_server" "db" {
  name                          = "${var.prefix}-db-${random_string.suffix.result}"
  resource_group_name           = azurerm_resource_group.phishing-detector-rg.name
  location                      = azurerm_resource_group.phishing-detector-rg.location
  version                       = "16"
  sku_name                      = "B_Standard_B1ms"
  storage_mb                    = 32768
  zone                          = "1"
  delegated_subnet_id           = azurerm_subnet.subnet-db.id
  private_dns_zone_id           = azurerm_private_dns_zone.db-dns.id
  public_network_access_enabled = false
  administrator_login           = var.db_admin_username
  administrator_password        = random_password.db-admin.result

  # The server can't register its DNS name until the zone is linked to the VNet.
  depends_on = [azurerm_private_dns_zone_virtual_network_link.db-dns]
}

resource "azurerm_postgresql_flexible_server_database" "app" {
  name      = var.db_name
  server_id = azurerm_postgresql_flexible_server.db.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

locals {
  # What the app reads from DATABASE_URL (SQLAlchemy format)
  database_url = format("postgresql+psycopg2://%s:%s@%s:5432/%s?sslmode=require",
    azurerm_postgresql_flexible_server.db.administrator_login,
    random_password.db-admin.result,
    azurerm_postgresql_flexible_server.db.fqdn,
    azurerm_postgresql_flexible_server_database.app.name,
  )
}
