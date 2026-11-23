# Private storage for the app package. The VMs download it at first boot with their managed identity.

resource "azurerm_storage_account" "app" {
  # 3-24 lowercase letters and digits, globally unique
  name                            = "${substr(replace(var.prefix, "-", ""), 0, 18)}${random_string.suffix.result}"
  resource_group_name             = azurerm_resource_group.phishing-detector-rg.name
  location                        = azurerm_resource_group.phishing-detector-rg.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "app" {
  name                  = "app"
  storage_account_id    = azurerm_storage_account.app.id
  container_access_type = "private"
}

# Re-uploaded whenever the zip changes (content_md5). Running VMs keep their copy until redeployed.
resource "azurerm_storage_blob" "app" {
  name                 = "phishing-detector.zip"
  storage_container_id = azurerm_storage_container.app.id
  type                 = "Block"
  source               = "${path.module}/${var.app_zip}"
  content_md5          = filemd5("${path.module}/${var.app_zip}")
}

# The VMs can only read the app container, nothing else in the account.
resource "azurerm_role_assignment" "vm-read-app" {
  scope                = azurerm_storage_container.app.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id         = azurerm_user_assigned_identity.vm-identity.principal_id
  principal_type       = "ServicePrincipal"
}
