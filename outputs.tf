output "app_url" {
  description = "Public URL of the app (through the Application Gateway)"
  value       = "http://${azurerm_public_ip.AG-pip.fqdn}"
}

output "app_public_ip" {
  value = azurerm_public_ip.AG-pip.ip_address
}

output "vm_private_ips" {
  value = { for vm in azurerm_linux_virtual_machine.VM : vm.name => vm.private_ip_address }
}

output "db_fqdn" {
  description = "Resolves to a private IP from inside the VNet only"
  value       = azurerm_postgresql_flexible_server.db.fqdn
}

output "db_name" {
  value = azurerm_postgresql_flexible_server_database.app.name
}

output "db_admin_password" {
  description = "Read it with: terraform output -raw db_admin_password"
  value       = random_password.db-admin.result
  sensitive   = true
}
