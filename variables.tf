variable "vm_size" {
  description = "Size of the app VMs"
  type        = string
  default     = "Standard_B1s"
}

variable "vm_admin_username" {
  description = "Admin user created on the app VMs"
  type        = string
  default     = "azureuser"
}

variable "db_admin_username" {
  description = "PostgreSQL administrator login (Azure reserves names like admin, root and azure_superuser)"
  type        = string
  default     = "psqladmin"
}

variable "db_name" {
  description = "Database the app connects to"
  type        = string
  default     = "phishing_detector"
}

variable "app_zip" {
  description = "App package, next to the .tf files, that the VMs download and run at first boot"
  type        = string
  default     = "Phishing_detector_VM_files-main.zip"
}
