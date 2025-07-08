resource "azurerm_log_analytics_workspace" "log_analytics_workspace" {
  name                = var.workspace_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.retention_in_days

  tags = {
    environment = "production"
  }
}