# Create the Resource Group
resource "azurerm_resource_group" "rg" {
  name     = var.resource_group_name
  location = var.location
  tags = {
    environment = "production"
  }
}

# Call the Log Analytics Workspace module
module "log_analytics" {
  source              = "./modules/log_analytics"
  resource_group_name = var.resource_group_name
  location            = var.location
  workspace_name      = var.log_analytics_workspace_name
  retention_in_days   = var.retention_in_days
  depends_on = [ azurerm_resource_group.rg ]
}

# Call the Azure Sentinel module
module "sentinel" {
  source                   = "./modules/sentinel"
  log_analytics_workspace_id = module.log_analytics.workspace_id
depends_on = [ module.log_analytics ]
}