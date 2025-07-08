resource "azurerm_sentinel_log_analytics_workspace_onboarding" "sentinel" {
  workspace_id                 = var.log_analytics_workspace_id
  customer_managed_key_enabled = false
}

# Optional: Add data connectors and alert rules here