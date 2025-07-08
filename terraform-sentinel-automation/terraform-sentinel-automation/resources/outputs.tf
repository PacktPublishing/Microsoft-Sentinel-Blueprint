# outputs.tf
output "log_analytics_workspace_id" {
  value = module.log_analytics.workspace_id
}

output "sentinel_deployment_status" {
  value = module.sentinel.deployment_status
}