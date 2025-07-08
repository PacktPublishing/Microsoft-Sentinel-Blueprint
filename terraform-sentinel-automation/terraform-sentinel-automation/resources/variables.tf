# variables.tf

variable "subscription_id" {
  description = "Client's Subscription ID"
  type        = string
}

variable "client_id" {
  description = "Client's Service Principal ID"
  type        = string
}

variable "client_secret" {
  description = "Client's Service Principal Secret"
  type        = string
}

variable "tenant_id" {
  description = "Client's Tenant ID"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "location" {
  description = "Azure region to deploy resources in"
  type        = string
  default     = "East US"
}

variable "log_analytics_workspace_name" {
  description = "Name of the Log Analytics Workspace"
  type        = string
}

variable "retention_in_days" {
  description = "Retention period in days for the workspace"
  type        = number
  default     = 30
}

variable "backend_resource_group_name" {
  description = "Backend Resource Group Name"
  type        = string
}

variable "backend_storage_account_name" {
  description = "Backend Storage Account Name"
  type        = string
}

variable "backend_container_name" {
  description = "Backend Container Name"
  type        = string
}

