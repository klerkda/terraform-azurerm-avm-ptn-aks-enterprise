terraform {
  required_version = ">= 1.9, < 2.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0.0, < 5.0.0"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
  subscription_id = "4b833d96-11d2-43bf-ac69-7baf7305341b"
  tenant_id       = "0e0c2c6b-835a-4d45-8a92-4fac0d3be692"
}

# This ensures we have unique CAF compliant names for our resources.
module "naming" {
  source  = "Azure/naming/azurerm"
  version = "~> 0.3"
}

# This is required for resource modules
resource "azurerm_resource_group" "this" {
  location = "westeurope" # Hardcoded because we have to test in a region with availability zones
  name     = module.naming.resource_group.name_unique
}

resource "azurerm_user_assigned_identity" "this" {
  location            = azurerm_resource_group.this.location
  name                = "uami-${var.kubernetes_cluster_name}"
  resource_group_name = azurerm_resource_group.this.name
}

# This is the module call
# Do not specify location here due to the randomization above.
# Leaving location as `null` will cause the module to use the resource group location
# with a data source.
module "test" {
  source = "../../"

  location                                    = azurerm_resource_group.this.location
  name                                        = module.naming.kubernetes_cluster.name_unique
  resource_group_name                         = azurerm_resource_group.this.name
  enable_telemetry                            = var.enable_telemetry # see variables.tf
  kubernetes_version                          = "1.30"
  user_assigned_managed_identity_resource_ids = [azurerm_user_assigned_identity.this.id]
}
