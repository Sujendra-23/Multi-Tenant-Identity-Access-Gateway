# Example root configuration. The provider block below uses mock credentials and
# skips every AWS API call that validation would make, so `terraform plan` runs
# with NO AWS account. That is for checking the module only: remove the skip_*
# and mock key lines (and use real credentials) to actually deploy.
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

variable "offline_plan" {
  description = "Use mock credentials and skip AWS API validation (plan-only, no account needed)."
  type        = bool
  default     = false
}

provider "aws" {
  region = "us-west-2"

  access_key                  = var.offline_plan ? "mock-access-key" : null
  secret_key                  = var.offline_plan ? "mock-secret-key" : null
  skip_credentials_validation = var.offline_plan
  skip_requesting_account_id  = var.offline_plan
  skip_metadata_api_check     = var.offline_plan
  skip_region_validation      = var.offline_plan
}

module "identity_gateway" {
  source = "../.."

  name                    = "identity-gateway"
  region                  = "us-west-2"
  eks_public_access_cidrs = ["203.0.113.0/24"] # replace with your VPN/office range
}

output "kubeconfig_command" {
  value = module.identity_gateway.kubeconfig_command
}

output "gateway_env" {
  value = module.identity_gateway.gateway_env
}
