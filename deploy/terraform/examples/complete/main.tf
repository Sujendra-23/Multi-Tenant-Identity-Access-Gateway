# Example root configuration. offline_plan=true selects mock credentials and
# skips AWS API validation. Use only for planning with no state; never apply it.
# The ECS image/secret ARNs below are placeholders: replace before a real deploy.
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

variable "gateway_ecs" {
  description = "Fargate configuration. Defaults are OFFLINE PLACEHOLDERS; replace with your image and existing secret ARNs, or set null to omit ECS."
  type = object({
    image                    = string
    postgres_dsn_secret_arn  = string
    bootstrap_key_secret_arn = string
    secret_kms_key_arns      = optional(list(string), [])
    desired_count            = optional(number, 3)
    cpu                      = optional(number, 256)
    memory                   = optional(number, 512)
    environment              = optional(map(string), {})
  })
  default = {
    image                    = "111122223333.dkr.ecr.us-west-2.amazonaws.com/identity-gateway:replace-me"
    postgres_dsn_secret_arn  = "arn:aws:secretsmanager:us-west-2:111122223333:secret:gateway-app-dsn-ABCDEF"
    bootstrap_key_secret_arn = "arn:aws:secretsmanager:us-west-2:111122223333:secret:gateway-bootstrap-ABCDEF"
    environment = {
      JWT_ISSUER = "https://gateway.example.com"
      UPSTREAMS  = "demo=https://upstream.internal.example.com"
    }
  }
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
  gateway_ecs             = var.gateway_ecs
  eks_public_access_cidrs = ["203.0.113.0/24"] # replace with your VPN/office range
}

output "kubeconfig_command" {
  value = module.identity_gateway.kubeconfig_command
}

output "gateway_env" {
  value = module.identity_gateway.gateway_env
}

output "aurora_reader_endpoint" {
  value = module.identity_gateway.aurora_reader_endpoint
}

output "rds_master_secret_arn" {
  value = module.identity_gateway.rds_master_secret_arn
}

output "ecs_cluster_name" {
  value = module.identity_gateway.ecs_cluster_name
}

output "ecs_service_name" {
  value = module.identity_gateway.ecs_service_name
}

output "ecs_gateway_url" {
  value = module.identity_gateway.ecs_gateway_url
}
