variable "name" {
  type = string
}

variable "region" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "vpc_cidr" {
  description = "VPC CIDR allowed to reach the internal ALB."
  type        = string
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "database_security_group_id" {
  type = string
}

variable "redis_security_group_id" {
  type = string
}

variable "redis_address" {
  type = string
}

variable "image" {
  description = "Gateway Linux/X86_64 container image URI (prefer an immutable digest)."
  type        = string

  validation {
    condition     = length(trimspace(var.image)) > 0
    error_message = "image must be a non-empty gateway container image URI."
  }
}

variable "postgres_dsn_secret_arn" {
  description = "Existing Secrets Manager secret whose entire value is a gateway_app PostgreSQL DSN with sslmode=require or stricter. Never use the Aurora master secret."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[^:]+$", var.postgres_dsn_secret_arn))
    error_message = "postgres_dsn_secret_arn must be a complete Secrets Manager secret ARN."
  }
}

variable "bootstrap_key_secret_arn" {
  description = "Existing Secrets Manager secret whose entire value is BOOTSTRAP_KEY."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[^:]+$", var.bootstrap_key_secret_arn))
    error_message = "bootstrap_key_secret_arn must be a complete Secrets Manager secret ARN."
  }
}

variable "secret_kms_key_arns" {
  description = "Customer managed KMS keys used by the supplied secrets; empty for the default Secrets Manager key."
  type        = list(string)
  default     = []
}

variable "desired_count" {
  type    = number
  default = 3

  validation {
    condition     = var.desired_count >= 1 && floor(var.desired_count) == var.desired_count
    error_message = "desired_count must be a positive integer."
  }
}

variable "cpu" {
  description = "Fargate CPU units. Supported sizes: 256, 512, 1024, 2048, 4096."
  type        = number
  default     = 256

  validation {
    condition     = contains([256, 512, 1024, 2048, 4096], var.cpu)
    error_message = "cpu must be 256, 512, 1024, 2048, or 4096."
  }
}

variable "memory" {
  description = "Fargate memory in MiB; must match the CPU size."
  type        = number
  default     = 512
}

variable "environment" {
  description = "Non-secret gateway settings, such as JWT_ISSUER, JWT_AUDIENCE, and UPSTREAMS. Infrastructure and secret settings cannot be overridden."
  type        = map(string)
  default     = {}

  validation {
    condition = length(setintersection(toset(keys(var.environment)), toset([
      "ENV", "HTTP_ADDR", "METRICS_ADDR", "REDIS_ADDR", "FEATURE_FLAGS_BACKEND",
      "TRUSTED_PROXY_CIDRS", "POSTGRES_DSN", "BOOTSTRAP_KEY", "REDIS_PASSWORD",
      "TLS_CERT_FILE", "TLS_KEY_FILE",
    ]))) == 0
    error_message = "environment cannot override infrastructure, TLS, or secret settings; use the dedicated inputs for secrets."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
