variable "name" {
  description = "Name prefix for every resource (cluster, DB, cache, VPC)."
  type        = string
  default     = "identity-gateway"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.name))
    error_message = "name must be 2-31 chars: lowercase letters, digits, hyphens, starting with a letter."
  }
}

variable "region" {
  description = "AWS region. Used to derive default availability zone names."
  type        = string
  default     = "us-west-2"
}

variable "availability_zones" {
  description = "AZs to spread subnets across (at least 2: RDS and ElastiCache need a multi-AZ subnet group). Defaults to <region>a and <region>b. Passed explicitly rather than looked up so the module plans without calling AWS."
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.availability_zones) == 0 || length(var.availability_zones) >= 2
    error_message = "Provide at least two availability zones (or leave empty for the default two)."
  }
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "vpc_cidr must be a valid CIDR block."
  }
}

variable "single_nat_gateway" {
  description = "One shared NAT gateway (cheaper, single-AZ egress failure domain) instead of one per AZ."
  type        = bool
  default     = true
}

# ---- EKS ----

variable "eks_version" {
  description = "Kubernetes version for the EKS control plane."
  type        = string
  default     = "1.31"
}

variable "eks_endpoint_public_access" {
  description = "Expose the Kubernetes API endpoint publicly (restricted by eks_public_access_cidrs)."
  type        = bool
  default     = true
}

variable "eks_public_access_cidrs" {
  description = "CIDRs allowed to reach the public Kubernetes API endpoint. Restrict this to your office/VPN range."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "eks_node_instance_types" {
  description = "Instance types for the managed node group."
  type        = list(string)
  default     = ["m6i.large"]
}

variable "eks_node_min_size" {
  type    = number
  default = 3
}

variable "eks_node_desired_size" {
  type    = number
  default = 3
}

variable "eks_node_max_size" {
  type    = number
  default = 6

  validation {
    condition     = var.eks_node_max_size >= var.eks_node_min_size
    error_message = "eks_node_max_size must be >= eks_node_min_size."
  }
}

variable "enable_network_policy" {
  description = "Turn on the VPC CNI's built-in NetworkPolicy enforcement so deploy/k8s/07-networkpolicy.yaml is actually enforced."
  type        = bool
  default     = true
}

# ---- RDS Postgres ----

variable "db_name" {
  description = "Initial database name (matches POSTGRES_DB in deploy/k8s/01-secrets.example.yaml)."
  type        = string
  default     = "gateway"
}

variable "db_master_username" {
  description = "RDS master user. This is the bootstrap/admin role, NOT the role the gateway connects as (gateway_app; see README)."
  type        = string
  default     = "postgres_bootstrap"
}

variable "db_engine_version" {
  description = "Postgres major version. Row-level security and trusted pgcrypto need >= 13."
  type        = string
  default     = "16.4"
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "db_allocated_storage" {
  description = "Initial storage in GiB."
  type        = number
  default     = 50
}

variable "db_max_allocated_storage" {
  description = "Storage autoscaling ceiling in GiB (0 disables autoscaling)."
  type        = number
  default     = 200
}

variable "db_multi_az" {
  description = "Synchronous standby in a second AZ."
  type        = bool
  default     = true
}

variable "db_backup_retention_days" {
  type    = number
  default = 7
}

variable "db_deletion_protection" {
  description = "Block terraform destroy / console deletion of the database."
  type        = bool
  default     = true
}

variable "db_skip_final_snapshot" {
  description = "Skip the final snapshot on destroy. Keep false outside throwaway environments."
  type        = bool
  default     = false
}

# ---- ElastiCache Redis ----

variable "redis_engine_version" {
  type    = string
  default = "7.1"
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}

variable "redis_num_cache_clusters" {
  description = "Primary + replicas. 2 or more gives automatic failover."
  type        = number
  default     = 2

  validation {
    condition     = var.redis_num_cache_clusters >= 1 && var.redis_num_cache_clusters <= 6
    error_message = "redis_num_cache_clusters must be between 1 and 6."
  }
}

variable "redis_transit_encryption_enabled" {
  description = <<-EOT
    TLS between clients and Redis. DEFAULT FALSE ON PURPOSE: the gateway's Redis
    client (internal/store/redisstore/client.go) does not configure TLS today,
    so enabling this makes the gateway unable to connect until the client gains
    a tls.Config. ElastiCache AUTH tokens also require transit encryption, so
    with this off Redis is protected by private subnets + a security group that
    only admits the EKS nodes, not by a password.
  EOT
  type        = bool
  default     = false
}

variable "tags" {
  description = "Extra tags applied to every resource."
  type        = map(string)
  default     = {}
}
