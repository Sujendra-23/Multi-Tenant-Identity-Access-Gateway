# Plan-only tests: no resources are created and the provider uses no AWS APIs.
provider "aws" {
  region                      = "us-west-2"
  access_key                  = "mock-access-key"
  secret_key                  = "mock-secret-key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

run "aurora_defaults" {
  command = plan
  plan_options { refresh = false }

  assert {
    condition     = aws_rds_cluster.this.engine == "aurora-postgresql" && aws_rds_cluster.this.storage_encrypted && aws_rds_cluster.this.manage_master_user_password
    error_message = "Aurora must use encrypted storage and a managed master password."
  }
  assert {
    condition     = length(aws_rds_cluster_instance.this) == 2 && length(toset(aws_rds_cluster_instance.this[*].availability_zone)) == 2
    error_message = "Default Aurora compute must span two AZs with a failover replica."
  }
  assert {
    condition     = alltrue([for i in aws_rds_cluster_instance.this : !i.publicly_accessible])
    error_message = "Aurora instances must remain private."
  }
  assert {
    condition     = aws_rds_cluster_parameter_group.this.family == "aurora-postgresql16" && anytrue([for p in aws_rds_cluster_parameter_group.this.parameter : p.name == "rds.force_ssl" && p.value == "1"])
    error_message = "The Aurora PostgreSQL parameter group must force TLS."
  }
  assert {
    condition     = length(module.gateway_ecs) == 0
    error_message = "ECS must remain optional for EKS-only callers."
  }
}

run "single_instance" {
  command = plan
  plan_options { refresh = false }
  variables { db_instance_count = 1 }
  assert {
    condition     = length(aws_rds_cluster_instance.this) == 1
    error_message = "A caller can explicitly choose a single Aurora instance."
  }
}

run "reject_fractional_instances" {
  command = plan
  variables { db_instance_count = 1.5 }
  expect_failures = [var.db_instance_count]
}

run "reject_wrong_parameter_family" {
  command = plan
  variables { db_engine_version = "17.1" }
  expect_failures = [var.db_engine_version]
}

run "reject_invalid_name" {
  command = plan
  variables { name = "Bad_Name" }
  expect_failures = [var.name]
}
