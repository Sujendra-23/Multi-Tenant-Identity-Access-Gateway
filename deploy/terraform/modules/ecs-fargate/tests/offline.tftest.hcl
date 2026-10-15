provider "aws" {
  region                      = "us-west-2"
  access_key                  = "mock-access-key"
  secret_key                  = "mock-secret-key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

variables {
  name                       = "gateway-test"
  region                     = "us-west-2"
  vpc_id                     = "vpc-0123456789abcdef0"
  vpc_cidr                   = "10.20.0.0/16"
  private_subnet_ids         = ["subnet-0123456789abcdef0", "subnet-0123456789abcdef1"]
  database_security_group_id = "sg-0123456789abcdef0"
  redis_security_group_id    = "sg-0123456789abcdef1"
  redis_address              = "redis.internal:6379"
  image                      = "111122223333.dkr.ecr.us-west-2.amazonaws.com/gateway:test"
  postgres_dsn_secret_arn    = "arn:aws:secretsmanager:us-west-2:111122223333:secret:gateway-dsn-ABCDEF"
  bootstrap_key_secret_arn   = "arn:aws:secretsmanager:us-west-2:111122223333:secret:gateway-bootstrap-ABCDEF"
}

run "private_gateway" {
  command = plan
  plan_options { refresh = false }

  assert {
    condition     = aws_ecs_task_definition.gateway.network_mode == "awsvpc" && aws_ecs_task_definition.gateway.requires_compatibilities == toset(["FARGATE"])
    error_message = "The task must use Fargate with awsvpc networking."
  }
  assert {
    condition     = !aws_ecs_service.gateway.network_configuration[0].assign_public_ip && aws_lb.gateway.internal && aws_lb_target_group.gateway.target_type == "ip"
    error_message = "Gateway tasks and their IP target load balancer must remain private."
  }
  assert {
    condition     = aws_lb_target_group.gateway.health_check[0].path == "/readyz" && jsondecode(aws_ecs_task_definition.gateway.container_definitions)[0].healthCheck.command == ["CMD", "/app", "-healthcheck"]
    error_message = "ALB readiness and distroless-compatible container liveness checks are required."
  }
  assert {
    condition     = toset([for s in jsondecode(aws_ecs_task_definition.gateway.container_definitions)[0].secrets : s.name]) == toset(["POSTGRES_DSN", "BOOTSTRAP_KEY"])
    error_message = "The gateway must receive its DSN and bootstrap key through secret injection."
  }
  assert {
    condition     = alltrue([for e in jsondecode(aws_ecs_task_definition.gateway.container_definitions)[0].environment : !contains(["POSTGRES_DSN", "BOOTSTRAP_KEY"], e.name)])
    error_message = "Credentials must never be plain environment values in Terraform."
  }
  assert {
    condition     = aws_vpc_security_group_ingress_rule.database_from_gateway.security_group_id == var.database_security_group_id && aws_vpc_security_group_ingress_rule.database_from_gateway.from_port == 5432 && aws_vpc_security_group_ingress_rule.redis_from_gateway.security_group_id == var.redis_security_group_id && aws_vpc_security_group_ingress_rule.redis_from_gateway.from_port == 6379
    error_message = "Gateway tasks need explicit database and Redis access."
  }
  assert {
    condition     = aws_ecs_service.gateway.deployment_circuit_breaker[0].rollback
    error_message = "Unhealthy deployments must roll back."
  }
}

run "reject_invalid_memory" {
  command = plan
  variables { memory = 4096 }
  expect_failures = [aws_ecs_task_definition.gateway]
}

run "reject_plaintext_secret_override" {
  command = plan
  variables { environment = { POSTGRES_DSN = "plaintext-is-forbidden" } }
  expect_failures = [var.environment]
}

run "reject_non_secret_reference" {
  command = plan
  variables { postgres_dsn_secret_arn = "postgres://gateway_app:password@db/gateway" }
  expect_failures = [var.postgres_dsn_secret_arn]
}

run "reject_unsupported_half_gib" {
  command = plan
  variables { memory = 1536 }
  expect_failures = [aws_ecs_task_definition.gateway]
}

run "larger_fargate_task" {
  command = plan
  variables {
    cpu    = 512
    memory = 4096
  }
  assert {
    condition     = aws_ecs_task_definition.gateway.cpu == "512" && aws_ecs_task_definition.gateway.memory == "4096"
    error_message = "A supported larger Fargate task size must plan successfully."
  }
}
