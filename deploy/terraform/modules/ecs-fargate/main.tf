locals {
  memory_sizes = {
    "256"  = [512, 1024, 2048]
    "512"  = range(1024, 4097, 1024)
    "1024" = range(2048, 8193, 1024)
    "2048" = range(4096, 16385, 1024)
    "4096" = range(8192, 30721, 1024)
  }
  environment = merge(var.environment, {
    ENV                   = "production"
    HTTP_ADDR             = ":8080"
    METRICS_ADDR          = ":9090"
    REDIS_ADDR            = var.redis_address
    FEATURE_FLAGS_BACKEND = "redis"
    # ALB nodes are in the private subnets; tasks accept HTTP only from its SG.
    TRUSTED_PROXY_CIDRS = var.vpc_cidr
  })
}

data "aws_iam_policy_document" "task_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "secrets" {
  statement {
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.postgres_dsn_secret_arn, var.bootstrap_key_secret_arn]
  }
  dynamic "statement" {
    for_each = length(var.secret_kms_key_arns) > 0 ? [1] : []
    content {
      actions   = ["kms:Decrypt"]
      resources = var.secret_kms_key_arns
    }
  }
}

resource "aws_iam_role_policy" "secrets" {
  name   = "gateway-secrets"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.secrets.json
}

# The application has no AWS API permissions; ECS injects secrets at startup.
resource "aws_iam_role" "task" {
  name               = "${var.name}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
  tags               = var.tags
}

resource "aws_cloudwatch_log_group" "gateway" {
  name              = "/ecs/${var.name}/gateway"
  retention_in_days = 30
  tags              = var.tags
}

resource "aws_ecs_cluster" "this" {
  name = "${var.name}-fargate"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = var.tags
}

resource "aws_ecs_task_definition" "gateway" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name                   = "gateway"
    image                  = var.image
    essential              = true
    user                   = "65532:65532"
    readonlyRootFilesystem = true
    stopTimeout            = 30
    portMappings = [{
      name          = "http"
      containerPort = 8080
      hostPort      = 8080
      protocol      = "tcp"
    }]
    environment = [for name, value in local.environment : { name = name, value = value }]
    secrets = [
      { name = "POSTGRES_DSN", valueFrom = var.postgres_dsn_secret_arn },
      { name = "BOOTSTRAP_KEY", valueFrom = var.bootstrap_key_secret_arn },
    ]
    healthCheck = {
      command     = ["CMD", "/app", "-healthcheck"]
      interval    = 10
      timeout     = 3
      retries     = 5
      startPeriod = 30
    }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.gateway.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "gateway"
      }
    }
  }])

  tags = var.tags

  lifecycle {
    precondition {
      condition     = contains(lookup(local.memory_sizes, tostring(var.cpu), []), var.memory)
      error_message = "memory must be a valid Fargate MiB value for the selected cpu."
    }
  }
}

resource "aws_lb" "gateway" {
  name_prefix                = "gw-"
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = var.private_subnet_ids
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
  tags                       = var.tags
}

resource "aws_lb_target_group" "gateway" {
  name_prefix          = "gw-"
  port                 = 8080
  protocol             = "HTTP"
  target_type          = "ip"
  vpc_id               = var.vpc_id
  deregistration_delay = 30
  health_check {
    path                = "/readyz"
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
  tags = var.tags
}

# Private VPC traffic only. Add a trusted HTTPS edge before external exposure.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.gateway.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway.arn
  }
}

resource "aws_ecs_service" "gateway" {
  name             = "gateway"
  cluster          = aws_ecs_cluster.this.id
  task_definition  = aws_ecs_task_definition.gateway.arn
  desired_count    = var.desired_count
  launch_type      = "FARGATE"
  platform_version = "1.4.0"

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 60
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.gateway.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.gateway.arn
    container_name   = "gateway"
    container_port   = 8080
  }
  tags = var.tags

  depends_on = [
    aws_lb_listener.http,
    aws_iam_role_policy_attachment.execution,
    aws_iam_role_policy.secrets,
    aws_vpc_security_group_ingress_rule.gateway_from_alb,
    aws_vpc_security_group_egress_rule.alb_to_gateway,
    aws_vpc_security_group_egress_rule.gateway_https,
    aws_vpc_security_group_egress_rule.gateway_database,
    aws_vpc_security_group_egress_rule.gateway_redis,
    aws_vpc_security_group_egress_rule.gateway_vpc,
    aws_vpc_security_group_ingress_rule.database_from_gateway,
    aws_vpc_security_group_ingress_rule.redis_from_gateway,
  ]
}
