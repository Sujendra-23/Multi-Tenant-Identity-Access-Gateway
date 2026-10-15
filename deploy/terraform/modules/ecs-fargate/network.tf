resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Internal gateway load balancer"
  vpc_id      = var.vpc_id
  tags        = var.tags
  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "gateway" {
  name_prefix = "${var.name}-ecs-"
  description = "Gateway Fargate tasks; HTTP only from the ALB"
  vpc_id      = var.vpc_id
  tags        = var.tags
  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "alb_from_vpc" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "alb_to_gateway" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.gateway.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_vpc_security_group_ingress_rule" "gateway_from_alb" {
  security_group_id            = aws_security_group.gateway.id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
}

resource "aws_vpc_security_group_egress_rule" "gateway_https" {
  description       = "ECR, Secrets Manager, CloudWatch Logs and HTTPS upstreams through NAT"
  security_group_id = aws_security_group.gateway.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "gateway_database" {
  security_group_id            = aws_security_group.gateway.id
  referenced_security_group_id = var.database_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_egress_rule" "gateway_redis" {
  security_group_id            = aws_security_group.gateway.id
  referenced_security_group_id = var.redis_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
}

resource "aws_vpc_security_group_egress_rule" "gateway_vpc" {
  description       = "Configured private upstream services within the VPC"
  security_group_id = aws_security_group.gateway.id
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 1
  to_port           = 65535
}

resource "aws_vpc_security_group_ingress_rule" "database_from_gateway" {
  security_group_id            = var.database_security_group_id
  referenced_security_group_id = aws_security_group.gateway.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "Aurora PostgreSQL from gateway Fargate tasks"
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_gateway" {
  security_group_id            = var.redis_security_group_id
  referenced_security_group_id = aws_security_group.gateway.id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "Redis from gateway Fargate tasks"
}
