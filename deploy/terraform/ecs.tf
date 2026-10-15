module "gateway_ecs" {
  source = "./modules/ecs-fargate"
  count  = var.gateway_ecs == null ? 0 : 1

  name                       = var.name
  region                     = var.region
  vpc_id                     = aws_vpc.this.id
  vpc_cidr                   = var.vpc_cidr
  private_subnet_ids         = aws_subnet.private[*].id
  database_security_group_id = aws_security_group.rds.id
  redis_security_group_id    = aws_security_group.redis.id
  redis_address              = "${aws_elasticache_replication_group.this.primary_endpoint_address}:6379"
  image                      = var.gateway_ecs.image
  postgres_dsn_secret_arn    = var.gateway_ecs.postgres_dsn_secret_arn
  bootstrap_key_secret_arn   = var.gateway_ecs.bootstrap_key_secret_arn
  secret_kms_key_arns        = var.gateway_ecs.secret_kms_key_arns
  desired_count              = var.gateway_ecs.desired_count
  cpu                        = var.gateway_ecs.cpu
  memory                     = var.gateway_ecs.memory
  environment                = var.gateway_ecs.environment
  tags                       = local.tags

  depends_on = [aws_rds_cluster_instance.this, aws_route.private_nat]
}
