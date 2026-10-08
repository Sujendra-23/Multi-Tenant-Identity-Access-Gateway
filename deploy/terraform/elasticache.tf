resource "aws_security_group" "redis" {
  name_prefix = "${var.name}-redis-"
  description = "Redis for the identity gateway: ingress only from EKS nodes/pods"
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.tags, { Name = "${var.name}-redis" })

  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_eks" {
  security_group_id            = aws_security_group.redis.id
  referenced_security_group_id = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "Redis from EKS cluster security group"
}

resource "aws_elasticache_subnet_group" "this" {
  name       = var.name
  subnet_ids = aws_subnet.database[*].id
  tags       = local.tags
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = var.name
  description          = "Identity gateway sessions, rate limits, policy cache, risk history"

  engine               = "redis"
  engine_version       = var.redis_engine_version
  node_type            = var.redis_node_type
  port                 = 6379
  parameter_group_name = "default.redis7"

  num_cache_clusters         = var.redis_num_cache_clusters
  automatic_failover_enabled = var.redis_num_cache_clusters > 1
  multi_az_enabled           = var.redis_num_cache_clusters > 1

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  # See the variable's description: off by default because the gateway's Redis
  # client has no TLS support yet. No auth_token is set for the same reason
  # (ElastiCache only accepts an AUTH token with transit encryption on).
  transit_encryption_enabled = var.redis_transit_encryption_enabled

  snapshot_retention_limit = 3
  apply_immediately        = false

  tags = local.tags
}
