output "vpc_id" {
  value = aws_vpc.this.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "eks_cluster_name" {
  value = aws_eks_cluster.this.name
}

output "eks_cluster_endpoint" {
  value = aws_eks_cluster.this.endpoint
}

output "eks_oidc_issuer" {
  description = "OIDC issuer URL (for IRSA trust policies)."
  value       = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

output "kubeconfig_command" {
  description = "Run this to point kubectl at the cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${aws_eks_cluster.this.name}"
}

output "rds_address" {
  description = "Aurora writer hostname (use as the host in POSTGRES_DSN)."
  value       = aws_rds_cluster.this.endpoint
}

output "rds_port" {
  value = aws_rds_cluster.this.port
}

output "rds_master_secret_arn" {
  description = "Secrets Manager secret holding the generated Aurora master credentials (admin use only; the gateway connects as gateway_app)."
  value       = aws_rds_cluster.this.master_user_secret[0].secret_arn
}

output "redis_primary_endpoint" {
  description = "ElastiCache primary endpoint (use as REDIS_ADDR, host:6379)."
  value       = "${aws_elasticache_replication_group.this.primary_endpoint_address}:6379"
}

output "gateway_env" {
  description = "Values to put in deploy/k8s/02-configmap.yaml and the POSTGRES_DSN of 05-gateway.yaml when using these managed services instead of 03-postgres.yaml / 04-redis.yaml."
  value = {
    REDIS_ADDR        = "${aws_elasticache_replication_group.this.primary_endpoint_address}:6379"
    POSTGRES_HOST     = aws_rds_cluster.this.endpoint
    POSTGRES_DB       = var.db_name
    POSTGRES_DSN_HINT = "postgres://gateway_app:<GATEWAY_APP_PASSWORD>@${aws_rds_cluster.this.endpoint}:5432/${var.db_name}?sslmode=require"
  }
}

output "aurora_reader_endpoint" {
  description = "Aurora reader endpoint. The gateway DSN must use the writer endpoint (rds_address)."
  value       = aws_rds_cluster.this.reader_endpoint
}

output "aurora_cluster_id" {
  value = aws_rds_cluster.this.id
}

output "ecs_service_name" {
  value = try(module.gateway_ecs[0].service_name, null)
}

output "ecs_cluster_name" {
  value = try(module.gateway_ecs[0].cluster_name, null)
}

output "ecs_gateway_url" {
  description = "Internal HTTP ALB URL, reachable only within the VPC. Terminate HTTPS at a trusted edge before exposing externally."
  value       = try(module.gateway_ecs[0].gateway_url, null)
}
