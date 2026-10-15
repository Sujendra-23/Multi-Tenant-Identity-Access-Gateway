output "security_group_id" {
  value = aws_security_group.gateway.id
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "service_name" {
  value = aws_ecs_service.gateway.name
}

output "gateway_url" {
  value = "http://${aws_lb.gateway.dns_name}"
}

output "task_definition_arn" {
  value = aws_ecs_task_definition.gateway.arn
}
