# Gateway ECS Fargate service

Reusable child module for a gateway image in existing private VPC subnets.
The parent module wires it to Aurora and ElastiCache when `gateway_ecs` is set.
See the [parent usage and setup instructions](../../README.md).

Required inputs are `name`, `region`, `vpc_id`, `vpc_cidr`,
`private_subnet_ids` (at least two AZs for the ALB),
`database_security_group_id`, `redis_security_group_id`, `redis_address`,
`image`, `postgres_dsn_secret_arn`, and `bootstrap_key_secret_arn`.
Secrets must contain the complete DSN and bootstrap value respectively;
Terraform never fetches them. The caller creates database roles and secrets.

Optional inputs: `desired_count` (3), `cpu` (256), `memory` (512 MiB),
`environment` (non-secret app settings), `secret_kms_key_arns`, and `tags`.
CPU/memory combinations are validated for the supported Fargate CPU sizes
256–4096. The image must support Linux/X86_64 and `/app -healthcheck`.

Outputs: `cluster_name`, `service_name`, `task_definition_arn`,
`security_group_id`, and `gateway_url` (internal HTTP ALB).

This module creates inbound rules on the supplied database and cache security
groups. Those groups must belong to the same VPC and use separate rule resources
rather than conflicting inline rules. Private subnets need NAT or suitable VPC
endpoints to pull images and reach Secrets Manager/CloudWatch. The gateway's
configured upstreams must also be reachable. The ALB is internal; public HTTPS
routing, DNS, image publishing, and autoscaling are separate concerns.

Plan-only tests use mock credentials and no AWS API calls:

```bash
terraform init -backend=false
terraform validate
terraform test # Terraform >=1.6; all test runs use command = plan
```
