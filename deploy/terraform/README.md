# Terraform: Aurora PostgreSQL, ECS Fargate, EKS, and ElastiCache

This module provisions the gateway's AWS infrastructure. EKS remains available
for `deploy/k8s/`; an optional ECS Fargate module runs the gateway in the same
VPC with the same managed data stores. The complete example includes both.

| Piece | Resources |
|---|---|
| Network | VPC, public/private/database subnets across two AZs by default, IGW, NAT, route tables; database subnets have no internet route |
| Aurora PostgreSQL 16 | Encrypted cluster, writer + failover replica in distinct AZs by default, cluster parameter group forcing TLS, managed master secret, backups, deletion protection, private instances |
| ECS Fargate (optional) | Cluster, gateway task definition and service, internal ALB with IP targets and `/readyz` checks, task/execution roles, Secrets Manager injection, CloudWatch logs, security group rules |
| EKS | Cluster with KMS-encrypted Kubernetes secrets, private managed node group, control-plane logs, OIDC provider, core add-ons with VPC CNI NetworkPolicy enforcement |
| ElastiCache Redis 7.1 | Private primary + replica, automatic failover, encryption at rest; ingress from EKS and, when enabled, gateway tasks |

> **Validated and planned offline only; never applied to AWS.** The complete
> example now plans **70 resources to add, 0 to change, 0 to destroy**, replacing
> the previous 46-resource RDS/EKS plan. Nothing was deployed.

## Usage

```hcl
module "identity_gateway" {
  source = "./deploy/terraform"

  name                    = "identity-gateway"
  region                  = "us-west-2"
  eks_public_access_cidrs = ["203.0.113.0/24"] # replace with your VPN/office range

  gateway_ecs = {
    image                    = "111122223333.dkr.ecr.us-west-2.amazonaws.com/identity-gateway:replace-me"
    postgres_dsn_secret_arn   = "arn:aws:secretsmanager:us-west-2:111122223333:secret:gateway-app-dsn-ABCDEF"
    bootstrap_key_secret_arn  = "arn:aws:secretsmanager:us-west-2:111122223333:secret:gateway-bootstrap-ABCDEF"
    environment = {
      JWT_ISSUER = "https://gateway.example.com"
      UPSTREAMS  = "demo=https://upstream.internal.example.com"
    }
  }
}
```

All image URLs, domains, account IDs, and secret ARNs above are **placeholders**.
The ECS configuration defaults to `null` in the module, preserving EKS-only
compute for existing callers. The [complete example](examples/complete/main.tf)
enables ECS by default; set its `gateway_ecs` variable to `null` to omit it.
EKS is still provisioned when ECS is enabled. For a separate ECS service in an
existing VPC, use [`modules/ecs-fargate`](modules/ecs-fargate) directly.

Key inputs: `name`, `region`, `availability_zones`, `vpc_cidr`,
`single_nat_gateway`, `eks_*`, `db_engine_version`, `db_instance_class`,
`db_instance_count` (default 2; 1 disables replica failover), backup/deletion
settings, `redis_*`, `gateway_ecs`, and `tags`. Aurora manages storage growth;
`db_allocated_storage`, `db_max_allocated_storage`, and `db_multi_az` were
removed. The Aurora parameter family is pinned to PostgreSQL 16, and input
validation rejects other major versions.

Existing output names `rds_address`, `rds_port`, and `rds_master_secret_arn`
now refer to the Aurora **writer endpoint**, port, and managed admin secret.
New outputs include `aurora_cluster_id`, `aurora_reader_endpoint`,
`ecs_cluster_name`, `ecs_service_name`, and `ecs_gateway_url`. ECS outputs are
null when disabled. `gateway_env` retains its Kubernetes configuration hints.

## Reproduce the offline plan

Terraform initialization needs access to the provider registry or an existing
provider cache. "Offline" here means the plan makes **no AWS API calls** and
requires no AWS account; it does not mean the initial provider download works
without internet access.

```bash
cd deploy/terraform/examples/complete
terraform init -backend=false -input=false -lockfile=readonly
terraform validate
terraform plan -refresh=false -input=false -no-color -var=offline_plan=true
```

Use a fresh directory with no Terraform state. The flag selects mock credentials
and skips credentials/account/metadata/region validation. The module uses no
AWS API data sources: AZs are inputs and IAM policy documents are generated
locally. **Never apply an offline plan.** The full output is committed at
[`examples/complete/plan-output.txt`](examples/complete/plan-output.txt).

## Wiring the gateway

1. Push a gateway image to ECR, built for Linux/X86_64, for example with
   `docker build --platform linux/amd64 --build-arg BINARY=gateway -t <image> .`.
   Supply its URI, preferably an immutable digest, through `gateway_ecs.image`.
2. Bootstrap the `gateway_app` role and database ownership through an
   authorized EKS pod in the VPC, using the admin credentials from
   `rds_master_secret_arn`. Follow `deploy/postgres-init/01-app-role.sh`; Aurora
   uses an RDS admin role rather than a true PostgreSQL superuser, so role
   membership/ownership grants need verification in a real account. This
   bootstrap step has not been tested against Aurora. The gateway must connect
   as a non-superuser with `NOBYPASSRLS`; it checks this at startup.
3. Store the **entire connection string** as a Secrets Manager secret:
   `postgres://gateway_app:<URL-encoded-password>@<rds_address>:5432/gateway?sslmode=require`.
   Use the writer endpoint, not the reader endpoint. Terraform receives only
   this secret's ARN, and never reads its contents or the master password.
4. Store a shared `BOOTSTRAP_KEY` in a separate Secrets Manager secret. Supply
   both ARNs in `gateway_ecs`. For customer managed encryption keys, also supply
   their ARNs in `secret_kms_key_arns` and authorize the execution role in the
   corresponding KMS key policies. The default Secrets Manager key needs no
   extra KMS policy here. The task role itself has no AWS API permissions.
5. Set `JWT_ISSUER`, `JWT_AUDIENCE`, and `UPSTREAMS` for your environment. The
   module sets production mode, the managed Redis address, a shared Redis
   feature-flag backend, and trusted proxy CIDRs. It injects the DSN and
   bootstrap key at task startup; after changing secret values, force a new
   ECS deployment to pick them up. Secret rotation is not automated here.
6. Reach `ecs_gateway_url` from within the VPC. The internal ALB accepts HTTP
   on port 80 from the VPC CIDR; only its security group can reach tasks on
   port 8080. Tasks have no public IP. Metrics port 9090 is not exposed. Add a
   trusted HTTPS edge before external exposure; public ingress, certificates,
   and DNS are not provisioned.

For EKS deployments, skip `03-postgres.yaml` and `04-redis.yaml`, set
`REDIS_ADDR` in `02-configmap.yaml` from `redis_primary_endpoint`, and set
`POSTGRES_DSN` in `05-gateway.yaml` to the same restricted-role Aurora DSN with
TLS. Replace the Kubernetes example image names with your registry images.

## Change from the previous RDS configuration

This changes the Terraform resource types from `aws_db_instance` and
`aws_db_parameter_group` to `aws_rds_cluster`, `aws_rds_cluster_instance`, and
`aws_rds_cluster_parameter_group`. It is not an in-place database migration.
There is no deployed state in this repository. If you applied an older copy,
plan a separate data migration and cutover; do not assume applying this change
will preserve or transfer the old database's data. Existing deletion protection
and final snapshot settings still apply to deletion of an old database.

## Known gaps

- Redis TLS and AUTH remain disabled by default because the gateway Redis
  client does not configure TLS. Access is restricted to private networking
  and the EKS/gateway security groups. Enabling TLS requires a client change.
- The ECS module provisions a fixed desired count (default 3), rolling
  deployments, liveness checks, ALB readiness checks, and circuit-breaker
  rollback. Autoscaling, an ECR repository, SQL bootstrap, secret creation,
  public HTTPS ingress, and Prometheus/Grafana are outside its scope.
- Task egress allows HTTPS through NAT and TCP to configured private upstreams
  within the VPC; database/cache ingress remains limited by source security
  groups. Narrow private upstream egress for your service topology if needed.
- Real engine/class availability, quotas, IAM permissions, EKS add-on versions,
  failover, deployment behavior, bootstrap SQL, and costs remain unverified.
  Defaults retain the previous Aurora-compatible `16.4` engine version; check
  regional availability and support before a real deployment.
- Remote state/locking and CI apply automation are not configured. Restrict
  `eks_public_access_cidrs` for a real account (the module default is
  `0.0.0.0/0`). No policy scanner was run.

## What was verified

Terraform v1.16.5 and `hashicorp/aws` v5.100.0 on macOS arm64:

| Check | Result |
|---|---|
| `terraform fmt -check -recursive` | clean |
| `terraform validate` | root module, ECS child module, and complete example valid |
| Complete example offline plan | **70 to add, 0 to change, 0 to destroy** |
| EKS + Aurora without ECS | **48 to add, 0 to change, 0 to destroy** |
| Root plan-only tests | 5 passed: Aurora encryption/managed secret/TLS, AZ spread, optional ECS, single-instance setting, invalid inputs |
| ECS plan-only tests | 6 passed: private networking, IP targets, readiness/liveness, secret injection, data-store rules, rollback, invalid sizing/secret inputs |

Run the tests with Terraform >=1.6 (the configuration itself requires >=1.5):

```bash
cd deploy/terraform
terraform init -backend=false
terraform test
terraform -chdir=modules/ecs-fargate init -backend=false
terraform -chdir=modules/ecs-fargate test
terraform fmt -check -recursive
```

Every test run explicitly uses `command = plan` and mock credentials with API
validation disabled. No test applies infrastructure.

Implementation references: [Aurora cluster resource](https://registry.terraform.io/providers/hashicorp/aws/5.100.0/docs/resources/rds_cluster),
[Aurora instances](https://registry.terraform.io/providers/hashicorp/aws/5.100.0/docs/resources/rds_cluster_instance),
[ECS secret injection](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/secrets-envvar-secrets-manager.html).
