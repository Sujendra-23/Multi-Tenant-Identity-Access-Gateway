# Terraform: EKS + RDS Postgres + ElastiCache Redis

A Terraform module that provisions the AWS infrastructure the gateway's
Kubernetes manifests (`deploy/k8s/`) are meant to run on:

| Piece | Resources |
|---|---|
| Network | VPC, 3 subnet tiers across >=2 AZs (public / private for EKS nodes / **database with no internet route**), IGW, NAT (one shared by default), route tables |
| EKS | Cluster (secrets envelope-encrypted with a KMS key, control-plane logs to CloudWatch), one managed node group in private subnets, add-ons (`vpc-cni` with **NetworkPolicy enforcement on**, `kube-proxy`, `coredns`), OIDC provider for IRSA |
| RDS Postgres 16 | Encrypted gp3, Multi-AZ by default, `rds.force_ssl=1`, **master password generated and held in Secrets Manager** (never in variables/state inputs), private subnets, ingress only from the EKS cluster security group |
| ElastiCache Redis 7.1 | Replication group (primary + replica, automatic failover), encrypted at rest, private subnets, ingress only from the EKS cluster security group |

> **Status: written and checked offline only. It has never been applied.**
> There is no AWS account behind this repo. What was actually run is listed
> under [What was verified](#what-was-verified). Do not describe this as a
> deployed or production-proven environment.

## Usage

```hcl
module "identity_gateway" {
  source = "./deploy/terraform"

  name                    = "identity-gateway"
  region                  = "us-west-2"
  eks_public_access_cidrs = ["203.0.113.0/24"] # your VPN/office range
}
```

A runnable example root (with the provider block) is in
[`examples/complete`](examples/complete). Real deploy:

```bash
cd deploy/terraform/examples/complete
terraform init
terraform plan            # needs real AWS credentials
terraform apply
$(terraform output -raw kubeconfig_command)
```

Key inputs (all have defaults; see `variables.tf`): `name`, `region`,
`availability_zones`, `vpc_cidr`, `single_nat_gateway`, `eks_version`,
`eks_public_access_cidrs`, `eks_node_*`, `db_*` (instance class, storage,
Multi-AZ, backups, deletion protection), `redis_*`,
`redis_transit_encryption_enabled`, `tags`. Key outputs: `eks_cluster_name`,
`eks_cluster_endpoint`, `kubeconfig_command`, `rds_address`,
`rds_master_secret_arn`, `redis_primary_endpoint`, `gateway_env`.

## Wiring the gateway to it

With managed data stores, skip `deploy/k8s/03-postgres.yaml` and
`04-redis.yaml`. Then:

1. Set `REDIS_ADDR` in `02-configmap.yaml` to the `redis_primary_endpoint` output.
2. Create the `gateway_app` role. The gateway must **not** connect as the RDS
   master user: row-level security is only enforced against a non-superuser
   owner role (see `deploy/postgres-init/01-app-role.sh` and the README's design
   notes). Run that script's SQL against RDS using the master credentials from
   the `rds_master_secret_arn` secret, from a pod in the cluster (the database
   is not reachable from outside the VPC). On RDS the master user is
   `rds_superuser`, not a true superuser, so it likely needs
   `GRANT gateway_app TO <master>;` before `ALTER DATABASE ... OWNER TO gateway_app`
   works -- **this step has not been tested**.
3. Point `POSTGRES_DSN` in `05-gateway.yaml` at `rds_address` and change
   `sslmode=disable` to `sslmode=require` (the parameter group forces TLS).
4. Replace the example image names with images pushed to ECR (node role already
   has ECR read-only access).

## Known gaps (read before relying on this)

- **Redis has no TLS and no AUTH password by default.** The gateway's Redis
  client (`internal/store/redisstore/client.go`) does not set a `tls.Config`,
  and ElastiCache only allows an AUTH token together with in-transit
  encryption. So `redis_transit_encryption_enabled` defaults to `false`, and
  Redis is protected by private subnets + a security group admitting only the
  EKS cluster SG. Enabling TLS needs a gateway code change first.
- Not applied, so unknown: real-world apply errors (service quotas, AZ/instance
  availability, add-on version compatibility with `eks_version`, IAM
  permissions of the applying principal), and cost. A Multi-AZ RDS + NAT +
  3x m6i.large + 2 cache nodes is not free.
- Remote state, state locking, CI plan/apply, an ingress controller / ALB, the
  external-secrets operator and Prometheus/Grafana in-cluster are out of scope.
- `0.0.0.0/0` is the default for the public API endpoint CIDRs; set
  `eks_public_access_cidrs` (or disable the public endpoint) for anything real.
- No policy scanner (tfsec/checkov/trivy) was run.

## What was verified

Terraform v1.16.5, `hashicorp/aws` v5.100.0, on macOS arm64, **offline**:

| Command | Result |
|---|---|
| `terraform fmt -check -recursive` | clean |
| `terraform init` (example root, and the module standalone with `-backend=false`) | succeeded |
| `terraform validate` (both) | `Success! The configuration is valid.` |
| `terraform plan -var offline_plan=true` (example root, mock credentials, skip-validation flags) | **`Plan: 46 to add, 0 to change, 0 to destroy.`** |
| Variable validation | `name = "Bad_Name"` is rejected with the module's validation message |

The plan used mock credentials with `skip_credentials_validation`,
`skip_requesting_account_id` and `skip_metadata_api_check`, so no AWS API was
called and **nothing was created or applied**. The module avoids data sources
that call AWS (AZs are variables; IAM policy documents are local) so it can plan
this way. The full redacted plan output is committed at
[`examples/complete/plan-output.txt`](examples/complete/plan-output.txt). The
46 resources by type: 6 subnets, 6 route-table associations, 4 route tables, 4
IAM role-policy attachments, 3 routes, 3 EKS add-ons, 2 SG ingress rules, 2
security groups, 2 IAM roles, and one each of VPC, NAT gateway, EIP, internet
gateway, KMS key, OIDC provider, ElastiCache subnet group + replication group,
EKS cluster + node group, DB subnet group + parameter group + instance, and
CloudWatch log group.
