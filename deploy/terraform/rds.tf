resource "aws_security_group" "rds" {
  name_prefix = "${var.name}-rds-"
  description = "Postgres for the identity gateway: ingress only from EKS and gateway Fargate tasks"
  vpc_id      = aws_vpc.this.id
  tags        = merge(local.tags, { Name = "${var.name}-rds" })

  lifecycle { create_before_destroy = true }
}

# Pods use the cluster security group via the VPC CNI, so allow that source.
resource "aws_vpc_security_group_ingress_rule" "rds_from_eks" {
  security_group_id            = aws_security_group.rds.id
  referenced_security_group_id = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "Postgres from EKS cluster security group"
}

resource "aws_db_subnet_group" "this" {
  name       = var.name
  subnet_ids = aws_subnet.database[*].id
  tags       = local.tags
}

resource "aws_rds_cluster_parameter_group" "this" {
  name_prefix = "${var.name}-aurora-pg16-"
  family      = "aurora-postgresql16"
  description = "Identity gateway Aurora PostgreSQL parameters"

  # Reject plaintext connections. The gateway DSN must use sslmode=require (or
  # stricter); the default DSN in deploy/k8s/05-gateway.yaml says sslmode=disable
  # and must be changed when pointing at this database.
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }

  tags = local.tags

  lifecycle { create_before_destroy = true }
}

resource "aws_rds_cluster" "this" {
  cluster_identifier = var.name
  engine             = "aurora-postgresql"
  engine_mode        = "provisioned"
  engine_version     = var.db_engine_version

  database_name               = var.db_name
  master_username             = var.db_master_username
  manage_master_user_password = true
  storage_encrypted           = true
  port                        = 5432

  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [aws_security_group.rds.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.this.name

  backup_retention_period         = var.db_backup_retention_days
  copy_tags_to_snapshot           = true
  deletion_protection             = var.db_deletion_protection
  skip_final_snapshot             = var.db_skip_final_snapshot
  final_snapshot_identifier       = var.db_skip_final_snapshot ? null : "${var.name}-final"
  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = local.tags
}

# One writer plus a failover replica by default, placed in distinct AZs.
# Aurora manages storage capacity; instance-style gp3/storage limits do not apply.
resource "aws_rds_cluster_instance" "this" {
  count = var.db_instance_count

  identifier                   = "${var.name}-${count.index + 1}"
  cluster_identifier           = aws_rds_cluster.this.id
  engine                       = aws_rds_cluster.this.engine
  engine_version               = aws_rds_cluster.this.engine_version
  instance_class               = var.db_instance_class
  availability_zone            = local.azs[count.index % length(local.azs)]
  promotion_tier               = count.index
  db_subnet_group_name         = aws_db_subnet_group.this.name
  publicly_accessible          = false
  auto_minor_version_upgrade   = true
  performance_insights_enabled = true
  copy_tags_to_snapshot        = true

  tags = local.tags
}
