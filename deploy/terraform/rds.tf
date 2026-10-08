resource "aws_security_group" "rds" {
  name_prefix = "${var.name}-rds-"
  description = "Postgres for the identity gateway: ingress only from EKS nodes/pods"
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

resource "aws_db_parameter_group" "this" {
  name_prefix = "${var.name}-pg16-"
  family      = "postgres16"
  description = "Identity gateway Postgres parameters"

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

resource "aws_db_instance" "this" {
  identifier     = var.name
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  db_name  = var.db_name
  username = var.db_master_username
  # RDS generates the master password and keeps it in Secrets Manager, so no
  # password ever appears in Terraform variables or plan output.
  manage_master_user_password = true

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage > 0 ? var.db_max_allocated_storage : null
  storage_type          = "gp3"
  storage_encrypted     = true

  multi_az               = var.db_multi_az
  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.this.name
  publicly_accessible    = false

  backup_retention_period      = var.db_backup_retention_days
  copy_tags_to_snapshot        = true
  deletion_protection          = var.db_deletion_protection
  skip_final_snapshot          = var.db_skip_final_snapshot
  final_snapshot_identifier    = var.db_skip_final_snapshot ? null : "${var.name}-final"
  auto_minor_version_upgrade   = true
  performance_insights_enabled = true

  tags = local.tags
}
