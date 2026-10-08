locals {
  azs = length(var.availability_zones) > 0 ? var.availability_zones : ["${var.region}a", "${var.region}b"]

  # /20 subnets carved from the VPC CIDR: public, private (EKS nodes), database.
  public_subnet_cidrs   = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i)]
  private_subnet_cidrs  = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 4)]
  database_subnet_cidrs = [for i, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, i + 8)]

  nat_count = var.single_nat_gateway ? 1 : length(local.azs)

  tags = merge({
    Project   = "multi-tenant-identity-access-gateway"
    ManagedBy = "terraform"
  }, var.tags)
}
