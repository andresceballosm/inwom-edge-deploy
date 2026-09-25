# The Edge security group has NO ingress rules. There is nothing to connect to: no listener, no
# SSH, no public IP. Outbound is limited to TCP 443 (and, when enabled, your VPC endpoints).

resource "aws_security_group" "edge" {
  name        = "${var.name_prefix}-edge"
  description = "Inwom Edge: outbound-only. No inbound rules."
  vpc_id      = var.vpc_id

  # Deliberately no `ingress` blocks. A test (security/tests/test_iac_invariants.py) fails the build if one is added.
}

resource "aws_vpc_security_group_egress_rule" "https" {
  for_each          = toset(var.egress_cidr_blocks)
  security_group_id = aws_security_group.edge.id
  description       = "HTTPS to Inwom ingest and AWS APIs"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = each.value
}

# ---- optional: keep AWS-service traffic on the AWS network -----------------------------------------

resource "aws_security_group" "endpoints" {
  count       = var.create_vpc_endpoints ? 1 : 0
  name        = "${var.name_prefix}-endpoints"
  description = "Interface endpoints for the Inwom Edge. Accepts 443 only from the Edge task."
  vpc_id      = var.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_edge" {
  count                        = var.create_vpc_endpoints ? 1 : 0
  security_group_id            = aws_security_group.endpoints[0].id
  description                  = "HTTPS from the Edge task only"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.edge.id
}

locals {
  interface_endpoints = var.create_vpc_endpoints ? toset(compact([
    "kms",
    "logs",
    "secretsmanager",
    var.guardduty_detector_id != "" ? "guardduty" : "",
    var.ecr_repository_arn != null ? "ecr.api" : "",
    var.ecr_repository_arn != null ? "ecr.dkr" : "",
  ])) : toset([])
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "s3" {
  count             = var.create_vpc_endpoints && length(var.route_table_ids) > 0 ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = var.route_table_ids
}

resource "aws_vpc_security_group_egress_rule" "to_endpoints" {
  count                        = var.create_vpc_endpoints ? 1 : 0
  security_group_id            = aws_security_group.edge.id
  description                  = "HTTPS to the VPC interface endpoints"
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  referenced_security_group_id = aws_security_group.endpoints[0].id
}
