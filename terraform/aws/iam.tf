# IAM for Inwom Edge V1. Every action below appears in deploy/security/iam_matrix.yaml, and a CI
# test fails if this file grants anything that matrix does not list.

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

locals {
  partition         = data.aws_partition.current.partition
  account_id        = data.aws_caller_identity.current.account_id
  cloudtrail_bucket = local.mirror ? aws_s3_bucket.mirror[0].id : var.cloudtrail_bucket
  s3_buckets        = compact([local.cloudtrail_bucket, var.waf_bucket, var.alb_bucket, var.vpc_flow_bucket])
  log_group_arns = flatten([
    for name in var.cloudwatch_log_group_names : [
      "arn:${local.partition}:logs:${data.aws_region.current.region}:${local.account_id}:log-group:${name}",
      "arn:${local.partition}:logs:${data.aws_region.current.region}:${local.account_id}:log-group:${name}:*",
    ]
  ])
}

# ------------------------------------------------------------------------------------------------
# Task role: what the Edge process can do in your account. Read-only on telemetry; cryptographic
# use (not management) of its two own KMS keys.
# ------------------------------------------------------------------------------------------------

resource "aws_iam_role" "task" {
  name                 = "${var.name_prefix}-task"
  assume_role_policy   = data.aws_iam_policy_document.ecs_assume.json
  permissions_boundary = var.permissions_boundary_arn
}

data "aws_iam_policy_document" "task" {
  dynamic "statement" {
    for_each = length(local.s3_buckets) > 0 ? [1] : []
    content {
      sid       = "S3LogBucketsList"
      actions   = ["s3:ListBucket"]
      resources = [for b in local.s3_buckets : "arn:${local.partition}:s3:::${b}"]
    }
  }

  dynamic "statement" {
    for_each = length(local.s3_buckets) > 0 ? [1] : []
    content {
      sid       = "S3LogObjectsRead"
      actions   = ["s3:GetObject"]
      resources = [for b in local.s3_buckets : "arn:${local.partition}:s3:::${b}/*"]
    }
  }

  dynamic "statement" {
    for_each = var.guardduty_detector_id != "" ? [1] : []
    content {
      sid       = "GuardDutyFindingsRead"
      actions   = ["guardduty:ListFindings", "guardduty:GetFindings"]
      resources = ["arn:${local.partition}:guardduty:${data.aws_region.current.region}:${local.account_id}:detector/${var.guardduty_detector_id}"]
    }
  }

  dynamic "statement" {
    for_each = length(var.cloudwatch_log_group_names) > 0 ? [1] : []
    content {
      sid       = "CloudWatchSignalCounts"
      actions   = ["logs:FilterLogEvents"]
      resources = local.log_group_arns
    }
  }

  dynamic "statement" {
    for_each = var.enable_iam_metadata ? [1] : []
    content {
      sid       = "IamInventoryMetadata"
      actions   = ["iam:ListUsers", "iam:ListMFADevices", "iam:ListAccessKeys"]
      resources = ["arn:${local.partition}:iam::${local.account_id}:user/*"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_compute_metadata ? [1] : []
    content {
      sid       = "ComputeExposureMetadataNoResourceLevel"
      actions   = ["ec2:DescribeInstances", "eks:ListClusters", "ecs:ListClusters"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_compute_metadata ? [1] : []
    content {
      sid     = "ComputeExposureMetadataScoped"
      actions = ["eks:DescribeCluster", "ecs:ListServices", "ecs:DescribeServices"]
      resources = [
        "arn:${local.partition}:eks:*:${local.account_id}:cluster/*",
        "arn:${local.partition}:ecs:*:${local.account_id}:cluster/*",
        "arn:${local.partition}:ecs:*:${local.account_id}:service/*/*",
      ]
    }
  }

  dynamic "statement" {
    for_each = local.mirror ? [1] : []
    content {
      sid       = "MirrorKeyDecryptViaS3Only"
      actions   = ["kms:Decrypt"]
      resources = [aws_kms_key.mirror[0].arn]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${data.aws_region.current.region}.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.enable_durable_queue ? [1] : []
    content {
      sid       = "OwnTransportQueueOnly"
      actions   = ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"]
      resources = [aws_sqs_queue.transport[0].arn]
    }
  }

  statement {
    sid       = "PseudonymKeyDerivationOnly"
    actions   = ["kms:GenerateMac"]
    resources = [aws_kms_key.pseudonym.arn]
  }

  statement {
    sid       = "InstallationIdentityKeySignOnly"
    actions   = ["kms:Sign", "kms:GetPublicKey"]
    resources = [aws_kms_key.identity.arn]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${var.name_prefix}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

# ------------------------------------------------------------------------------------------------
# Execution role: used by ECS to start the task (pull image, write the Edge's own logs, inject the
# single-use bootstrap token). Never used by the Edge process.
# ------------------------------------------------------------------------------------------------

resource "aws_iam_role" "execution" {
  name                 = "${var.name_prefix}-execution"
  assume_role_policy   = data.aws_iam_policy_document.ecs_assume.json
  permissions_boundary = var.permissions_boundary_arn
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid       = "OwnLogGroupWriteOnly"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.edge.arn}:*"]
  }

  statement {
    sid       = "BootstrapSecretReadOnly"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.bootstrap.arn]
  }

  dynamic "statement" {
    for_each = var.ecr_repository_arn != null ? [1] : []
    content {
      sid       = "EcrAuthorizationToken"
      actions   = ["ecr:GetAuthorizationToken"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.ecr_repository_arn != null ? [1] : []
    content {
      sid       = "EcrPullPinnedImage"
      actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
      resources = [var.ecr_repository_arn]
    }
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "${var.name_prefix}-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}
